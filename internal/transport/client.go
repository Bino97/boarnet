// Package transport is the sensor's outbound HTTPS emitter. It drains batches
// from the buffer and POSTs them to the ingest service with gzip, retry, and
// rate-limit awareness.
//
// TODO(boarnet): swap the bearer-token auth for mTLS with sensor-issued certs.
// The enrollment flow (/v1/enroll) mints those; the transport needs to load
// the cert and present it on every request.
package transport

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/Bino97/boarnet-agent/internal/buffer"
	"github.com/Bino97/boarnet-agent/internal/envelope"
)

const (
	maxBatchSize  = 100
	pollInterval  = 5 * time.Second
	retryBase     = 2 * time.Second
	retryCap      = 300 * time.Second
	maxAttempts   = 7
)

type Client struct {
	ingestURL string
	token     string // TODO: replace with mTLS cert
	http      *http.Client
	buffer    *buffer.Buffer
	log       *slog.Logger
}

type rejected struct {
	EventID string `json:"event_id"`
	Reason  string `json:"reason"`
}

type response struct {
	Accepted             int        `json:"accepted"`
	Rejected             []rejected `json:"rejected"`
	ThrottleHintSeconds  int        `json:"throttle_hint_seconds"`
}

func New(ingestURL, token string, buf *buffer.Buffer, log *slog.Logger) *Client {
	return &Client{
		ingestURL: ingestURL,
		token:     token,
		http:      &http.Client{Timeout: 30 * time.Second},
		buffer:    buf,
		log:       log,
	}
}

// Run blocks, draining the buffer on an interval until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := c.drainOnce(ctx); err != nil {
				c.log.Error("drain failed", "err", err)
			}
		}
	}
}

func (c *Client) drainOnce(ctx context.Context) error {
	envs, ids, err := c.buffer.Drain(ctx, maxBatchSize)
	if err != nil {
		return fmt.Errorf("drain buffer: %w", err)
	}
	if len(envs) == 0 {
		return nil
	}

	batch := envelope.NewBatch(envs)
	if err := c.sendWithRetry(ctx, batch); err != nil {
		c.log.Warn("batch delivery failed after retries", "batch_id", batch.BatchID, "err", err)
		return err
	}
	return c.buffer.Ack(ctx, ids)
}

func (c *Client) sendWithRetry(ctx context.Context, batch *envelope.Batch) error {
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err := c.sendOnce(ctx, batch)
		if err == nil {
			return nil
		}
		lastErr = err

		var throttled *httpThrottledError
		backoff := decorrelatedJitter(attempt)
		if asThrottled, ok := err.(*httpThrottledError); ok {
			throttled = asThrottled
			if throttled.retryAfter > 0 {
				backoff = throttled.retryAfter
			}
		}

		c.log.Info("retrying", "attempt", attempt+1, "delay", backoff, "err", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
	return fmt.Errorf("gave up after %d attempts: %w", maxAttempts, lastErr)
}

type httpThrottledError struct {
	retryAfter time.Duration
}

func (e *httpThrottledError) Error() string {
	return fmt.Sprintf("throttled, retry after %s", e.retryAfter)
}

func (c *Client) sendOnce(ctx context.Context, batch *envelope.Batch) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}

	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(body); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ingestURL, &compressed)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == 429:
		hint := parseRetryAfter(resp.Header.Get("Retry-After"))
		return &httpThrottledError{retryAfter: hint}
	case resp.StatusCode >= 500:
		return fmt.Errorf("ingest 5xx: %s", resp.Status)
	case resp.StatusCode == 401, resp.StatusCode == 403:
		return fmt.Errorf("ingest auth failure: %s (not retrying)", resp.Status)
	case resp.StatusCode >= 400:
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("ingest 4xx: %s", resp.Status)
	}

	var parsed response
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if len(parsed.Rejected) > 0 {
		c.log.Warn("some envelopes rejected",
			"accepted", parsed.Accepted,
			"rejected_count", len(parsed.Rejected),
		)
	}
	return nil
}

// decorrelatedJitter implements the AWS-style exponential backoff with
// decorrelated jitter: min(cap, random(base, prev*3)).
func decorrelatedJitter(attempt int) time.Duration {
	prev := retryBase
	for i := 0; i < attempt; i++ {
		next := time.Duration(rand.Int64N(int64(prev*3-retryBase))) + retryBase
		if next > retryCap {
			next = retryCap
		}
		prev = next
	}
	return prev
}

func parseRetryAfter(h string) time.Duration {
	if h == "" {
		return retryBase
	}
	var seconds int
	_, err := fmt.Sscanf(h, "%d", &seconds)
	if err != nil || seconds <= 0 {
		return retryBase
	}
	return time.Duration(seconds) * time.Second
}
