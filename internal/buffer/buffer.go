// Package buffer is the agent's local event queue. Envelopes land here first,
// persist across crashes, and drain to the transport layer in batches.
//
// Implementation detail: each row stores an AES-256-GCM ciphertext of the
// marshaled envelope. The master key currently lives in a file on disk (mode
// 0600) — production should source it from the OS keystore (DPAPI / Keychain
// / libsecret). That swap is an implementation change in loadOrCreateKey, no
// schema change.
package buffer

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Bino97/boarnet-agent/internal/envelope"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS events (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	event_id    TEXT    NOT NULL UNIQUE,
	created_at  INTEGER NOT NULL,
	nonce       BLOB    NOT NULL,
	ciphertext  BLOB    NOT NULL,
	attempts    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS events_created_at ON events(created_at);
`

type Buffer struct {
	db    *sql.DB
	aead  cipher.AEAD
}

// Open initializes (or opens) a buffer at dataDir. Loads the AES-GCM key from
// dataDir/key (creating one if missing) and opens the SQLite file at
// dataDir/buffer.db.
func Open(dataDir string) (*Buffer, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir data dir: %w", err)
	}

	key, err := loadOrCreateKey(filepath.Join(dataDir, "key"))
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: %w", err)
	}

	db, err := sql.Open("sqlite", filepath.Join(dataDir, "buffer.db"))
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return &Buffer{db: db, aead: aead}, nil
}

func (b *Buffer) Close() error {
	return b.db.Close()
}

// Enqueue marshals, encrypts, and persists an envelope.
func (b *Buffer) Enqueue(ctx context.Context, env *envelope.Envelope) error {
	payload, err := json.Marshal(env)
	if err != nil {
		return err
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ct := b.aead.Seal(nil, nonce, payload, nil)
	_, err = b.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO events (event_id, created_at, nonce, ciphertext) VALUES (?, ?, ?, ?)`,
		env.EventID, env.TS.UnixMilli(), nonce, ct,
	)
	return err
}

// Drain returns up to n envelopes in creation order (oldest first). Callers
// delete successfully-transmitted rows via Ack.
func (b *Buffer) Drain(ctx context.Context, n int) ([]*envelope.Envelope, []int64, error) {
	rows, err := b.db.QueryContext(ctx,
		`SELECT id, nonce, ciphertext FROM events ORDER BY created_at ASC LIMIT ?`, n)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var envs []*envelope.Envelope
	var ids []int64
	for rows.Next() {
		var id int64
		var nonce, ct []byte
		if err := rows.Scan(&id, &nonce, &ct); err != nil {
			return nil, nil, err
		}
		plain, err := b.aead.Open(nil, nonce, ct, nil)
		if err != nil {
			// Corrupted or keys rotated; drop the row rather than block.
			_, _ = b.db.ExecContext(ctx, `DELETE FROM events WHERE id = ?`, id)
			continue
		}
		env := &envelope.Envelope{}
		if err := json.Unmarshal(plain, env); err != nil {
			continue
		}
		envs = append(envs, env)
		ids = append(ids, id)
	}
	return envs, ids, rows.Err()
}

// Ack deletes rows that were accepted by ingest.
func (b *Buffer) Ack(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `DELETE FROM events WHERE id = ?`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, id := range ids {
		if _, err := stmt.ExecContext(ctx, id); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// Depth returns how many events are currently buffered.
func (b *Buffer) Depth(ctx context.Context) (int, error) {
	var n int
	err := b.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&n)
	return n, err
}

// loadOrCreateKey reads a 32-byte key file, creating one with crypto/rand if missing.
// TODO(boarnet): replace with OS keystore integration (DPAPI / Keychain / libsecret).
func loadOrCreateKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("key file %s has wrong length %d", path, len(b))
		}
		return b, nil
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}
