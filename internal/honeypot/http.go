package honeypot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Bino97/boarnet-agent/internal/envelope"
	"github.com/Bino97/boarnet-agent/internal/hash"
)

type HTTPConfig struct {
	Listen     string // ":8080"
	Pepper     hash.Pepper
	SensorInfo envelope.Sensor
	OnEvent    func(*envelope.Envelope)
	Log        *slog.Logger
}

// Response body for GET /  — mimics nginx's default page so scanners
// probing `:80` see something "real" and engage further. Any other path
// returns a canonical nginx 404 so path probes still look authentic.
const nginxIndex = `<!DOCTYPE html>
<html>
<head><title>Welcome to nginx!</title>
<style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;}</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>
<p><em>Thank you for using nginx.</em></p>
</body>
</html>
`

const nginx404 = `<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.24.0</center>
</body>
</html>
`

// Read at most this many bytes of the request body. More than enough to
// capture typical CVE probe payloads (Log4Shell headers, Spring4Shell POST
// bodies, path-traversal URLs); plenty of slack for future-proofing.
const maxBody = 8 * 1024

// Tags applied on top of the base `http` tag when we spot characteristic
// CVE-probe patterns. Not exhaustive — goal is to surface the most common
// attacker signatures on the Explore page without a separate classifier.
func tagsForRequest(r *http.Request, body []byte) []string {
	tags := []string{"http"}

	path := strings.ToLower(r.URL.Path)
	cveyPaths := []string{
		"/wp-admin", "/wp-login", "/xmlrpc.php",
		"/phpmyadmin", "/pma", "/adminer",
		"/solr/", "/actuator", "/manager/html", "/struts",
		"/.env", "/.git/", "/config.json", "/server-status",
		"/cgi-bin/", "/shell", "/webshell",
		"/boaform/", "/GponForm/", // common IoT CVE probes
	}
	for _, needle := range cveyPaths {
		if strings.Contains(path, needle) {
			tags = append(tags, "cve-probe")
			break
		}
	}

	if strings.EqualFold(r.Method, "CONNECT") {
		tags = append(tags, "proxy-probe")
	}

	// Log4Shell signature in any header value or body.
	joined := strings.ToLower(string(body))
	for k, vs := range r.Header {
		_ = k
		for _, v := range vs {
			joined += "\n" + strings.ToLower(v)
		}
	}
	if strings.Contains(joined, "${jndi:") {
		tags = append(tags, "log4shell")
	}

	ua := strings.ToLower(r.UserAgent())
	switch {
	case strings.Contains(ua, "censys"):
		tags = append(tags, "scanner:censys")
	case strings.Contains(ua, "shodan"):
		tags = append(tags, "scanner:shodan")
	case strings.Contains(ua, "binaryedge"):
		tags = append(tags, "scanner:binaryedge")
	case strings.Contains(ua, "zgrab") || strings.Contains(ua, "masscan"):
		tags = append(tags, "scanner:mass")
	case strings.Contains(ua, "internet-measurement"):
		tags = append(tags, "scanner:research")
	}

	return tags
}

func sanitizePreview(b []byte) string {
	if len(b) > 512 {
		b = b[:512]
	}
	// Strip non-printable bytes so the preview renders cleanly in the
	// Explore table. The full body is already hashed separately; this is
	// just a human-readable hint.
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		} else {
			out = append(out, '.')
		}
	}
	return string(out)
}

func StartHTTP(ctx context.Context, cfg HTTPConfig) (stop func() error, err error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		srcHost, srcPort := splitHostPortStr(r.RemoteAddr)
		ipHash, _ := cfg.Pepper.SrcIPHash(srcHost)

		// Read at most maxBody bytes so a hostile client can't OOM the
		// agent by streaming a gigabyte.
		body, _ := io.ReadAll(io.LimitReader(r.Body, maxBody))
		_ = r.Body.Close()
		sum := sha256.Sum256(body)

		headers := make(map[string]string, len(r.Header))
		for k, vs := range r.Header {
			if len(vs) > 0 {
				headers[k] = vs[0]
			}
		}

		raw := envelope.HTTPRequestRaw{
			Method:        r.Method,
			Path:          r.URL.RequestURI(),
			HTTPVersion:   r.Proto,
			Host:          r.Host,
			UserAgent:     r.UserAgent(),
			Headers:       headers,
			ContentLength: int64(len(body)),
			BodySHA256:    "sha256:" + hex.EncodeToString(sum[:]),
			BodyPreview:   sanitizePreview(body),
		}

		env := envelope.New(cfg.SensorInfo, cfg.Pepper.KeyID)
		env.EventType = envelope.EventHTTPRequest
		env.Src = envelope.Source{IP: srcHost, IPHash: ipHash, Port: srcPort}
		env.Dst = envelope.Destination{Port: portFromListen(cfg.Listen), Proto: "tcp"}
		env.Fingerprints = envelope.Fingerprints{}
		env.Tags = tagsForRequest(r, body)
		if encoded, err := json.Marshal(raw); err == nil {
			env.Raw = encoded
		}
		cfg.OnEvent(env)

		// Send a reply that looks like a real nginx server so the
		// attacker keeps sending CVE probes instead of moving on.
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(nginxIndex))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(nginx404))
	})

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		// Cap header size so oversized header attacks don't chew RAM.
		MaxHeaderBytes: 32 * 1024,
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, err
	}

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed && ctx.Err() == nil {
			cfg.Log.Error("http honeypot stopped", "err", err)
		}
	}()

	cfg.Log.Info("http honeypot listening", "addr", cfg.Listen)
	return func() error {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}, nil
}

func splitHostPortStr(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	var p int
	for _, c := range portStr {
		if c < '0' || c > '9' {
			break
		}
		p = p*10 + int(c-'0')
	}
	return host, p
}
