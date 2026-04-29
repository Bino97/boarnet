// HTTPS honeypot: terminates TLS with a self-signed certificate so the
// HTTP request behind the encryption is captured exactly like a
// plaintext :80 probe. Crucial for edge-device research — Palo Alto
// GlobalProtect, Fortinet, Ivanti, Citrix probes all hit :443 with
// app-specific URI paths (`/global-protect/login.esp`, `/remote/login`,
// `/dana-na/...`, `/vpn/index.html`). Without TLS termination the
// agent only sees a `tls.clienthello` event and the path is invisible.
//
// JA3/JA4 fingerprinting is preserved: the listener peeks the raw
// ClientHello bytes off the wire, parses + emits the existing
// `tls.clienthello` envelope, then replays the bytes into Go's
// crypto/tls server so the handshake completes normally and the
// HTTP server above sees a regular request.
package honeypot

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/Bino97/boarnet-agent/internal/envelope"
	"github.com/Bino97/boarnet-agent/internal/hash"
)

type HTTPSConfig struct {
	Listen     string // ":4443"
	Pepper     hash.Pepper
	SensorInfo envelope.Sensor
	OnEvent    func(*envelope.Envelope)
	Log        *slog.Logger
	// CertCN is the Subject CN of the in-memory self-signed cert. Mostly
	// cosmetic — most edge-device scanners ignore cert validity since
	// the appliances they target ship with self-signed certs out of
	// the box. Defaults to "appliance" if empty.
	CertCN string
}

// StartHTTPS spawns the TLS-terminating HTTPS honeypot. Returns a
// stop function that closes the listener.
func StartHTTPS(ctx context.Context, cfg HTTPSConfig) (stop func() error, err error) {
	cert, err := generateSelfSignedCert(cfg.CertCN)
	if err != nil {
		return nil, fmt.Errorf("generate self-signed cert: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// We deliberately accept ancient versions so legacy scanners
		// still complete the handshake and hand us their HTTP probe.
		MinVersion: tls.VersionTLS10,
		NextProtos: []string{"h2", "http/1.1"},
	}

	listenPort := portFromListen(cfg.Listen)
	httpHandlerCfg := HTTPConfig{
		Listen:     cfg.Listen,
		Pepper:     cfg.Pepper,
		SensorInfo: cfg.SensorInfo,
		OnEvent:    cfg.OnEvent,
		Log:        cfg.Log,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", httpRequestHandler(httpHandlerCfg, listenPort))

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    32 * 1024,
		TLSConfig:         tlsCfg,
		ErrorLog:          nil,
	}

	rawLn, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, err
	}
	peekLn := &peekListener{
		Listener: rawLn,
		cfg:      cfg,
		port:     listenPort,
	}
	tlsLn := tls.NewListener(peekLn, tlsCfg)

	go func() {
		if err := srv.Serve(tlsLn); err != nil && err != http.ErrServerClosed && ctx.Err() == nil {
			cfg.Log.Error("https honeypot stopped", "err", err)
		}
	}()

	cfg.Log.Info("https honeypot listening", "addr", cfg.Listen)
	return func() error {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}, nil
}

// peekListener wraps a TCP listener and, on each accepted connection,
// reads the first TLS record (ClientHello), parses it for JA3/JA4
// fingerprinting, emits a `tls.clienthello` envelope, then returns a
// connection whose Read replays the buffered bytes before delegating
// to the underlying socket. This way the standard tls.Server above
// reads the ClientHello it expects without any awareness that we
// already saw and recorded it.
type peekListener struct {
	net.Listener
	cfg  HTTPSConfig
	port int
}

func (p *peekListener) Accept() (net.Conn, error) {
	c, err := p.Listener.Accept()
	if err != nil {
		return nil, err
	}
	// Set a tight deadline for the ClientHello peek so a half-open
	// connection can't tie up the goroutine. The deadline is cleared
	// before handing the conn off to tls.Server.
	c.SetReadDeadline(time.Now().Add(5 * time.Second))

	srcHost, srcPort := splitHostPort(c.RemoteAddr())
	ipHash, _ := p.cfg.Pepper.SrcIPHash(srcHost)

	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		emitHTTPSScanProbe(p.cfg, srcHost, ipHash, srcPort, p.port, 0)
		_ = c.Close()
		// Returning a closed conn would still surface as a handshake
		// error in tls.Server's Serve loop. Cleaner to just synthesize
		// a fresh dummy conn that errors on Read so the caller moves on.
		return &deadConn{remote: c.RemoteAddr()}, nil
	}
	if hdr[0] != 0x16 {
		// Not a TLS handshake — emit a scan.probe with whatever bytes
		// we got and bail. Most scanners that hit :443 plaintext are
		// looking for cleartext HTTP redirects.
		emitHTTPSScanProbe(p.cfg, srcHost, ipHash, srcPort, p.port, 5)
		_ = c.Close()
		return &deadConn{remote: c.RemoteAddr()}, nil
	}
	length := int(hdr[3])<<8 | int(hdr[4])
	if length < 4 || length > 1<<15 {
		emitHTTPSScanProbe(p.cfg, srcHost, ipHash, srcPort, p.port, 5)
		_ = c.Close()
		return &deadConn{remote: c.RemoteAddr()}, nil
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(c, body); err != nil {
		emitHTTPSScanProbe(p.cfg, srcHost, ipHash, srcPort, p.port, 5+length)
		_ = c.Close()
		return &deadConn{remote: c.RemoteAddr()}, nil
	}

	if len(body) > 4 && body[0] == 0x01 {
		if hello, _, err := parseClientHelloBody(body[4:]); err == nil {
			emitClientHelloEnvelope(p.cfg, srcHost, ipHash, srcPort, p.port, hello)
		}
	}

	// Clear the deadline before handing off — the TLS handshake has
	// its own timing managed by the http.Server config above.
	_ = c.SetReadDeadline(time.Time{})

	prefix := make([]byte, 0, 5+length)
	prefix = append(prefix, hdr...)
	prefix = append(prefix, body...)
	return &replayConn{Conn: c, prefix: prefix}, nil
}

// replayConn drains the buffered ClientHello bytes on the first Read
// calls, then delegates to the underlying conn for the rest of the
// session. Implements net.Conn by embedding the original.
type replayConn struct {
	net.Conn
	prefix []byte
}

func (r *replayConn) Read(p []byte) (int, error) {
	if len(r.prefix) > 0 {
		n := copy(p, r.prefix)
		r.prefix = r.prefix[n:]
		return n, nil
	}
	return r.Conn.Read(p)
}

// deadConn is a net.Conn stub that errors on every Read so the caller
// (tls.Server) abandons the connection cleanly. We use it when the
// ClientHello peek failed and we already closed the real socket.
type deadConn struct {
	remote net.Addr
}

func (d *deadConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (d *deadConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (d *deadConn) Close() error                     { return nil }
func (d *deadConn) LocalAddr() net.Addr              { return d.remote }
func (d *deadConn) RemoteAddr() net.Addr             { return d.remote }
func (d *deadConn) SetDeadline(time.Time) error      { return nil }
func (d *deadConn) SetReadDeadline(time.Time) error  { return nil }
func (d *deadConn) SetWriteDeadline(time.Time) error { return nil }

func emitClientHelloEnvelope(
	cfg HTTPSConfig,
	srcHost, ipHash string,
	srcPort, dstPort int,
	hello *clientHello,
) {
	ja3 := ja3String(hello)
	ja3Sum := md5.Sum([]byte(ja3))
	ja3Hash := hex.EncodeToString(ja3Sum[:])
	ja4 := ja4Fingerprint(hello)

	env := envelope.New(cfg.SensorInfo, cfg.Pepper.KeyID)
	env.EventType = envelope.EventTLSClientHello
	env.Src = envelope.Source{IP: srcHost, IPHash: ipHash, Port: srcPort}
	env.Dst = envelope.Destination{Port: dstPort, Proto: "tls"}
	env.Fingerprints = envelope.Fingerprints{
		JA3:     envelope.StrPtr(ja3),
		JA3Hash: envelope.StrPtr(ja3Hash),
		JA4:     envelope.StrPtr(ja4),
	}
	raw := envelope.TLSClientHelloRaw{
		TLSVersion:      fmt.Sprintf("0x%04x", hello.Version),
		Ciphersuites:    ciphersuitesAsHex(hello.Ciphersuites),
		Extensions:      extsToInts(hello.Extensions),
		ALPN:            hello.ALPN,
		SNI:             hello.SNI,
		SupportedGroups: namedGroups(hello.SupportedGroups),
	}
	if body, err := json.Marshal(raw); err == nil {
		env.Raw = body
	}
	env.Tags = []string{"tls"}
	cfg.OnEvent(env)
}

func emitHTTPSScanProbe(cfg HTTPSConfig, srcHost, ipHash string, srcPort, dstPort, bytesIn int) {
	env := envelope.New(cfg.SensorInfo, cfg.Pepper.KeyID)
	env.EventType = envelope.EventScanProbe
	env.Src = envelope.Source{IP: srcHost, IPHash: ipHash, Port: srcPort}
	env.Dst = envelope.Destination{Port: dstPort, Proto: "tcp"}
	env.Fingerprints = envelope.Fingerprints{}
	raw := envelope.ScanProbeRaw{BytesIn: bytesIn, RSTSent: false}
	if body, err := json.Marshal(raw); err == nil {
		env.Raw = body
	}
	env.Tags = []string{"tls", "probe"}
	cfg.OnEvent(env)
}

// generateSelfSignedCert mints a fresh ECDSA P-256 key pair + self-signed
// X.509 cert in memory at agent startup. Valid one year, generic SAN so
// any host the scanner asks for matches. Most edge-device scanners ignore
// validity (the appliances they hunt ship with self-signed certs by
// default) so the missing CA chain is not a research-grade obstacle.
func generateSelfSignedCert(cn string) (tls.Certificate, error) {
	if cn == "" {
		cn = "appliance"
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{cn, "*." + cn, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        &x509.Certificate{Raw: der, NotAfter: tmpl.NotAfter},
	}, nil
}

