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

// presencePatterns flags an appliance vendor / CVE-probe class purely
// from the URL substring. Matched against the full lowercase
// RequestURI() so encoded query params (`?@evil/`) are still visible.
// First match wins per vendor; multiple vendor tags are possible if
// a request contains independent markers. Sourced from named threat-
// intel reports — see the long-form comments next to each block for
// the published advisory each pattern is grounded in.
var presencePatterns = []struct {
	needle string
	tag    string
}{
	// --- Palo Alto GlobalProtect / PAN-OS ---
	// Volexity April-2024 zero-day report; UMBRELLA + Unit42 telemetry.
	{"/global-protect/", "edge-device:globalprotect"},
	{"/sslmgr", "edge-device:globalprotect"},
	{"/ssl-vpn/hipreport.esp", "edge-device:globalprotect"},
	{"/ssl-vpn/login.esp", "edge-device:globalprotect"},
	// PAN-OS management plane (watchTowr "Pots and Pans" research,
	// CVE-2024-0012 / 9474). Only the createremoteappwebsession.php
	// path is distinctive — `/php/login.php` alone is too common
	// across random PHP apps to attribute reliably.
	{"/php/utils/createremoteappwebsession.php", "edge-device:panos-mgmt"},

	// --- Fortinet FortiOS / FortiManager ---
	// CVE-2018-13379, CVE-2022-42475, CVE-2024-21762 all hit the SSL VPN
	// portal at /remote/*. abrewer251 PoC for 21762 anchors on /remote/
	// hostcheck_validate.
	{"/remote/login", "edge-device:fortinet"},
	{"/remote/logincheck", "edge-device:fortinet"},
	{"/remote/fgt_lang", "edge-device:fortinet"},
	{"/remote/error", "edge-device:fortinet"},
	{"/remote/hostcheck_validate", "edge-device:fortinet"},
	{"/sslvpn_logon.shtml", "edge-device:fortinet"},
	// FortiManager web UI is at /p/login but that path is too generic
	// to attribute on its own. The CVE-2024-47575 marker is on
	// TCP/541 (FGFM), not the HTTP plane — handled out-of-band.

	// --- Ivanti Connect Secure / Pulse Secure / Sentry ---
	// Mandiant "Cutting Edge" + Unit42 research on CVE-2023-46805 +
	// CVE-2024-21887 path traversal → command injection chain.
	{"/dana-na/", "edge-device:ivanti"},
	{"/dana/home/", "edge-device:ivanti"},
	{"/dana-ws/saml.ws", "edge-device:ivanti"},
	{"/dana-ws/saml20.ws", "edge-device:ivanti"},
	{"/api/v1/totp/user-backup-code/", "edge-device:ivanti"},
	{"/api/v1/license/keys-status/", "edge-device:ivanti"},
	// Ivanti Sentry MICS web admin.
	{"/mics/", "edge-device:ivanti-sentry"},

	// --- Cisco ASA / AnyConnect / FTD ---
	// Eclypsium scanning-surge analysis + Talos brute-force telemetry.
	// `+cscoe+` and `+cscou+` are URL-escaped on the wire so the
	// post-decode lowercased path contains the raw `+`.
	{"/+cscoe+/", "edge-device:cisco-asa"},
	{"/+cscou+/", "edge-device:cisco-asa"},
	{"/+webvpn+/", "edge-device:cisco-asa"},
	{"/cscoplus/", "edge-device:cisco-asa"},

	// --- Citrix NetScaler / Gateway / ADC ---
	// Assetnote CVE-2023-3519 walkthrough; Mandiant "Citrix Bleed"
	// CVE-2023-4966 advisory.
	{"/vpn/index.html", "edge-device:citrix"},
	{"/logon/logonpoint/", "edge-device:citrix"},
	{"/citrix/", "edge-device:citrix"},
	{"/netscaler/", "edge-device:citrix"},
	{"/nf/auth/doauthentication.do", "edge-device:citrix"},
	{"/gwtest/formssso", "edge-device:citrix"},
	{"/cgi/api/login", "edge-device:citrix"},
	{"/vpns/cfg/smb.conf", "edge-device:citrix"},
	{"/vpns/portal/scripts/newbm.pl", "edge-device:citrix"},
	// Citrix Bleed's anchor is `/oauth/idp/.well-known/openid-
	// configuration`, but that's the standard OIDC discovery URL —
	// any OAuth-compliant service exposes it. Attribution happens
	// only when the oversized-Host CVE-2023-4966 marker also fires
	// (composite check below).

	// --- Microsoft Exchange OWA / ECP / Autodiscover ---
	// MSRC ProxyShell / ProxyLogon / ProxyNotShell advisories. The `@`
	// in autodiscover query strings is the ProxyShell marker but it
	// can't go in a substring match — handled separately below.
	{"/owa/", "edge-device:exchange"},
	{"/ecp/", "edge-device:exchange"},
	{"/autodiscover/autodiscover.xml", "edge-device:exchange"},
	{"/autodiscover/autodiscover.json", "edge-device:exchange"},
	{"/mapi/nspi/", "edge-device:exchange"},
	{"/ews/exchange.asmx", "edge-device:exchange"},
	{"/rpc/rpcproxy.dll", "edge-device:exchange"},

	// --- SonicWall SMA / SonicOS ---
	// Rapid7 CVE-2024-40766 ETR + earlier 2021-20016 reports.
	{"/sonicui/", "edge-device:sonicwall"},
	{"/cgi-bin/welcome", "edge-device:sonicwall"},
	{"/cgi-bin/userlogin", "edge-device:sonicwall"},
	{"/cgi-bin/jarrewrite.sh", "edge-device:sonicwall"},
	{"/__api__/v1/logon", "edge-device:sonicwall"},
	{"/sslvpnclient", "edge-device:sonicwall"},

	// --- F5 BIG-IP TMUI / iControl REST ---
	// Praetorian "Refresh" CVE-2023-46747 writeup; F5's own CVE-2022-
	// 1388 advisory. The `/tmui/login.jsp/..;/tmui/locallb/...` path
	// (CVE-2020-5902) requires preserving the `;` semicolon.
	{"/tmui/login.jsp", "edge-device:f5-bigip"},
	{"/tmui/locallb/", "edge-device:f5-bigip"},
	{"/mgmt/tm/sys/", "edge-device:f5-bigip"},
	{"/mgmt/tm/util/bash", "edge-device:f5-bigip"},
	{"/mgmt/tm/auth/user", "edge-device:f5-bigip"},

	// --- VMware vCenter / ESXi ---
	// Juniper CVE-2021-21972 RCE PoC; Broadcom advisory for 2024-37081.
	{"/ui/vropspluginui/rest/services/uploadova", "edge-device:vcenter"},
	{"/analytics/telemetry/ph/api/hyper/send", "edge-device:vcenter"},
	{"/websso/saml2", "edge-device:vcenter"},
	// `/sdk`, `/mob/`, `/folder/` are too generic on their own to
	// attribute to vCenter/ESXi — many unrelated services expose
	// those names. Skipped from presence; can be added later via
	// composite checks (e.g. SDK + SOAP envelope marker).

	// --- Atlassian Confluence / Jira ---
	// CISA AA23-289A on CVE-2023-22515 unauth privilege escalation.
	// `/login.action` alone is too generic — it's a Struts
	// convention used by Confluence, Jira, and any standalone Struts
	// app. Confluence-specific attribution requires one of the
	// distinctive setup/admin paths below.
	{"/dologin.action", "edge-device:confluence"},
	{"/server-info.action", "edge-device:confluence"},
	{"/setup/setupadministrator.action", "edge-device:confluence"},
	{"/setup/finishsetup.action", "edge-device:confluence"},
	{"/admin/configurenewlanguage.action", "edge-device:confluence"},
	{"/rest/api/2/serverinfo", "edge-device:jira"},
	{"/secure/dashboard.jspa", "edge-device:jira"},
	{"/insightplugin/", "edge-device:jira"},

	// --- App-server / Java enterprise ---
	// Spring Boot Actuator paths (CVE-2022-22947 SpringCloud Gateway
	// RCE pivots through /actuator/gateway/routes); Tomcat manager UI;
	// Jolokia JMX-over-HTTP enumeration (SANS ISC). Tagged separately
	// from "edge-device" because they aren't network appliances.
	{"/actuator/env", "appserver:spring-actuator"},
	{"/actuator/heapdump", "appserver:spring-actuator"},
	{"/actuator/gateway/routes", "appserver:spring-actuator"},
	{"/actuator/jolokia", "appserver:jolokia"},
	{"/jolokia/list", "appserver:jolokia"},
	{"/manager/html", "appserver:tomcat"},
	{"/manager/text/list", "appserver:tomcat"},
	{"/host-manager/html", "appserver:tomcat"},
	{"/jmx-console/", "appserver:jboss"},
	{"/invoker/jmxinvokerservlet", "appserver:jboss"},
	{"/web-console/", "appserver:jboss"},
	{"/struts2-showcase/", "appserver:struts"},

	// --- SOHO routers / IoT (Mirai-class) ---
	// SANS ISC multi-perimeter Mirai diaries; Realtek SDK probes;
	// Linksys "Moon worm" CVE-2014-9583 still everywhere in 2026.
	{"/hnap1/", "edge-device:soho-router"},
	{"/gponform/", "edge-device:soho-router"},
	{"/cgi-bin/luci", "edge-device:soho-router"},
	{"/setup.cgi", "edge-device:soho-router"},
	{"/ud/?5", "edge-device:soho-router"},
	{"/boaform/", "edge-device:soho-router"},
	{"/goform/setmac", "edge-device:soho-router"},
	{"/goform/sysmode", "edge-device:soho-router"},
	{"/goform/webread/open", "edge-device:soho-router"},
	{"/tmunblock.cgi", "edge-device:soho-router"},
	{"/picsdesc.xml", "edge-device:soho-router"},
	{"/soap.cgi?service=", "edge-device:soho-router"},
	{"/wlogin.htm", "edge-device:soho-router"},
	{"/web/cgi-bin/hi3510/", "edge-device:iot-camera"},
	{"/onvif/device_service", "edge-device:iot-camera"},
}

// cveyPaths flags any request that smells like a generic CVE / web-shell
// hunter. Keeps the existing `cve-probe` umbrella tag the dashboard
// already faceted on.
var cveyPaths = []string{
	"/wp-admin", "/wp-login", "/xmlrpc.php",
	"/phpmyadmin", "/pma", "/adminer",
	"/solr/", "/actuator", "/struts",
	"/.env", "/.git/", "/config.json", "/server-status",
	"/cgi-bin/", "/shell", "/webshell",
}

// Tags applied on top of the base `http` tag when we spot characteristic
// CVE-probe patterns. Output is the dedup'd union of:
//   - vendor presence patterns (table above)
//   - generic CVE-probe umbrella
//   - composite CVE signals (path + body + header co-signals)
//   - request-shape signals (CONNECT, log4shell, scanner UA)
func tagsForRequest(r *http.Request, body []byte) []string {
	tagSet := map[string]struct{}{"http": {}}
	add := func(t string) { tagSet[t] = struct{}{} }

	// Match against the full URI (path + query) so encoded query
	// markers like ProxyShell's `?@evil/` and OGNL `${...}` literals
	// in the URL are visible.
	uri := strings.ToLower(r.URL.RequestURI())
	for _, p := range presencePatterns {
		if strings.Contains(uri, p.needle) {
			add(p.tag)
		}
	}

	for _, needle := range cveyPaths {
		if strings.Contains(uri, needle) {
			add("cve-probe")
			break
		}
	}

	// --- Composite CVE signals ---
	// CVE-2022-26134 (Confluence OGNL) — `${...}` in the URI itself.
	// Matches both raw `${` and URL-encoded `%7b`.
	if strings.Contains(uri, "${") || strings.Contains(uri, "$%7b") {
		add("cve:CVE-2022-26134")
	}
	// CVE-2024-3400 (Palo Alto GlobalProtect) — Volexity PoC plants
	// path-traversal payload in the SESSID cookie of a /ssl-vpn/
	// hipreport.esp request. Cookie containing `/../` is the marker.
	if strings.Contains(uri, "/ssl-vpn/hipreport.esp") ||
		strings.Contains(uri, "/global-protect/") {
		if cookie := r.Header.Get("Cookie"); strings.Contains(cookie, "SESSID=") &&
			(strings.Contains(cookie, "/..") || strings.Contains(cookie, "${")) {
			add("cve:CVE-2024-3400")
		}
	}
	// CVE-2023-4966 (Citrix Bleed) — Mandiant: oversized Host header
	// (>21,739 bytes) on the OAuth IdP discovery endpoint leaks the
	// server's session token. We use 16 KiB as a conservative trigger
	// since legitimate Hosts are tens of bytes. The presence pattern
	// table deliberately excludes /oauth/idp/ on its own (standard
	// OIDC discovery URL, ambiguous), so we tag the vendor here.
	if strings.Contains(uri, "/oauth/idp/") && len(r.Host) > 16*1024 {
		add("cve:CVE-2023-4966")
		add("edge-device:citrix")
	}
	// CVE-2023-46747 (F5 BIG-IP TMUI request smuggling, Praetorian) —
	// `Connection: X-F5-Auth-Token` header on /mgmt/tm/auth/user.
	if strings.Contains(uri, "/mgmt/tm/auth/user") {
		for _, c := range r.Header["Connection"] {
			if strings.Contains(strings.ToLower(c), "x-f5-auth-token") {
				add("cve:CVE-2023-46747")
				break
			}
		}
	}
	// ProxyShell family (CVE-2021-34473 + CVE-2022-41040) — the `@`
	// path-confusion marker in the autodiscover query string. r.URL.
	// RawQuery preserves the `@` (URI parser doesn't strip it).
	if strings.Contains(uri, "/autodiscover/") && strings.Contains(r.URL.RawQuery, "@") {
		add("cve:CVE-2021-34473")
	}

	if strings.EqualFold(r.Method, "CONNECT") {
		add("proxy-probe")
	}

	// Log4Shell — `${jndi:` in any header value or body. Walk the
	// header values explicitly; iterating the map lets us catch it
	// in less-obvious headers like X-Forwarded-For where attackers
	// like to stash JNDI payloads.
	joined := strings.ToLower(string(body))
	for _, vs := range r.Header {
		for _, v := range vs {
			joined += "\n" + strings.ToLower(v)
		}
	}
	if strings.Contains(joined, "${jndi:") {
		add("log4shell")
		add("cve:CVE-2021-44228")
	}

	ua := strings.ToLower(r.UserAgent())
	switch {
	case strings.Contains(ua, "censys"), strings.Contains(ua, "internet-measurement"):
		add("scanner:censys")
	case strings.Contains(ua, "shodan"):
		add("scanner:shodan")
	case strings.Contains(ua, "binaryedge"):
		add("scanner:binaryedge")
	case strings.Contains(ua, "shadowserver"):
		add("scanner:shadowserver")
	case strings.Contains(ua, "greynoise"):
		add("scanner:greynoise")
	case strings.Contains(ua, "zgrab"), strings.Contains(ua, "masscan"):
		add("scanner:mass")
	}

	out := make([]string, 0, len(tagSet))
	for t := range tagSet {
		out = append(out, t)
	}
	return out
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

// httpRequestHandler is the canonical request-capture handler. Shared
// by the plaintext HTTP listener and the HTTPS listener so a probe on
// :443 (TLS-terminated) produces the same `http.request` envelope
// shape as a probe on :80 — the only difference is the scheme and
// the dst.port. `listenPort` is the wire port the agent bound to,
// stamped into env.Dst.Port.
func httpRequestHandler(cfg HTTPConfig, listenPort int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		srcHost, srcPort := splitHostPortStr(r.RemoteAddr)
		ipHash, _ := cfg.Pepper.SrcIPHash(srcHost)

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
		env.Dst = envelope.Destination{Port: listenPort, Proto: "tcp"}
		env.Fingerprints = envelope.Fingerprints{}
		env.Tags = tagsForRequest(r, body)
		if encoded, err := json.Marshal(raw); err == nil {
			env.Raw = encoded
		}
		cfg.OnEvent(env)

		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(nginxIndex))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(nginx404))
	}
}

func StartHTTP(ctx context.Context, cfg HTTPConfig) (stop func() error, err error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", httpRequestHandler(cfg, portFromListen(cfg.Listen)))

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
