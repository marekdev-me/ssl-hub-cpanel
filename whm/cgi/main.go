// GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ssl-hub ./whm/cgi
// Install the resulting binary to:
// /usr/local/cpanel/whostmgr/docroot/cgi/ssl-hub/ssl-hub (chmod 750, root:root)
package main

import (
	"crypto/subtle"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

func header() { fmt.Print("Content-Type: text/html; charset=utf-8\r\n\r\n") }

func esc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;")
	return r.Replace(s)
}

func parseForm() (url.Values, error) {
	m := os.Getenv("REQUEST_METHOD")
	switch m {
	case "GET":
		return url.ParseQuery(os.Getenv("QUERY_STRING"))
	case "POST":
		cl := os.Getenv("CONTENT_LENGTH")
		var n int
		fmt.Sscanf(cl, "%d", &n)
		body := make([]byte, n)
		if n > 0 {
			if _, err := io.ReadFull(os.Stdin, body); err != nil {
				return nil, err
			}
		}
		ct := os.Getenv("CONTENT_TYPE")
		if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			return url.ParseQuery(string(body))
		}
		return url.Values{}, nil
	default:
		return url.Values{}, nil
	}
}

var domainRe = regexp.MustCompile(`^(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func safeRun(cmd string, args ...string) (string, error) {
	c := exec.Command(cmd, args...)
	c.Env = os.Environ() // inherit PATH etc.; wrapper script controls sensitive env
	out, err := c.CombinedOutput()
	return string(out), err
}

func h(s string) { fmt.Print(s) }

func gate() bool {
	// Optional: simple protection so only WHM root can trigger actions when proxied.
	// If you set SSL_HUB_SHARED_SECRET in env + in /root/.ssl-hub/secret, verify here.
	secEnv := os.Getenv("SSL_HUB_SHARED_SECRET")
	b, _ := os.ReadFile("/root/.ssl-hub/secret")
	b = bytesTrim(b)
	if len(secEnv) == 0 || len(b) == 0 {
		return true
	}
	if subtle.ConstantTimeCompare([]byte(secEnv), b) == 1 {
		return true
	}
	return false
}

func bytesTrim(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

func main() {
	header()
	form, _ := parseForm()
	tab := form.Get("tab")
	action := form.Get("action")

	h(`<style>body{font-family:system-ui,Segoe UI,Arial;margin:24px}nav a{margin-right:12px}</style>`)
	h(`<h2>SSL Hub</h2><nav>` +
		`<a href="?tab=autossl">AutoSSL (Let’s Encrypt)</a>` +
		`<a href="?tab=zerossl">ZeroSSL (ACME)</a>` +
		`</nav><hr/>`)

	if !gate() {
		h(`<p>Unauthorized.</p>`)
		return
	}

	switch action {
	case "autossl_enable_le":
		// Accept LE TOS checkbox gate from UI
		tos := form.Get("tos")
		if tos != "on" {
			h(`<p>Please accept the Let’s Encrypt Terms of Service.</p>`)
			return
		}
		out, err := safeRun("/usr/local/cpanel/bin/whmapi1", "set_autossl_provider", "provider=LetsEncrypt", "x_terms_of_service_accepted=https://letsencrypt.org/documents/LE-SA-v1.4-April-3-2024.pdf")
		if err != nil {
			h(`<pre>ERROR:
` + esc(out) + `</pre>`)
			return
		}
		h(`<pre>` + esc(out) + `</pre>`)
		return
	case "autossl_run_all":
		out, err := safeRun("/usr/local/cpanel/bin/autossl_check", "--all")
		if err != nil {
			h(`<pre>ERROR:
` + esc(out) + `</pre>`)
			return
		}
		h(`<pre>` + esc(out) + `</pre>`)
		return
	case "zerossl_issue":
		domain := strings.TrimSpace(form.Get("domain"))
		kid := strings.TrimSpace(form.Get("eab_kid"))
		hmac := strings.TrimSpace(form.Get("eab_hmac"))
		if !domainRe.MatchString(domain) {
			h(`<p>Invalid domain.</p>`)
			return
		}
		if len(kid) == 0 || len(hmac) == 0 {
			h(`<p>EAB KID/HMAC required.</p>`)
			return
		}
		out, err := safeRun("/usr/local/cpanel/whostmgr/docroot/cgi/ssl-hub/zerossl.sh", domain, kid, hmac)
		if err != nil {
			h(`<pre>ERROR:
` + esc(out) + `</pre>`)
			return
		}
		h(`<pre>` + esc(out) + `</pre>`)
		return
	}
	// Render tabs
	if tab == "zerossl" {
		h(`<h3>ZeroSSL (ACME via DNS‑01)</h3>`)
		h(`<form method="post"><div>` +
			`<label>Primary domain (wildcard included):</label><br/>` +
			`<input name="domain" placeholder="example.com" required />` +
			`</div><div style="margin-top:8px">` +
			`<label>EAB KID:</label><br/><input name="eab_kid" required />` +
			`</div><div style="margin-top:8px">` +
			`<label>EAB HMAC:</label><br/><input name="eab_hmac" required />` +
			`</div>` +
			`<input type="hidden" name="action" value="zerossl_issue"/>` +
			`<div style="margin-top:12px"><button>Issue & Install</button></div>` +
			`</form>`)
		return
	}
	// default AutoSSL tab
	h(`<h3>AutoSSL (Let’s Encrypt)</h3>`)
	h(`<form method="post" style="margin-bottom:12px">` +
		`<label><input type="checkbox" name="tos"/> I agree to the Let’s Encrypt Terms of Service</label>` +
		`<input type="hidden" name="action" value="autossl_enable_le"/>` +
		`<div style="margin-top:8px"><button>Enable Let’s Encrypt provider</button></div>` +
		`</form>`)

	h(`<form method="post">` +
		`<input type="hidden" name="action" value="autossl_run_all"/>` +
		`<button>Run AutoSSL for all users</button>` +
		`</form>`)
}
