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

const (
	stateDir        = "/root/.ssl-hub"
	zerosslKidPath  = stateDir + "/zerossl_kid"
	zerosslHmacPath = stateDir + "/zerossl_hmac"
)

func ensureStateDir() error {
	return os.MkdirAll(stateDir, 0o700)
}

func saveEAB(kid, hmac string) error {
	if err := ensureStateDir(); err != nil {
		return err
	}
	if err := os.WriteFile(zerosslKidPath, []byte(kid+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(zerosslHmacPath, []byte(hmac+"\n"), 0o600); err != nil {
		return err
	}
	return nil
}

func loadEAB() (string, string, error) {
	kid, err := os.ReadFile(zerosslKidPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", nil
		}
		return "", "", err
	}
	hmac, err := os.ReadFile(zerosslHmacPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", nil
		}
		return "", "", err
	}
	return strings.TrimSpace(string(kid)), strings.TrimSpace(string(hmac)), nil
}

func maskSecret(s string) string {
	if len(s) == 0 {
		return ""
	}
	if len(s) <= 4 {
		return strings.Repeat("•", len(s))
	}
	return strings.Repeat("•", len(s)-4) + s[len(s)-4:]
}

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

	h(`<style>body{font-family:system-ui,Segoe UI,Arial;margin:24px}` +
		`nav a{margin-right:12px}` +
		`.provider-grid{display:flex;flex-wrap:wrap;gap:16px;margin:16px 0}` +
		`.provider-card{flex:1 1 260px;border:1px solid #d0d7de;border-radius:8px;padding:16px;box-shadow:0 1px 2px rgba(15,23,42,.08)}` +
		`.provider-card h4{margin:0 0 8px;font-size:18px}` +
		`.provider-card p{margin:0 0 12px;color:#334155;font-size:14px}` +
		`.provider-card small{display:block;margin-top:4px;color:#64748b}` +
		`.provider-actions form{margin:0 0 8px}` +
		`.provider-actions button,.provider-actions a.button{display:inline-block;background:#1d4ed8;color:#fff;border:none;border-radius:4px;padding:6px 12px;font-size:14px;text-decoration:none;cursor:pointer}` +
		`.provider-actions a.button{background:#0f172a}` +
		`.provider-actions .secondary{background:#475569}` +
		`</style>`)
	h(`<h2>SSL Hub</h2><nav>` +
		`<a href="?tab=autossl">AutoSSL Providers</a>` +
		`<a href="?tab=zerossl">ZeroSSL AutoSSL</a>` +
		`</nav><hr/>`)

	if !gate() {
		h(`<p>Unauthorized.</p>`)
		return
	}

	switch action {
	case "autossl_enable_cpanel":
		out, err := safeRun("/usr/local/cpanel/bin/whmapi1", "set_autossl_provider", "provider=cPanel")
		if err != nil {
			h(`<pre>ERROR:\n` + esc(out) + `</pre>`)
			return
		}
		h(`<pre>` + esc(out) + `</pre>`)
		return
	case "autossl_enable_le":
		// Accept LE TOS checkbox gate from UI
		tos := form.Get("tos")
		if tos != "on" {
			h(`<p>Please accept the Let’s Encrypt Terms of Service.</p>`)
			return
		}
		out, err := safeRun("/usr/local/cpanel/bin/whmapi1", "set_autossl_provider", "provider=LetsEncrypt", "x_terms_of_service_accepted=https://letsencrypt.org/documents/LE-SA-v1.4-April-3-2024.pdf")
		if err != nil {
			h(`<pre>ERROR:\n` + esc(out) + `</pre>`)
			return
		}
		h(`<pre>` + esc(out) + `</pre>`)
		return
	case "autossl_run_all":
		out, err := safeRun("/usr/local/cpanel/bin/autossl_check", "--all")
		if err != nil {
			h(`<pre>ERROR:\n` + esc(out) + `</pre>`)
			return
		}
		h(`<pre>` + esc(out) + `</pre>`)
		return
	case "zerossl_save_eab":
		kid := strings.TrimSpace(form.Get("eab_kid"))
		hmac := strings.TrimSpace(form.Get("eab_hmac"))
		if len(kid) == 0 || len(hmac) == 0 {
			h(`<p>Please provide both the ZeroSSL External Account Binding KID and HMAC.</p>`)
			return
		}
		if err := saveEAB(kid, hmac); err != nil {
			h(`<pre>ERROR:\n` + esc(err.Error()) + `</pre>`)
			return
		}
		h(`<p>Saved ZeroSSL External Account Binding credentials securely for future runs.</p>`)
		return
	case "zerossl_issue":
		domain := strings.TrimSpace(form.Get("domain"))
		if !domainRe.MatchString(domain) {
			h(`<p>Invalid domain.</p>`)
			return
		}
		kid, hmac, err := loadEAB()
		if err != nil {
			h(`<pre>ERROR:\n` + esc(err.Error()) + `</pre>`)
			return
		}
		if len(kid) == 0 || len(hmac) == 0 {
			h(`<p>Please save your ZeroSSL EAB credentials before issuing certificates.</p>`)
			return
		}
		out, err := safeRun("/usr/local/cpanel/whostmgr/docroot/cgi/ssl-hub/zerossl.sh", domain)
		if err != nil {
			h(`<pre>ERROR:\n` + esc(out) + `</pre>`)
			return
		}
		h(`<pre>` + esc(out) + `</pre>`)
		return
	case "zerossl_run_all":
		kid, hmac, err := loadEAB()
		if err != nil {
			h(`<pre>ERROR:\n` + esc(err.Error()) + `</pre>`)
			return
		}
		if len(kid) == 0 || len(hmac) == 0 {
			h(`<p>Please save your ZeroSSL EAB credentials before running AutoSSL.</p>`)
			return
		}
		out, err := safeRun("/usr/local/cpanel/whostmgr/docroot/cgi/ssl-hub/zerossl.sh", "--run-all")
		if err != nil {
			h(`<pre>ERROR:\n` + esc(out) + `</pre>`)
			return
		}
		h(`<pre>` + esc(out) + `</pre>`)
		return
	}
	// Render tabs
	if tab == "zerossl" {
		kid, hmac, err := loadEAB()
		h(`<h3>ZeroSSL AutoSSL</h3>`)
		if err != nil {
			h(`<p style="color:#c00">Unable to read stored credentials: ` + esc(err.Error()) + `</p>`)
		} else if len(kid) > 0 && len(hmac) > 0 {
			h(`<p>Stored ZeroSSL EAB KID: ` + esc(maskSecret(kid)) + ` &mdash; HMAC: ` + esc(maskSecret(hmac)) + `.</p>`)
		} else {
			h(`<p>No ZeroSSL External Account Binding credentials saved yet.</p>`)
		}
		h(`<form method="post"><div>` +
			`<label>EAB KID:</label><br/><input name="eab_kid" autocomplete="off" required />` +
			`</div><div style="margin-top:8px">` +
			`<label>EAB HMAC:</label><br/><input name="eab_hmac" autocomplete="off" required />` +
			`</div>` +
			`<input type="hidden" name="action" value="zerossl_save_eab"/>` +
			`<div style="margin-top:12px"><button>Save ZeroSSL credentials</button></div>` +
			`</form>`)
		h(`<form method="post" style="margin-top:16px">` +
			`<input type="hidden" name="action" value="zerossl_run_all"/>` +
			`<button>Run ZeroSSL AutoSSL for all cPanel accounts</button>` +
			`</form>`)
		h(`<form method="post" style="margin-top:16px"><div>` +
			`<label>Primary domain (wildcard included):</label><br/>` +
			`<input name="domain" placeholder="example.com" required />` +
			`</div>` +
			`<input type="hidden" name="action" value="zerossl_issue"/>` +
			`<div style="margin-top:12px"><button>Issue & Install for this domain</button></div>` +
			`<p style="font-size:12px;color:#555">The script will automatically include *.domain for wildcard coverage.</p>` +
			`</form>`)
		return
	}
	// default AutoSSL tab
	kid, hmac, err := loadEAB()
	h(`<h3>AutoSSL Providers</h3>`)
	h(`<div class="provider-grid">`)
	h(`<div class="provider-card">` +
		`<h4>cPanel (powered by Sectigo)</h4>` +
		`<p>The default AutoSSL provider included with WHM.</p>` +
		`<div class="provider-actions">` +
		`<form method="post">` +
		`<input type="hidden" name="action" value="autossl_enable_cpanel"/>` +
		`<button class="secondary">Enable cPanel provider</button>` +
		`</form>` +
		`</div>` +
		`</div>`)

	h(`<div class="provider-card">` +
		`<h4>Let’s Encrypt</h4>` +
		`<p>Issue certificates from Let’s Encrypt via the official AutoSSL provider.</p>` +
		`<div class="provider-actions">` +
		`<form method="post">` +
		`<label style="display:block;margin-bottom:6px"><input type="checkbox" name="tos"/> I agree to the Let’s Encrypt Terms of Service</label>` +
		`<input type="hidden" name="action" value="autossl_enable_le"/>` +
		`<button>Enable Let’s Encrypt provider</button>` +
		`</form>` +
		`</div>` +
		`</div>`)

	h(`<div class="provider-card">` +
		`<h4>ZeroSSL (via SSL Hub)</h4>`)
	switch {
	case err != nil:
		h(`<p style="color:#b91c1c">Unable to read stored ZeroSSL credentials: ` + esc(err.Error()) + `.</p>`)
	case len(kid) == 0 || len(hmac) == 0:
		h(`<p>ZeroSSL External Account Binding credentials are not saved yet. Configure them before enabling ZeroSSL.</p>`)
	default:
		h(`<p>Ready to issue certificates with ZeroSSL. Stored EAB KID ` + esc(maskSecret(kid)) + ` and HMAC ` + esc(maskSecret(hmac)) + `.</p>`)
	}
	h(`<div class="provider-actions">`)
	if err == nil && len(kid) > 0 && len(hmac) > 0 {
		h(`<form method="post">` +
			`<input type="hidden" name="action" value="zerossl_run_all"/>` +
			`<button>Run ZeroSSL AutoSSL now</button>` +
			`</form>`)
	}
	h(`<a class="button" href="?tab=zerossl">Manage ZeroSSL provider</a>` +
		`</div>` +
		`</div>`)
	h(`</div>`)

	h(`<form method="post">` +
		`<input type="hidden" name="action" value="autossl_run_all"/>` +
		`<button>Run active AutoSSL provider for all users</button>` +
		`</form>`)
}
