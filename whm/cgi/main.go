package main

import (
	"embed"
	"html/template"
	"net/http"
	"net/http/cgi"
	"os/exec"
	"regexp"
)

//go:embed templates/*.tmpl templates/partials/*.tmpl
var tplFS embed.FS

var (
	tpl      = template.Must(template.ParseFS(tplFS, "templates/*.tmpl", "templates/partials/*.tmpl"))
	domainRe = regexp.MustCompile(`^(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

type PageData struct {
	Tab          string
	BodyTemplate string
	Output       string
}

func run(cmd string, args ...string) (string, error) {
	c := exec.Command(cmd, args...)
	out, err := c.CombinedOutput()
	return string(out), err
}

func handler(w http.ResponseWriter, r *http.Request) {
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "autossl"
	}

	data := PageData{
		Tab:          tab,
		BodyTemplate: "autossl", // default
	}

	if tab == "zerossl" {
		data.BodyTemplate = "zerossl"
	}

	if r.Method == http.MethodPost {
		switch r.FormValue("action") {
		case "autossl_enable_le":
			if r.FormValue("tos") != "on" {
				data.Output = "Please accept the Let’s Encrypt Terms of Service."
				break
			}
			out, err := run("/usr/local/cpanel/bin/whmapi1",
				"set_autossl_provider",
				"provider=LetsEncrypt",
				"x_terms_of_service_accepted=https://letsencrypt.org/documents/LE-SA-v1.4-April-3-2024.pdf",
			)
			if err != nil {
				data.Output = "ERROR:\n" + out
			} else {
				data.Output = out
			}
		case "autossl_run_all":
			out, err := run("/usr/local/cpanel/bin/autossl_check", "--all")
			if err != nil {
				data.Output = "ERROR:\n" + out
			} else {
				data.Output = out
			}
		case "zerossl_issue":
			domain := r.FormValue("domain")
			kid := r.FormValue("eab_kid")
			hmac := r.FormValue("eab_hmac")
			if !domainRe.MatchString(domain) {
				data.Output = "Invalid domain."
				break
			}
			if kid == "" || hmac == "" {
				data.Output = "EAB KID/HMAC required."
				break
			}
			out, err := run("/usr/local/cpanel/whostmgr/docroot/cgi/ssl-hub/zerossl.sh", domain, kid, hmac)
			if err != nil {
				data.Output = "ERROR:\n" + out
			} else {
				data.Output = out
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

func main() {
	_ = cgi.Serve(http.HandlerFunc(handler))
}
