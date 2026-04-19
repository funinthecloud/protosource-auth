// Package loginpage serves a browser login form that POSTs to /login
// and sets a shadow cookie on the parent domain.
package loginpage

import (
	"bytes"
	"context"
	_ "embed"
	"html/template"
	"net"
	"net/http"
	"strings"

	"github.com/funinthecloud/protosource"
)

//go:embed login.html
var loginHTML string

var loginTmpl = template.Must(template.New("login").Parse(loginHTML))

// Page serves the login form and implements [protosource.RouteRegistrar].
type Page struct {
	issuerID string
}

// New returns a Page that injects issuerID into the login form template.
func New(issuerID string) *Page {
	return &Page{issuerID: issuerID}
}

// RegisterRoutes registers GET / on the router.
func (p *Page) RegisterRoutes(router *protosource.Router) {
	router.Handle("GET", "/", p.handle)
}

type templateData struct {
	IssuerID     string
	CookieDomain string
}

func (p *Page) handle(_ context.Context, req protosource.Request) protosource.Response {
	host := req.Headers["host"]
	if host == "" {
		host = req.Headers["Host"]
	}

	data := templateData{
		IssuerID:     p.issuerID,
		CookieDomain: parentDomain(host),
	}

	var buf bytes.Buffer
	if err := loginTmpl.Execute(&buf, data); err != nil {
		return protosource.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       "internal error",
			Headers:    map[string]string{"Content-Type": "text/plain"},
		}
	}

	return protosource.Response{
		StatusCode: http.StatusOK,
		Body:       buf.String(),
		Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
	}
}

// parentDomain derives the cookie domain from a Host header value.
//
//	auth.drhayt.com   -> .drhayt.com
//	drhayt.com        -> .drhayt.com
//	localhost:8080    -> ""  (omit Domain attribute)
//	localhost         -> ""
func parentDomain(host string) string {
	// Strip port if present.
	h := host
	if i := strings.LastIndex(h, ":"); i != -1 {
		h = h[:i]
	}

	// IP addresses: no domain attribute.
	if net.ParseIP(h) != nil {
		return ""
	}

	parts := strings.Split(h, ".")
	if len(parts) < 2 {
		return "" // localhost or single-label
	}

	// For "drhayt.com" (2 parts) -> ".drhayt.com"
	// For "auth.drhayt.com" (3+ parts) -> ".drhayt.com"
	return "." + strings.Join(parts[len(parts)-2:], ".")
}
