package fcling

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/charmbracelet/log"
)

// What the proxy lets through to an engine: fcling's fabric API and nothing else, so never
// its chat route, its MCP endpoint or its web UI.
var (
	allowedAPIPaths = map[string]map[string]bool{
		http.MethodGet: {
			"status": true, "reports": true, "checks": true, "incidents": true, "acks": true,
			"history": true, "drift": true, "configs": true, "configs/diff": true,
			"baselines": true, "lenses": true, "topology": true, "events": true,
		},
		http.MethodPost:   {"acks": true, "baselines": true},
		http.MethodDelete: {"acks": true},
	}
	// Paths with one more segment: a report's or lens's name, a baseline's name.
	allowedAPINames = map[string]map[string]bool{
		http.MethodGet:    {"reports": true, "lenses": true},
		http.MethodDelete: {"baselines": true},
	}
)

// proxyTransport talks to engines on this host: no proxy from the environment, and a long
// wait for headers since a report that is not streamed is collected on the spot.
var proxyTransport = &http.Transport{
	ResponseHeaderTimeout: 2 * time.Minute,
	MaxIdleConnsPerHost:   4,
	IdleConnTimeout:       30 * time.Second,
}

// AllowedAPI reports whether a request below an engine's /api may be proxied.
func AllowedAPI(method, path string) bool {
	path = strings.TrimPrefix(path, "/")
	if allowedAPIPaths[method][path] {
		return true
	}
	parent, name, found := strings.Cut(path, "/")
	if !found || !allowedAPINames[method][parent] {
		return false
	}
	return name != "" && name != "." && name != ".." && !strings.Contains(name, "/")
}

// NewProxy returns a reverse proxy to a path below a running engine's /api. The caller's
// credentials are for this server: the engine only ever sees its own token.
func NewProxy(target Target, path string) *httputil.ReverseProxy {
	path = strings.TrimPrefix(path, "/")
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = "http"
			r.Out.URL.Host = target.Host
			r.Out.URL.Path = "/api/" + path
			r.Out.URL.RawPath = ""
			r.Out.Host = target.Host

			query := r.Out.URL.Query()
			query.Del("token")
			r.Out.URL.RawQuery = query.Encode()

			r.Out.Header.Set("Authorization", "Bearer "+target.Token)
			r.Out.Header.Del("Cookie")
		},
		// Events arrive as they happen.
		FlushInterval: -1,
		Transport:     proxyTransport,
		ModifyResponse: func(response *http.Response) error {
			// An engine's session cookie must not reach the browser.
			response.Header.Del("Set-Cookie")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Warnf("fcling proxy to %s failed: %v", target.Host, err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprintf(w, `{"error":%q}`, fmt.Sprintf("the fcling engine is not reachable: %v", err))
		},
	}
}
