package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRegisteredRoutesHaveSwaggerDocs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	SetupRoutes(router)

	swaggerPaths := loadSwaggerPathMethods(t)
	var missing []string

	for _, route := range router.Routes() {
		method := strings.ToLower(route.Method)
		path := normalizeGinPath(route.Path)

		if isNonAPIDocumentationRoute(method, path) {
			continue
		}
		if isProxyImplementationDetail(method, path) {
			continue
		}
		if _, ok := swaggerPaths[path][method]; ok {
			continue
		}

		missing = append(missing, strings.ToUpper(method)+" "+path)
	}

	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("registered routes missing from swagger docs:\n%s", strings.Join(missing, "\n"))
	}
}

func loadSwaggerPathMethods(t *testing.T) map[string]map[string]struct{} {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve current test file path")
	}

	swaggerPath := filepath.Join(filepath.Dir(filename), "..", "..", "docs", "swagger.json")
	raw, err := os.ReadFile(swaggerPath)
	if err != nil {
		t.Fatalf("read swagger spec: %v", err)
	}

	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("parse swagger spec: %v", err)
	}

	pathMethods := make(map[string]map[string]struct{}, len(spec.Paths))
	for path, methods := range spec.Paths {
		pathMethods[path] = make(map[string]struct{}, len(methods))
		for method := range methods {
			pathMethods[path][strings.ToLower(method)] = struct{}{}
		}
	}

	return pathMethods
}

func normalizeGinPath(path string) string {
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if strings.HasPrefix(segment, ":") || strings.HasPrefix(segment, "*") {
			segments[i] = "{" + segment[1:] + "}"
		}
	}
	return strings.Join(segments, "/")
}

func isNonAPIDocumentationRoute(method, path string) bool {
	return method == "get" && (path == "/redoc" || path == "/swagger/{any}")
}

func isProxyImplementationDetail(method, path string) bool {
	if method == "get" {
		return false
	}
	return path == "/api/v1/capture/wireshark-vnc-sessions/{sessionId}/vnc/{proxyPath}" ||
		path == "/api/v1/labs/{labName}/nodes/{nodeName}/ports/{port}/proxy/{proxyPath}"
}
