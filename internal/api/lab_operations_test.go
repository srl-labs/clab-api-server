package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestDeployReconfigureRequestedCompatibilityAlias(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name  string
		query string
		want  bool
	}{
		{name: "none"},
		{name: "reconfigure", query: "reconfigure=true", want: true},
		{name: "cleanup alias", query: "cleanup=true", want: true},
		{name: "either true", query: "reconfigure=false&cleanup=true", want: true},
		{name: "both false", query: "reconfigure=false&cleanup=false"},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			var got bool
			router := gin.New()
			router.GET("/", func(c *gin.Context) {
				got = deployReconfigureRequested(c)
				c.Status(http.StatusNoContent)
			})

			requestPath := "/"
			if testCase.query != "" {
				requestPath += "?" + testCase.query
			}
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, requestPath, nil))
			if got != testCase.want {
				t.Fatalf("deployReconfigureRequested() = %t, want %t", got, testCase.want)
			}
		})
	}
}

func TestLabOperationRegistryRejectsConcurrentOperation(t *testing.T) {
	registry := &labOperationRegistry{active: make(map[string]string)}

	release, active, ok := registry.begin("demo", "deploy")
	if !ok {
		t.Fatalf("first operation rejected with active %q", active)
	}

	_, active, ok = registry.begin("demo", "netem")
	if ok {
		t.Fatal("second operation on same lab was accepted")
	}
	if active != "deploy" {
		t.Fatalf("active operation = %q, want deploy", active)
	}

	release()
	release, active, ok = registry.begin("demo", "netem")
	if !ok {
		t.Fatalf("operation after release rejected with active %q", active)
	}
	release()
}

func TestLabOperationRegistryAllowsDifferentLabs(t *testing.T) {
	registry := &labOperationRegistry{active: make(map[string]string)}

	release, active, ok := registry.begin("demo-a", "deploy")
	if !ok {
		t.Fatalf("first operation rejected with active %q", active)
	}
	defer release()

	otherRelease, active, ok := registry.begin("demo-b", "destroy")
	if !ok {
		t.Fatalf("different lab operation rejected with active %q", active)
	}
	otherRelease()
}
