package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

func newQueryContext(rawQuery string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/?"+rawQuery, nil)
	return c, recorder
}

func TestParseMgmtOverrideQuery(t *testing.T) {
	c, recorder := newQueryContext("network=lab-mgmt&ipv4Subnet=172.30.30.0/24&ipv6Subnet=3fff:172:30:30::/64")
	overrides, ok := parseMgmtOverrideQuery(c)
	if !ok {
		t.Fatalf("valid overrides rejected: %s", recorder.Body.String())
	}

	var opts clab.DeployOptions
	overrides.applyTo(&opts)
	if opts.MgmtNetwork != "lab-mgmt" || opts.MgmtIPv4Subnet != "172.30.30.0/24" || opts.MgmtIPv6Subnet != "3fff:172:30:30::/64" {
		t.Fatalf("unexpected deploy options: %+v", opts)
	}

	c, _ = newQueryContext("")
	overrides, ok = parseMgmtOverrideQuery(c)
	if !ok || overrides != (mgmtOverrides{}) {
		t.Fatalf("empty query = %+v, %v; want no overrides", overrides, ok)
	}
}

func TestParseMgmtOverrideQueryRejectsInvalidValues(t *testing.T) {
	for _, query := range []string{
		"network=-bad",
		"network=has%20space",
		"ipv4Subnet=172.30.30.1",
		"ipv4Subnet=3fff::/64",
		"ipv6Subnet=172.30.30.0/24",
		"ipv6Subnet=::ffff:172.30.30.0/120",
	} {
		c, recorder := newQueryContext(query)
		if _, ok := parseMgmtOverrideQuery(c); ok {
			t.Errorf("%s accepted", query)
			continue
		}
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", query, recorder.Code)
		}
	}
}

func TestDeployErrorStatus(t *testing.T) {
	if got := deployErrorStatus(clab.ErrMgmtOverrideUnsupported); got != http.StatusBadRequest {
		t.Fatalf("override error status = %d, want 400", got)
	}
	if got := deployErrorStatus(errors.New("boom")); got != http.StatusInternalServerError {
		t.Fatalf("generic error status = %d, want 500", got)
	}
}

func TestNetemErrorStatus(t *testing.T) {
	for _, err := range []error{clab.ErrNetemInterfaceNotFound, clab.ErrNetemNodeNotFound} {
		if got := netemErrorStatus(err); got != http.StatusNotFound {
			t.Errorf("netemErrorStatus(%v) = %d, want 404", err, got)
		}
	}
	if got := netemErrorStatus(errors.New("boom")); got != http.StatusInternalServerError {
		t.Fatalf("generic error status = %d, want 500", got)
	}
}

func TestResolveNetemRequestTargetValidation(t *testing.T) {
	tests := []struct {
		name                     string
		container, lab, node     string
		nodeOptional             bool
		wantErrorMessageContains string
	}{
		{name: "nothing", wantErrorMessageContains: "containerName or labName"},
		{name: "both", container: "clab-demo-srl1", lab: "demo", node: "srl1", wantErrorMessageContains: "not both"},
		{name: "lab without node", lab: "demo", wantErrorMessageContains: "nodeName is required"},
		{name: "invalid lab", lab: "bad lab", node: "srl1", wantErrorMessageContains: "Invalid lab name"},
		{name: "invalid node", lab: "demo", node: "bad node", wantErrorMessageContains: "Invalid node name"},
		{name: "invalid container", container: "bad container", wantErrorMessageContains: "Invalid container name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder := newQueryContext("")
			if _, ok := resolveNetemRequestTarget(c, "user", tt.container, tt.lab, tt.node, tt.nodeOptional); ok {
				t.Fatal("invalid target accepted")
			}
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", recorder.Code)
			}
			var response models.ErrorResponse
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(response.Error, tt.wantErrorMessageContains) {
				t.Fatalf("error = %q, want it to contain %q", response.Error, tt.wantErrorMessageContains)
			}
		})
	}
}
