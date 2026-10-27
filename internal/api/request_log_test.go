package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/srl-labs/clab-api-server/internal/config"
)

func TestRedactCaptureTickets(t *testing.T) {
	const ticket = "q1w2E3r4-_T5y6U7i8O9p0a1S2d3F4g5H6j7K8l9Z0x"
	for in, want := range map[string]string{
		"/api/v1/capture/packetflix/" + ticket:                                         "/api/v1/capture/packetflix/<redacted>",
		"/api/v1/capture/packetflix/" + ticket + "/capture":                            "/api/v1/capture/packetflix/<redacted>/capture",
		"/api/v1/capture/packetflix/" + ticket + "/capture?nif=a/b":                    "/api/v1/capture/packetflix/<redacted>/capture?nif=a/b",
		"/api/v1/capture/packetflix/" + ticket + "/discover/mobyshark":                 "/api/v1/capture/packetflix/<redacted>/discover/mobyshark",
		`GET "/api/v1/capture/packetflix/` + ticket + `" 404`:                          `GET "/api/v1/capture/packetflix/<redacted>" 404`,
		"/api/v1/capture/packetflix//" + ticket:                                        "/api/v1/capture/packetflix//<redacted>",
		"/API/V1/capture/packetflix/" + ticket:                                         "/API/V1/capture/packetflix/<redacted>",
		"packetflix:wss://h:8443/api/v1/capture/packetflix/" + ticket + "?container=x": "packetflix:wss://h:8443/api/v1/capture/packetflix/<redacted>?container=x",
		// Not a ticket path, or the route's parameter.
		"/api/v1/capture/packetflix/:ticket/capture": "/api/v1/capture/packetflix/:ticket/capture",
		"/api/v1/labs/lab1/capture/packetflix":       "/api/v1/labs/lab1/capture/packetflix",
		"/api/v1/labs/lab1/capture/tickets":          "/api/v1/labs/lab1/capture/tickets",
		"/api/v1/capture/wireshark-vnc-sessions":     "/api/v1/capture/wireshark-vnc-sessions",
	} {
		require.Equal(t, want, RedactCaptureTickets(in), in)
	}
}

// TestRequestLoggingRedactsCaptureTickets runs the server's routes with the request logging
// middleware: the access log and the recovery log of a panicking request show the Packetflix
// paths without their tickets.
func TestRequestLoggingRedactsCaptureTickets(t *testing.T) {
	// In debug mode gin's recovery dumps the request (method, path, headers) with the panic.
	gin.SetMode(gin.DebugMode)
	previousWriter := gin.DefaultWriter
	var debugOut bytes.Buffer
	gin.DefaultWriter = NewRedactingWriter(&debugOut)
	t.Cleanup(func() {
		gin.SetMode(gin.TestMode)
		gin.DefaultWriter = previousWriter
	})
	previous := config.AppConfig
	t.Cleanup(func() { config.AppConfig = previous })
	config.AppConfig.ClabRuntime = "docker"
	const ticket = "Zx9Yw8Xv7Wu6Vt5Us4Tr3Sq2Rp1Qo0Pn9Om8Nl7Mk6L"

	var out, errOut bytes.Buffer
	router := gin.New()
	router.Use(RequestLogging(&out, &errOut)...)
	router.GET("/api/v1/capture/packetflix/:ticket/discover/panic", func(*gin.Context) { panic("boom") })
	SetupRoutes(router)

	for _, target := range []string{
		"/api/v1/capture/packetflix/" + ticket,
		"/api/v1/capture/packetflix/" + ticket + "/capture?container=%7B%7D&nif=n1:eth1",
		"/api/v1/capture/packetflix/" + ticket + "/discover/mobyshark",
		"/api/v1/capture/packetflix/" + ticket + "/no/such/route",
		"/api/v1/capture/packetflix/" + ticket + "/discover/panic",
	} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
		require.NotZero(t, recorder.Code, target)
	}

	access := out.String()
	require.Equal(t, 5, strings.Count(access, "/api/v1/capture/packetflix/<redacted>"), access)
	require.Contains(t, access, "/api/v1/capture/packetflix/<redacted>/capture")
	require.Contains(t, access, "/api/v1/capture/packetflix/<redacted>/discover/mobyshark")
	require.Contains(t, access, "| 500 |", "the panicking request is logged too")
	recovery := errOut.String()
	require.Contains(t, recovery, "boom")
	require.Contains(t, recovery, "GET /api/v1/capture/packetflix/<redacted>/discover/panic")
	require.Contains(t, debugOut.String(), "/api/v1/capture/packetflix/:ticket/capture", "routes are listed as they are")
	for name, log := range map[string]string{"access": access, "recovery": recovery, "debug": debugOut.String()} {
		require.NotContains(t, log, ticket, "the %s log holds the ticket", name)
		require.NotContains(t, log, ticket[:16], "the %s log holds part of the ticket", name)
	}
}
