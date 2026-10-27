// internal/api/request_log.go
package api

import (
	"bytes"
	"io"
	"regexp"

	"github.com/gin-gonic/gin"
)

// captureTicketPathRx matches the capture ticket in a Packetflix path
// (/api/v1/capture/packetflix/<ticket>[/capture|/discover/mobyshark]). The ticket is a
// credential, so logs show it as <redacted>. A route parameter (:ticket, as gin's debug output
// lists routes) is left alone; tickets are base64url and never start with a colon.
var captureTicketPathRx = regexp.MustCompile(`(?i)(/api/v1/capture/packetflix/+)[^/?#\s"':][^/?#\s"']*`)

// redactedTicket replaces a capture ticket in logs.
const redactedTicket = "<redacted>"

// RedactCaptureTickets replaces capture tickets in request paths within text with <redacted>.
func RedactCaptureTickets(text string) string {
	return captureTicketPathRx.ReplaceAllString(text, "${1}"+redactedTicket)
}

// redactingWriter writes what it is given with capture tickets redacted. Gin's logger and
// recovery write each entry with one Write, so a ticket is never split across writes.
type redactingWriter struct {
	out io.Writer
}

// NewRedactingWriter returns a writer that redacts capture tickets before writing to out.
func NewRedactingWriter(out io.Writer) io.Writer {
	return redactingWriter{out: out}
}

func (w redactingWriter) Write(p []byte) (int, error) {
	if !bytes.Contains(bytes.ToLower(p), []byte("/capture/packetflix/")) {
		return w.out.Write(p)
	}
	if _, err := w.out.Write([]byte(RedactCaptureTickets(string(p)))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// RequestLogging returns gin's request logger and panic recovery, writing to out and errOut
// with capture tickets redacted from request paths: the access log line, and the request
// recovery dumps after a panic.
func RequestLogging(out, errOut io.Writer) []gin.HandlerFunc {
	return []gin.HandlerFunc{
		gin.LoggerWithConfig(gin.LoggerConfig{Output: NewRedactingWriter(out)}),
		gin.RecoveryWithWriter(NewRedactingWriter(errOut)),
	}
}
