package models

// HostScriptSourceRequest names a script: a file (relative to the topology folder, or an
// absolute path inside the workspace or shared folder), or the script itself.
type HostScriptSourceRequest struct {
	ScriptPath string `json:"scriptPath,omitempty"`
	Script     string `json:"script,omitempty"`
}

// HostScriptRunRequest is a script to run.
type HostScriptRunRequest struct {
	HostScriptSourceRequest
	// TimeoutSeconds stops the script after this long; at most, and by default, one day.
	TimeoutSeconds *float64 `json:"timeoutSeconds,omitempty"`
	// ExpectedSha256 is the hash of the description the user agreed to. Anything else
	// is refused with 409.
	ExpectedSha256 string `json:"expectedSha256,omitempty"`
}

// HostScriptDescription says what a script is, as the signed-in user can read it now.
type HostScriptDescription struct {
	Kind         string `json:"kind" example:"file"` // file or inline
	ResolvedPath string `json:"resolvedPath,omitempty"`
	Sha256       string `json:"sha256"`
	Size         int64  `json:"size"`
	Owner        string `json:"owner,omitempty"`
	// Foreign means the user may not have written this: another user's file or lab, or a
	// shared folder.
	Foreign   bool   `json:"foreign"`
	Content   string `json:"content"` // The start of the script.
	Truncated bool   `json:"truncated"`
}

// HostScriptResult is how a script ended.
type HostScriptResult struct {
	// ExitCode is null when a signal stopped the script.
	ExitCode   *int  `json:"exitCode"`
	TimedOut   bool  `json:"timedOut"`
	Cancelled  bool  `json:"cancelled,omitempty"`
	DurationMs int64 `json:"durationMs"`
}

// HostScriptEvent is one line of the NDJSON stream of a running script: output as it
// comes, then its exit, or an error. Blank lines only keep the connection open.
type HostScriptEvent struct {
	Type   string            `json:"type" example:"output"` // output, exit or error
	Stream string            `json:"stream,omitempty"`      // stdout or stderr
	Text   string            `json:"text,omitempty"`
	Result *HostScriptResult `json:"result,omitempty"`
	Error  string            `json:"error,omitempty"`
}
