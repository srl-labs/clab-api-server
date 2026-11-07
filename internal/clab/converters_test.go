package clab

import (
	"encoding/json"
	"strings"
	"testing"

	clabcore "github.com/srl-labs/containerlab/core"
	clabexec "github.com/srl-labs/containerlab/exec"

	"github.com/srl-labs/clab-api-server/internal/models"
)

func TestApplyResultToResponseCopiesFields(t *testing.T) {
	result := &clabcore.ApplyResult{
		DryRun:           true,
		DeployedLab:      true,
		LabName:          "demo",
		AddedNodes:       []string{"n2"},
		DeletedNodes:     []string{"n3"},
		RecreatedNodes:   []string{"xrd1"},
		StartedNodes:     []string{"n4"},
		AddedLinks:       []string{"n1:eth1<-->n2:eth1"},
		DeletedEndpoints: []string{"n3:eth1"},
		RestartedNodes:   []string{"ceos1"},
		NodeChangeReasons: map[string]string{
			"ceos1": "added link",
		},
	}

	response := ApplyResultToResponse(result)

	if !response.DryRun {
		t.Fatal("expected dryRun=true")
	}
	if !response.DeployedLab {
		t.Fatal("expected deployedLab=true")
	}
	if response.LabName != "demo" {
		t.Fatalf("labName = %q, want demo", response.LabName)
	}
	if got := response.AddedNodes[0]; got != "n2" {
		t.Fatalf("addedNodes[0] = %q, want n2", got)
	}
	if got := response.NodeChangeReasons["ceos1"]; got != "added link" {
		t.Fatalf("nodeChangeReasons[ceos1] = %q, want added link", got)
	}

	result.AddedNodes[0] = "mutated"
	result.NodeChangeReasons["ceos1"] = "mutated"
	if got := response.AddedNodes[0]; got != "n2" {
		t.Fatalf("response addedNodes was aliased, got %q", got)
	}
	if got := response.NodeChangeReasons["ceos1"]; got != "added link" {
		t.Fatalf("response nodeChangeReasons was aliased, got %q", got)
	}
}

func TestApplyResultToResponseHandlesNil(t *testing.T) {
	response := ApplyResultToResponse(nil)
	if response.AddedNodes == nil {
		t.Fatal("expected non-nil addedNodes")
	}
	if response.NodeChangeReasons == nil {
		t.Fatal("expected non-nil nodeChangeReasons")
	}
}

func TestApplyResultToResponseHandlesNilFields(t *testing.T) {
	response := ApplyResultToResponse(&clabcore.ApplyResult{})
	if response.AddedNodes == nil {
		t.Fatal("expected non-nil addedNodes")
	}
	if response.DeletedEndpoints == nil {
		t.Fatal("expected non-nil deletedEndpoints")
	}
	if response.NodeChangeReasons == nil {
		t.Fatal("expected non-nil nodeChangeReasons")
	}
}

func TestApplyResultToResponseJSONUsesEmptyArrays(t *testing.T) {
	response := ApplyResultToResponse(&clabcore.ApplyResult{
		AddedNodes: []string{"srl3"},
	})

	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	body := string(data)
	if strings.Contains(body, "null") {
		t.Fatalf("expected empty collections to marshal as arrays/maps, got %s", body)
	}

	for _, field := range []string{
		`"deletedNodes":[]`,
		`"recreatedNodes":[]`,
		`"startedNodes":[]`,
		`"addedLinks":[]`,
		`"deletedEndpoints":[]`,
		`"restartedNodes":[]`,
		`"nodeChangeReasons":{}`,
	} {
		if !strings.Contains(body, field) {
			t.Fatalf("expected marshaled response to contain %s, got %s", field, body)
		}
	}
}

func TestExecResultsToExecResponseKeepsOutputAsPrinted(t *testing.T) {
	outputs := []string{
		"plain text\n",
		"{\n  \"foo\": \"bar\"\n}\n",
		"[1, 2]\n",
		"42\n",
		"true\n",
		"\"quoted\"\n",
	}
	for _, stdout := range outputs {
		result := clabexec.NewExecResult(clabexec.NewExecCmdFromSlice([]string{"cmd", "arg"}))
		result.SetStdOut([]byte(stdout))
		result.SetStdErr([]byte("warning\n"))
		result.SetReturnCode(3)

		response := ExecResultsToExecResponse(ExecResults{"clab-lab-n1": {result}})

		want := models.ExecResponse{"clab-lab-n1": {{
			Cmd:        []string{"cmd", "arg"},
			ReturnCode: 3,
			Stdout:     stdout,
			Stderr:     "warning\n",
		}}}
		gotJSON, err := json.Marshal(response)
		if err != nil {
			t.Fatalf("marshal response: %v", err)
		}
		wantJSON, _ := json.Marshal(want)
		if string(gotJSON) != string(wantJSON) {
			t.Errorf("stdout %q: got %s, want %s", stdout, gotJSON, wantJSON)
		}
	}
}

func TestExecResultsToExecResponseKeepsCommandOrder(t *testing.T) {
	first := clabexec.NewExecResult(clabexec.NewExecCmdFromSlice([]string{"first"}))
	second := clabexec.NewExecResult(clabexec.NewExecCmdFromSlice([]string{"second"}))

	response := ExecResultsToExecResponse(ExecResults{"n1": {first, second}})

	if len(response["n1"]) != 2 || response["n1"][0].Cmd[0] != "first" || response["n1"][1].Cmd[0] != "second" {
		t.Fatalf("unexpected results: %+v", response["n1"])
	}
}
