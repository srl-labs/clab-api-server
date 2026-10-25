package clab

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	clabconst "github.com/srl-labs/containerlab/constants"
	clabruntime "github.com/srl-labs/containerlab/runtime"
)

func TestSummarizeSnapshotResults(t *testing.T) {
	results := []SnapshotNodeResult{
		{Node: "a", Status: SnapshotStatusSuccess},
		{Node: "b", Status: SnapshotStatusSuccess},
		{Node: "c", Status: SnapshotStatusFailed},
		{Node: "d", Status: SnapshotStatusSkipped},
	}
	if got := SummarizeSnapshotResults(results); got != "2 succeeded, 1 failed, 1 skipped" {
		t.Fatalf("summary = %q", got)
	}
	if got := SummarizeSnapshotResults(nil); got != "0 succeeded, 0 failed, 0 skipped" {
		t.Fatalf("empty summary = %q", got)
	}
}

func TestIsVrnetlabContainer(t *testing.T) {
	for image, want := range map[string]bool{
		"vrnetlab/nokia_sros:25.3.R1":              true,
		"ghcr.io/srl-labs/vrnetlab/vr-sros:1":      true,
		"registry.local:5000/vrnetlab/cisco_xrv9k": true,
		"ghcr.io/nokia/srlinux:latest":             false,
		"alpine":                                   false,
		"myvrnetlab/thing":                         false,
	} {
		if got := isVrnetlabContainer(clabruntime.GenericContainer{Image: image}); got != want {
			t.Errorf("isVrnetlabContainer(%q) = %v, want %v", image, got, want)
		}
	}
}

func TestSelectSnapshotContainers(t *testing.T) {
	containers := []clabruntime.GenericContainer{
		testContainer("clab-demo-r2", "demo", "r2", nil),
		testContainer("clab-demo-r1", "demo", "r1", nil),
		testContainer("clab-demo-r1-helper", "demo", "r1", map[string]string{clabconst.InternalNode: "true"}),
	}
	selected, missing := selectSnapshotContainers(containers, nil)
	if len(selected) != 2 || selected[0].Names[0] != "clab-demo-r1" || len(missing) != 0 {
		t.Fatalf("selected=%v missing=%v", selected, missing)
	}
	selected, missing = selectSnapshotContainers(containers, []string{"r2", "nope"})
	if len(selected) != 1 || selected[0].Names[0] != "clab-demo-r2" || !reflect.DeepEqual(missing, []string{"nope"}) {
		t.Fatalf("selected=%v missing=%v", selected, missing)
	}
}

func dockerFrame(stream byte, payload string) []byte {
	header := make([]byte, 8)
	header[0] = stream
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	return append(header, payload...)
}

func TestLogDemuxReader(t *testing.T) {
	var muxed bytes.Buffer
	muxed.Write(dockerFrame(1, "booting\nSnapshot sa"))
	muxed.Write(dockerFrame(2, "ved to /snapshot-output.tar\n"))
	out, err := io.ReadAll(newLogDemuxReader(&muxed))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "booting\nSnapshot saved to /snapshot-output.tar\n" {
		t.Fatalf("demuxed = %q", out)
	}

	plain := "plain log line\nSnapshot saved to /snapshot-output.tar\n"
	out, err = io.ReadAll(newLogDemuxReader(strings.NewReader(plain)))
	if err != nil || string(out) != plain {
		t.Fatalf("plain = %q, %v", out, err)
	}
}

func TestWaitForSnapshotLog(t *testing.T) {
	ctx := context.Background()

	var success bytes.Buffer
	success.Write(dockerFrame(1, "INFO starting\n"))
	success.Write(dockerFrame(1, "INFO Snapshot saved to /snapshot-output.tar\n"))
	if err := waitForSnapshotLog(ctx, io.NopCloser(&success)); err != nil {
		t.Fatalf("success case: %v", err)
	}

	failure := io.NopCloser(strings.NewReader("ERROR Snapshot save failed: disk full\n"))
	if err := waitForSnapshotLog(ctx, failure); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("failure case: %v", err)
	}

	closed := io.NopCloser(strings.NewReader("nothing useful\n"))
	if err := waitForSnapshotLog(ctx, closed); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed stream case: %v", err)
	}

	reader, writer := io.Pipe()
	defer func() { _ = writer.Close() }()
	timeoutCtx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if err := waitForSnapshotLog(timeoutCtx, reader); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout case: %v", err)
	}
}

func TestExtractSingleFile(t *testing.T) {
	build := func(entries ...*tar.Header) *bytes.Buffer {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, header := range entries {
			if err := tw.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if header.Typeflag == tar.TypeReg {
				if _, err := tw.Write([]byte(strings.Repeat("x", int(header.Size)))); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		return &buf
	}

	var out bytes.Buffer
	size, err := extractSingleFile(build(&tar.Header{Name: "snapshot-output.tar", Typeflag: tar.TypeReg, Size: 5, Mode: 0o644}), "snapshot-output.tar", &out)
	if err != nil || size != 5 || out.String() != "xxxxx" {
		t.Fatalf("regular file: size=%d out=%q err=%v", size, out.String(), err)
	}

	_, err = extractSingleFile(build(&tar.Header{Name: "snapshot-output.tar", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"}), "snapshot-output.tar", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("symlink entry: %v", err)
	}

	_, err = extractSingleFile(build(&tar.Header{Name: "other", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644}), "snapshot-output.tar", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing entry: %v", err)
	}
}
