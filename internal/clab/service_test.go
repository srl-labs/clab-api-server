package clab

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"testing"
	"time"

	gotc "github.com/florianl/go-tc"
)

func TestContainerlabProcessStateSerializesAndRestores(t *testing.T) {
	restoreTestEnv := preserveEnv("SUDO_USER", "USER", "SUDO_UID", "SUDO_GID")
	defer restoreTestEnv()

	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get original cwd: %v", err)
	}
	if err := os.Setenv("SUDO_USER", "original-sudo"); err != nil {
		t.Fatalf("set original SUDO_USER: %v", err)
	}
	if err := os.Setenv("USER", "original-user"); err != nil {
		t.Fatalf("set original USER: %v", err)
	}

	firstDir := t.TempDir()
	secondDir := t.TempDir()
	firstEntered := make(chan struct{})
	secondEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	errorsCh := make(chan error, 2)

	go func() {
		errorsCh <- withContainerlabProcessState(firstDir, "first-owner", func() error {
			cwd, cwdErr := os.Getwd()
			if cwdErr != nil {
				return cwdErr
			}
			if cwd != firstDir || os.Getenv("SUDO_USER") != "first-owner" || os.Getenv("USER") != "first-owner" {
				return fmt.Errorf("unexpected first process state cwd=%q sudo=%q user=%q", cwd, os.Getenv("SUDO_USER"), os.Getenv("USER"))
			}
			close(firstEntered)
			<-releaseFirst
			return nil
		})
	}()

	<-firstEntered
	go func() {
		errorsCh <- withContainerlabProcessState(secondDir, "second-owner", func() error {
			cwd, cwdErr := os.Getwd()
			if cwdErr != nil {
				return cwdErr
			}
			if cwd != secondDir || os.Getenv("SUDO_USER") != "second-owner" || os.Getenv("USER") != "second-owner" {
				return fmt.Errorf("unexpected second process state cwd=%q sudo=%q user=%q", cwd, os.Getenv("SUDO_USER"), os.Getenv("USER"))
			}
			close(secondEntered)
			return nil
		})
	}()

	select {
	case <-secondEntered:
		t.Fatal("second process-state operation entered before the first was released")
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseFirst)
	select {
	case <-secondEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("second process-state operation did not enter after the first was released")
	}

	for range 2 {
		if err := <-errorsCh; err != nil {
			t.Fatalf("process-state operation failed: %v", err)
		}
	}

	if cwd, err := os.Getwd(); err != nil || cwd != originalDir {
		t.Fatalf("restored cwd = %q, %v; want %q", cwd, err, originalDir)
	}
	if got := os.Getenv("SUDO_USER"); got != "original-sudo" {
		t.Fatalf("restored SUDO_USER = %q, want original-sudo", got)
	}
	if got := os.Getenv("USER"); got != "original-user" {
		t.Fatalf("restored USER = %q, want original-user", got)
	}
}

func TestContainerlabProcessStateSetsOwnerEnv(t *testing.T) {
	restoreTestEnv := preserveEnv("SUDO_USER", "USER", "SUDO_UID", "SUDO_GID")
	defer restoreTestEnv()

	if err := os.Setenv("SUDO_USER", "root-sudo"); err != nil {
		t.Fatalf("set SUDO_USER: %v", err)
	}
	if err := os.Setenv("USER", "root-user"); err != nil {
		t.Fatalf("set USER: %v", err)
	}

	var gotSudoUser string
	var gotUser string
	err := withContainerlabProcessState("", "test", func() error {
		gotSudoUser = os.Getenv("SUDO_USER")
		gotUser = os.Getenv("USER")
		return nil
	})
	if err != nil {
		t.Fatalf("withContainerlabProcessState error = %v", err)
	}
	if gotSudoUser != "test" {
		t.Fatalf("SUDO_USER during init = %q, want %q", gotSudoUser, "test")
	}
	if gotUser != "test" {
		t.Fatalf("USER during init = %q, want %q", gotUser, "test")
	}
	if got := os.Getenv("SUDO_USER"); got != "root-sudo" {
		t.Fatalf("restored SUDO_USER = %q, want %q", got, "root-sudo")
	}
	if got := os.Getenv("USER"); got != "root-user" {
		t.Fatalf("restored USER = %q, want %q", got, "root-user")
	}
}

func TestSetProcessOwnerEnvRestoresExistingValues(t *testing.T) {
	restoreTestEnv := preserveEnv("SUDO_USER", "USER", "SUDO_UID", "SUDO_GID")
	defer restoreTestEnv()

	if err := os.Setenv("SUDO_USER", "root-sudo"); err != nil {
		t.Fatalf("set SUDO_USER: %v", err)
	}
	if err := os.Setenv("USER", "root-user"); err != nil {
		t.Fatalf("set USER: %v", err)
	}

	restoreOwnerEnv := setProcessOwnerEnv("test")
	if got := os.Getenv("SUDO_USER"); got != "test" {
		t.Fatalf("SUDO_USER = %q, want %q", got, "test")
	}
	if got := os.Getenv("USER"); got != "test" {
		t.Fatalf("USER = %q, want %q", got, "test")
	}

	restoreOwnerEnv()
	if got := os.Getenv("SUDO_USER"); got != "root-sudo" {
		t.Fatalf("restored SUDO_USER = %q, want %q", got, "root-sudo")
	}
	if got := os.Getenv("USER"); got != "root-user" {
		t.Fatalf("restored USER = %q, want %q", got, "root-user")
	}
}

func TestSetProcessOwnerEnvRestoresUnsetValues(t *testing.T) {
	restoreTestEnv := preserveEnv("SUDO_USER", "USER", "SUDO_UID", "SUDO_GID")
	defer restoreTestEnv()

	_ = os.Unsetenv("SUDO_USER")
	_ = os.Unsetenv("USER")

	restoreOwnerEnv := setProcessOwnerEnv("test")
	if got := os.Getenv("SUDO_USER"); got != "test" {
		t.Fatalf("SUDO_USER = %q, want %q", got, "test")
	}
	if got := os.Getenv("USER"); got != "test" {
		t.Fatalf("USER = %q, want %q", got, "test")
	}

	restoreOwnerEnv()
	if _, ok := os.LookupEnv("SUDO_USER"); ok {
		t.Fatalf("SUDO_USER remained set after restore")
	}
	if _, ok := os.LookupEnv("USER"); ok {
		t.Fatalf("USER remained set after restore")
	}
}

func TestSetProcessOwnerEnvSetsSudoIDsForExistingUser(t *testing.T) {
	restoreTestEnv := preserveEnv("SUDO_USER", "USER", "SUDO_UID", "SUDO_GID")
	defer restoreTestEnv()

	current, err := user.Current()
	if err != nil {
		t.Fatalf("get current user: %v", err)
	}

	restoreOwnerEnv := setProcessOwnerEnv(current.Username)
	defer restoreOwnerEnv()

	if got := os.Getenv("SUDO_UID"); got != current.Uid {
		t.Fatalf("SUDO_UID = %q, want %q", got, current.Uid)
	}
	if got := os.Getenv("SUDO_GID"); got != current.Gid {
		t.Fatalf("SUDO_GID = %q, want %q", got, current.Gid)
	}
}

func TestHasNetemQdisc(t *testing.T) {
	qdiscs := []gotc.Object{
		{Msg: gotc.Msg{Ifindex: 10}, Attribute: gotc.Attribute{Kind: "fq_codel"}},
		{Msg: gotc.Msg{Ifindex: 11}, Attribute: gotc.Attribute{Kind: "netem"}},
	}

	if !hasNetemQdisc(qdiscs, 11) {
		t.Fatalf("expected netem qdisc on interface index 11")
	}
	if hasNetemQdisc(qdiscs, 10) {
		t.Fatalf("did not expect non-netem qdisc on interface index 10 to match")
	}
	if hasNetemQdisc(qdiscs, 12) {
		t.Fatalf("did not expect missing interface index to match")
	}
}

func TestIsNetemAlreadyClearError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "invalid argument", err: errors.New("netlink receive: invalid argument"), want: true},
		{name: "not found", err: errors.New("could not find qdisc for interface eth1"), want: true},
		{name: "other", err: errors.New("permission denied"), want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNetemAlreadyClearError(tc.err); got != tc.want {
				t.Fatalf("isNetemAlreadyClearError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func preserveEnv(keys ...string) func() {
	type envValue struct {
		value string
		set   bool
	}

	values := make(map[string]envValue, len(keys))
	for _, key := range keys {
		value, set := os.LookupEnv(key)
		values[key] = envValue{value: value, set: set}
	}

	return func() {
		for key, value := range values {
			if value.set {
				_ = os.Setenv(key, value.value)
			} else {
				_ = os.Unsetenv(key)
			}
		}
	}
}
