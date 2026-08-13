package clab

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	gotc "github.com/florianl/go-tc"
	clabcore "github.com/srl-labs/containerlab/core"
	clabnodes "github.com/srl-labs/containerlab/nodes"
)

type fakeNodeConfigSaver struct {
	name   string
	err    error
	called bool
}

func (n *fakeNodeConfigSaver) GetShortName() string {
	return n.name
}

func (n *fakeNodeConfigSaver) SaveConfig(context.Context) (*clabnodes.SaveConfigResult, error) {
	n.called = true
	return nil, n.err
}

func TestResolveTopologySourceUsesContainerlabRendering(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatalf("get current user: %v", err)
	}

	t.Setenv("CLAB_API_SERVER_TEST_TOPOLOGY_NAME", "resolved-lab")
	topologyPath := filepath.Join(t.TempDir(), "test.clab.yml")
	topology := `name: ${CLAB_API_SERVER_TEST_TOPOLOGY_NAME}
topology:
  nodes:
    node1:
      kind: linux
      image: alpine:3
`
	if err := os.WriteFile(topologyPath, []byte(topology), 0600); err != nil {
		t.Fatalf("write topology: %v", err)
	}

	got, err := NewService().ResolveTopologySource(ResolveTopologySourceOptions{
		SourcePath: topologyPath,
		Username:   current.Username,
	})
	if err != nil {
		t.Fatalf("ResolveTopologySource error: %v", err)
	}
	if got.LabName != "resolved-lab" {
		t.Fatalf("resolved topology name = %q, want resolved-lab", got.LabName)
	}
	if got.TopologyPath != topologyPath {
		t.Fatalf("resolved topology path = %q, want %q", got.TopologyPath, topologyPath)
	}
}

func TestDeployClabOptionsForceAuthorizedLabName(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatalf("get current user: %v", err)
	}

	topologyPath := filepath.Join(t.TempDir(), "test.clab.yml")
	topology := `name: unchecked
topology:
  nodes:
    node1:
      kind: linux
      image: alpine:3
`
	if err := os.WriteFile(topologyPath, []byte(topology), 0600); err != nil {
		t.Fatalf("write topology: %v", err)
	}

	clab, err := newContainerLabForOwner(
		current.Username,
		deployClabOptions(topologyPath, "authorized", DeployOptions{})...,
	)
	if err != nil {
		t.Fatalf("create containerlab: %v", err)
	}
	if clab.Config.Name != "authorized" {
		t.Fatalf("containerlab topology name = %q, want authorized", clab.Config.Name)
	}
}

func TestDeployRequiresAuthorizedLabName(t *testing.T) {
	_, err := NewService().Deploy(context.Background(), DeployOptions{})
	if err == nil {
		t.Fatal("Deploy unexpectedly accepted an empty authorized lab name")
	}
	if !strings.Contains(err.Error(), "authorized lab name is required") {
		t.Fatalf("Deploy error = %q, want missing authorized lab name error", err)
	}
}

func TestNewContainerLabForOwnerSetsOwnerEnvDuringInit(t *testing.T) {
	restoreTestEnv := preserveEnv("SUDO_USER", "USER", "SUDO_UID", "SUDO_GID")
	defer restoreTestEnv()

	if err := os.Setenv("SUDO_USER", "root-sudo"); err != nil {
		t.Fatalf("set SUDO_USER: %v", err)
	}
	if err := os.Setenv("USER", "root-user"); err != nil {
		t.Fatalf("set USER: %v", err)
	}

	sentinelErr := errors.New("stop after env assertion")
	var gotSudoUser string
	var gotUser string
	_, err := newContainerLabForOwner("test", func(_ *clabcore.CLab) error {
		gotSudoUser = os.Getenv("SUDO_USER")
		gotUser = os.Getenv("USER")
		return sentinelErr
	})
	if !errors.Is(err, sentinelErr) {
		t.Fatalf("newContainerLabForOwner error = %v, want %v", err, sentinelErr)
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

func TestSaveNodeConfigsReturnsAllNodeErrors(t *testing.T) {
	leaf1 := &fakeNodeConfigSaver{name: "leaf1", err: errors.New("connection refused")}
	leaf2 := &fakeNodeConfigSaver{name: "leaf2", err: errors.New("authentication failed")}

	err := saveNodeConfigs(context.Background(), []nodeConfigSaver{leaf1, leaf2})
	if err == nil {
		t.Fatal("saveNodeConfigs unexpectedly returned nil")
	}
	for _, want := range []string{"leaf1", "connection refused", "leaf2", "authentication failed"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("saveNodeConfigs error = %q, want it to contain %q", err, want)
		}
	}
	if !leaf1.called || !leaf2.called {
		t.Fatalf("expected every node save to run, called leaf1=%t leaf2=%t", leaf1.called, leaf2.called)
	}
}

func TestSaveNodeConfigsReturnsNilWhenAllNodesSucceed(t *testing.T) {
	node := &fakeNodeConfigSaver{name: "leaf1"}
	if err := saveNodeConfigs(context.Background(), []nodeConfigSaver{node}); err != nil {
		t.Fatalf("saveNodeConfigs returned error: %v", err)
	}
	if !node.called {
		t.Fatal("expected node save to run")
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
