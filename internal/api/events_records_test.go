package api

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/kube"
)

// kubeScopedService is a service with the c9s scoper on a fake cluster, with the lab "lab1" of
// the current user provisioned from a topology file in the user's workspace.
func kubeScopedService(t *testing.T) (*clab.Service, *fake.Clientset, string, string, string) {
	t.Helper()
	previous := config.AppConfig
	t.Cleanup(func() { config.AppConfig = previous })
	config.AppConfig.ClabSharedLabsRoot = ""
	labsRoot := t.TempDir()
	setTestClabLabsRoot(t, labsRoot)
	current, err := user.Current()
	require.NoError(t, err)
	topology := filepath.Join(labsRoot, current.Username, "lab1", "lab1.clab.yml")
	require.NoError(t, os.MkdirAll(filepath.Dir(topology), 0o755))
	require.NoError(t, os.WriteFile(topology, []byte("name: lab1\n"), 0o644))

	client := fake.NewClientset()
	provisioner := kube.NewProvisioner(client, nil, kube.Settings{
		UserPrefix: "clab:", NamespaceTemplate: kube.DefaultNamespaceTemplate,
	})
	scoper := kube.NewScoper(provisioner, KubeUsers())
	scope, err := scoper.PrepareDeploy(context.Background(), current.Username, "lab1", topology)
	require.NoError(t, err)
	svc := clab.NewService()
	svc.SetLabScoper(scoper)
	return svc, client, current.Username, scope.Namespace, topology
}

func eventLine(t *testing.T, eventType string, attributes map[string]string) string {
	t.Helper()
	line, err := json.Marshal(map[string]any{
		"timestamp": "2026-10-27T12:00:00Z", "type": eventType, "action": "start",
		"actor_id": "ns/lab1/n1", "actor_name": "lab1-n1", "actor_full_id": "ns/lab1/n1",
		"attributes": attributes,
	})
	require.NoError(t, err)
	return string(line)
}

func TestEventsTakeOwnerAndTopologyFileFromTheServersRecords(t *testing.T) {
	svc, _, me, namespace, topology := kubeScopedService(t)
	verifier := newEventRecordVerifier(svc)
	ctx := context.Background()
	unrecorded := "k8s://" + namespace + "/topologies/lab1"

	container := func(owner, file string) map[string]string {
		return map[string]string{
			"containerlab": "lab1", "clab-node-name": "n1", "clab-owner": owner, "clab-topo-file": file,
			"image": "alpine", "state": "running", "namespace": namespace,
		}
	}
	verified := func(line string) map[string]any {
		t.Helper()
		got, ok := verifier.verify(ctx, line)
		require.True(t, ok)
		var event map[string]any
		require.NoError(t, json.Unmarshal([]byte(got), &event))
		return event
	}
	attributesOf := func(event map[string]any) map[string]any {
		return event["attributes"].(map[string]any)
	}

	// As deployed: the line passes unchanged.
	asDeployed := eventLine(t, "container", container(me, topology))
	got, ok := verifier.verify(ctx, asDeployed)
	require.True(t, ok)
	require.Equal(t, asDeployed, got)

	// The user edited the Topology's owner label and topology file annotation.
	for _, claimed := range [][2]string{
		{"mallory", "/etc/shadow"},
		{"mallory", topology},
		{me, "/etc/shadow"},
		{me, filepath.Join(filepath.Dir(topology), "..", "..", "..", "other", "x.clab.yml")},
	} {
		event := verified(eventLine(t, "container", container(claimed[0], claimed[1])))
		attributes := attributesOf(event)
		require.Equal(t, me, attributes["clab-owner"], "%v", claimed)
		want := topology
		if claimed[1] != topology {
			want = unrecorded
		}
		require.Equal(t, want, attributes["clab-topo-file"], "%v", claimed)
		require.Equal(t, "alpine", attributes["image"], "other attributes stay")
		require.Equal(t, "start", event["action"])
		require.Equal(t, "ns/lab1/n1", event["actor_id"])
		require.Equal(t, "2026-10-27T12:00:00Z", event["timestamp"])
	}

	// A snapshot without an owner label gets the namespace's owner, as inspect reports it.
	attributes := container("", topology)
	delete(attributes, "clab-owner")
	require.Equal(t, me, attributesOf(verified(eventLine(t, "container", attributes)))["clab-owner"])

	// A namespace the server did not provision keeps no topology file.
	foreign := container("someone", topology)
	foreign["namespace"] = "rogue"
	attributes2 := attributesOf(verified(eventLine(t, "container", foreign)))
	require.Equal(t, "k8s://rogue/topologies/lab1", attributes2["clab-topo-file"])
	require.Equal(t, "someone", attributes2["clab-owner"])

	// Events without these attributes, or not from a lab runtime, pass unchanged.
	for _, line := range []string{
		eventLine(t, "interface", map[string]string{"lab": "lab1", "ifname": "eth1", "state": "up", "namespace": namespace}),
		eventLine(t, "container", map[string]string{"containerlab": "lab1", "clab-owner": "x", "clab-topo-file": "/etc/shadow"}),
		"not json",
	} {
		got, ok := verifier.verify(ctx, line)
		require.True(t, ok)
		require.Equal(t, line, got)
	}
}

func TestEventsWithRecordsThatCannotBeCheckedAreLeftOut(t *testing.T) {
	svc, client, me, namespace, topology := kubeScopedService(t)
	client.PrependReactor("list", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("the API server is gone")
	})
	_, ok := newEventRecordVerifier(svc).verify(context.Background(), eventLine(t, "container", map[string]string{
		"containerlab": "lab1", "clab-owner": me, "clab-topo-file": topology, "namespace": namespace,
	}))
	require.False(t, ok, "an event whose owner and file cannot be checked is not streamed")
}
