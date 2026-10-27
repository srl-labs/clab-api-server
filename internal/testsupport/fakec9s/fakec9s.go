// Package fakec9s is an in-memory c9s lab runtime for tests. Install registers it under
// the "c9s" name containerlab's library initializes, so tests run the server's real code
// paths through containerlab's core without a Kubernetes cluster. Every call records the
// namespace and the identity it ran with.
package fakec9s

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	clabexec "github.com/srl-labs/containerlab/exec"
	clablabruntime "github.com/srl-labs/containerlab/labruntime"
	"gopkg.in/yaml.v3"
)

// Call is one runtime call the fake served.
type Call struct {
	Op        string
	Lab       string
	Namespace string
	Identity  clablabruntime.Identity
	Nodes     []string
	Cleanup   bool
	Command   []string
	Port      int
	// Deploy settings of a deploy call.
	Owner           string
	ExposeType      string
	ImagePullSecret string
	NoPersistence   bool
}

// Runtime is the shared state of every runtime instance containerlab creates.
type Runtime struct {
	mu    sync.Mutex
	labs  map[string]*clablabruntime.LabState // keyed by namespace/lab
	calls []Call
	// Configs are the configurations containerlab initialized the runtime with.
	configs []clablabruntime.Config

	// Logs is what StreamLogs writes for every node.
	Logs string
	// Stats is what SampleStats returns; StatsErr fails it instead.
	Stats    []clablabruntime.NodeStats
	StatsErr error
	// Resizes records the terminal sizes attach sessions received.
	resizes []clablabruntime.TerminalSize
	// Forbidden fails every call of these users with a Kubernetes-like forbidden error.
	Forbidden map[string]bool
	// ExposedPorts are reported for every node.
	ExposedPorts []clablabruntime.ExposedPort
	// PortHandler serves connections DialPort opens; nil echoes.
	PortHandler func(port int, conn net.Conn)
	// DeployErr fails every deploy; the lab state stays as it was.
	DeployErr error
	// CaptureIfaces are the capturable interfaces CaptureInterfaces reports per node; a node
	// without an entry has none.
	CaptureIfaces map[string][]clablabruntime.CaptureInterface
	// CaptureFunc serves Capture after the lab was found; nil writes nothing and returns.
	CaptureFunc func(ctx context.Context, req clablabruntime.CaptureRequest, w io.Writer) error
}

// Install registers the fake as the c9s lab runtime until the test ends.
func Install(t interface {
	Helper()
	Cleanup(func())
}) *Runtime {
	t.Helper()
	fake := &Runtime{labs: map[string]*clablabruntime.LabState{}}
	previous, hadPrevious := clablabruntime.LabRuntimes[clablabruntime.ClabernetesRuntimeName]
	clablabruntime.Register(clablabruntime.ClabernetesRuntimeName, func(cfg clablabruntime.Config) (clablabruntime.LabRuntime, error) {
		fake.mu.Lock()
		fake.configs = append(fake.configs, cfg)
		fake.mu.Unlock()
		return &instance{fake: fake, cfg: cfg}, nil
	})
	t.Cleanup(func() {
		if hadPrevious {
			clablabruntime.LabRuntimes[clablabruntime.ClabernetesRuntimeName] = previous
		} else {
			delete(clablabruntime.LabRuntimes, clablabruntime.ClabernetesRuntimeName)
		}
	})
	return fake
}

// Calls returns the recorded calls.
func (f *Runtime) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// CallsOf returns the recorded calls of one operation.
func (f *Runtime) CallsOf(op string) []Call {
	var calls []Call
	for _, call := range f.Calls() {
		if call.Op == op {
			calls = append(calls, call)
		}
	}
	return calls
}

// Resizes returns the terminal sizes attach sessions received.
func (f *Runtime) Resizes() []clablabruntime.TerminalSize {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.resizes)
}

// AddLab stores a deployed lab, as if containerlab had deployed it.
func (f *Runtime) AddLab(namespace, name, owner, topologyPath string, nodes ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state := &clablabruntime.LabState{
		Name: name, Namespace: namespace, Owner: owner, TopologyPath: topologyPath,
		State: "running", Ready: true,
	}
	for _, node := range nodes {
		state.Nodes = append(state.Nodes, f.nodeStateLocked(namespace, name, node))
	}
	f.labs[namespace+"/"+name] = state
}

// Lab returns a stored lab.
func (f *Runtime) Lab(namespace, name string) *clablabruntime.LabState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.labs[namespace+"/"+name]
}

func (f *Runtime) nodeStateLocked(namespace, lab, node string) clablabruntime.NodeState {
	return clablabruntime.NodeState{
		Name: node, Kind: "linux", Image: "alpine", State: "running", Ready: true,
		MgmtIPv4Address: "10.0.0.1/32",
		Pod:             lab + "-" + node + "-pod",
		Container:       "node-" + node,
		NodeUID:         "uid-" + namespace + "-" + node,
		ExposedPorts:    slices.Clone(f.ExposedPorts),
	}
}

// instance is one runtime containerlab created; it carries the configured namespace and
// identity.
type instance struct {
	fake *Runtime
	cfg  clablabruntime.Config
}

func (r *instance) namespace(requested, lab string) string {
	switch {
	case requested != "":
		return requested
	case r.cfg.Namespace != "":
		return r.cfg.Namespace
	default:
		return "c9s-" + lab
	}
}

func (r *instance) identity(requested clablabruntime.Identity) clablabruntime.Identity {
	if requested.IsZero() {
		return r.cfg.Identity
	}
	return requested
}

// record stores a call and fails it when its user is forbidden.
func (r *instance) record(call Call) error {
	r.fake.mu.Lock()
	defer r.fake.mu.Unlock()
	r.fake.calls = append(r.fake.calls, call)
	if r.fake.Forbidden[call.Identity.User] {
		return fmt.Errorf("%s is forbidden: User %q cannot access namespace %q", call.Op, call.Identity.User, call.Namespace)
	}
	return nil
}

func (r *instance) lab(namespace, name string) (*clablabruntime.LabState, error) {
	r.fake.mu.Lock()
	defer r.fake.mu.Unlock()
	state, ok := r.fake.labs[namespace+"/"+name]
	if !ok {
		return nil, fmt.Errorf("c9s lab %s/%s was not found", namespace, name)
	}
	copied := *state
	copied.Nodes = slices.Clone(state.Nodes)
	return &copied, nil
}

func topologyNodes(definition []byte) []string {
	var topology struct {
		Topology struct {
			Nodes map[string]any `yaml:"nodes"`
		} `yaml:"topology"`
	}
	_ = yaml.Unmarshal(definition, &topology)
	nodes := make([]string, 0, len(topology.Topology.Nodes))
	for node := range topology.Topology.Nodes {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	return nodes
}

func (r *instance) Deploy(_ context.Context, req clablabruntime.DeployRequest) (*clablabruntime.LabState, error) {
	namespace := r.namespace(req.Namespace, req.Name)
	if err := r.record(Call{Op: "deploy", Lab: req.Name, Namespace: namespace, Identity: r.identity(req.Identity),
		Owner: req.Owner, ExposeType: req.ExposeType, ImagePullSecret: req.ImagePullSecret, NoPersistence: req.NoPersistence}); err != nil {
		return nil, err
	}
	r.fake.mu.Lock()
	if err := r.fake.DeployErr; err != nil {
		r.fake.mu.Unlock()
		return nil, err
	}
	state := &clablabruntime.LabState{
		Name: req.Name, Namespace: namespace, Owner: req.Owner, TopologyPath: req.TopologyFile,
		State: "running", Ready: true,
	}
	for _, node := range topologyNodes(req.TopologyDefinition) {
		state.Nodes = append(state.Nodes, r.fake.nodeStateLocked(namespace, req.Name, node))
	}
	r.fake.labs[namespace+"/"+req.Name] = state
	r.fake.mu.Unlock()
	return r.lab(namespace, req.Name)
}

func (r *instance) Destroy(_ context.Context, req clablabruntime.DestroyRequest) error {
	namespace := r.namespace(req.Namespace, req.Name)
	if err := r.record(Call{Op: "destroy", Lab: req.Name, Namespace: namespace, Identity: r.identity(req.Identity), Cleanup: req.Cleanup}); err != nil {
		return err
	}
	r.fake.mu.Lock()
	delete(r.fake.labs, namespace+"/"+req.Name)
	r.fake.mu.Unlock()
	return nil
}

func (r *instance) Inspect(_ context.Context, req clablabruntime.InspectRequest) (*clablabruntime.LabState, error) {
	namespace := r.namespace(req.Namespace, req.Name)
	if err := r.record(Call{Op: "inspect", Lab: req.Name, Namespace: namespace, Identity: r.identity(req.Identity)}); err != nil {
		return nil, err
	}
	return r.lab(namespace, req.Name)
}

func (r *instance) LabExists(ctx context.Context, req clablabruntime.InspectRequest) (bool, error) {
	_, err := r.Inspect(ctx, req)
	return err == nil, nil
}

func (r *instance) List(_ context.Context, req clablabruntime.ListRequest) ([]*clablabruntime.LabState, error) {
	namespace := req.Namespace
	if namespace == "" {
		namespace = r.cfg.Namespace
	}
	if err := r.record(Call{Op: "list", Namespace: namespace, Identity: r.identity(req.Identity)}); err != nil {
		return nil, err
	}
	r.fake.mu.Lock()
	defer r.fake.mu.Unlock()
	keys := make([]string, 0, len(r.fake.labs))
	for key := range r.fake.labs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var states []*clablabruntime.LabState
	for _, key := range keys {
		state := r.fake.labs[key]
		if namespace != "" && state.Namespace != namespace {
			continue
		}
		copied := *state
		copied.Nodes = slices.Clone(state.Nodes)
		states = append(states, &copied)
	}
	return states, nil
}

func (r *instance) Exec(_ context.Context, req clablabruntime.ExecRequest) (*clabexec.ExecResult, error) {
	namespace := r.namespace(req.Namespace, req.Name)
	if err := r.record(Call{Op: "exec", Lab: req.Name, Namespace: namespace, Identity: r.identity(req.Identity),
		Nodes: []string{req.NodeName}, Command: req.Command}); err != nil {
		return nil, err
	}
	result := clabexec.NewExecResult(clabexec.NewExecCmdFromSlice(req.Command))
	result.SetStdOut([]byte("ran " + strings.Join(req.Command, " ") + " on " + req.NodeName))
	return result, nil
}

func (r *instance) lifecycle(op string, req clablabruntime.NodeRequest) error {
	namespace := r.namespace(req.Namespace, req.Name)
	if err := r.record(Call{Op: op, Lab: req.Name, Namespace: namespace, Identity: r.identity(req.Identity), Nodes: req.Nodes}); err != nil {
		return err
	}
	_, err := r.lab(namespace, req.Name)
	return err
}

func (r *instance) Start(_ context.Context, req clablabruntime.NodeRequest) error {
	return r.lifecycle("start", req)
}

func (r *instance) Stop(_ context.Context, req clablabruntime.NodeRequest) error {
	return r.lifecycle("stop", req)
}

func (r *instance) Restart(_ context.Context, req clablabruntime.NodeRequest) error {
	return r.lifecycle("restart", req)
}

func (r *instance) Save(_ context.Context, req clablabruntime.SaveRequest) (*clablabruntime.SaveResult, error) {
	namespace := r.namespace(req.Namespace, req.Name)
	if err := r.record(Call{Op: "save", Lab: req.Name, Namespace: namespace, Identity: r.identity(req.Identity), Nodes: req.Nodes}); err != nil {
		return nil, err
	}
	state, err := r.lab(namespace, req.Name)
	if err != nil {
		return nil, err
	}
	result := &clablabruntime.SaveResult{}
	if !req.Copy {
		return result, nil
	}
	for _, node := range state.Nodes {
		if len(req.Nodes) > 0 && !slices.Contains(req.Nodes, node.Name) {
			continue
		}
		result.Files = append(result.Files,
			clablabruntime.SavedFile{NodeName: node.Name, Name: "config-1.txt", Data: []byte("config of " + node.Name), Mode: 0o644},
			clablabruntime.SavedFile{NodeName: node.Name, Name: "config.txt", LinkTarget: "config-1.txt"})
	}
	return result, nil
}

func (r *instance) StreamEvents(ctx context.Context, req clablabruntime.EventStreamRequest) (<-chan clablabruntime.Event, <-chan error, error) {
	namespace := req.Namespace
	if namespace == "" {
		namespace = r.cfg.Namespace
	}
	if err := r.record(Call{Op: "events", Lab: req.Name, Namespace: namespace, Identity: r.identity(req.Identity)}); err != nil {
		return nil, nil, err
	}
	// One interface event per lab the stream covers, then nothing until the stream ends.
	r.fake.mu.Lock()
	var events []clablabruntime.Event
	keys := make([]string, 0, len(r.fake.labs))
	for key := range r.fake.labs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		state := r.fake.labs[key]
		if (namespace != "" && state.Namespace != namespace) || (req.Name != "" && state.Name != req.Name) {
			continue
		}
		events = append(events, clablabruntime.Event{
			Timestamp: time.Now(), Type: "interface", Action: "up",
			ActorID: state.Namespace + "/" + state.Name + "/n1", ActorName: state.Name + "-n1",
			Attributes: map[string]string{"lab": state.Name, "ifname": "eth1", "namespace": state.Namespace, "origin": "clabernetes"},
		})
	}
	r.fake.mu.Unlock()
	eventCh := make(chan clablabruntime.Event, len(events))
	for _, event := range events {
		eventCh <- event
	}
	errs := make(chan error)
	go func() {
		<-ctx.Done()
		close(eventCh)
		close(errs)
	}()
	return eventCh, errs, nil
}

func (r *instance) Validate(context.Context, clablabruntime.DeployRequest) error { return nil }

func (r *instance) Plan(_ context.Context, req clablabruntime.DeployRequest) (*clablabruntime.DeployPlan, error) {
	namespace := r.namespace(req.Namespace, req.Name)
	if err := r.record(Call{Op: "plan", Lab: req.Name, Namespace: namespace, Identity: r.identity(req.Identity)}); err != nil {
		return nil, err
	}
	plan := &clablabruntime.DeployPlan{LabName: req.Name, Namespace: namespace}
	for _, node := range topologyNodes(req.TopologyDefinition) {
		plan.Changes = append(plan.Changes, clablabruntime.ResourceChange{
			Action: clablabruntime.ChangeRecreate, Kind: "Node", Namespace: namespace, Name: node,
		})
	}
	return plan, nil
}

func (r *instance) LocateNode(_ context.Context, req clablabruntime.NodeRequest) ([]clablabruntime.NodeLocation, error) {
	namespace := r.namespace(req.Namespace, req.Name)
	if err := r.record(Call{Op: "locate", Lab: req.Name, Namespace: namespace, Identity: r.identity(req.Identity), Nodes: req.Nodes}); err != nil {
		return nil, err
	}
	state, err := r.lab(namespace, req.Name)
	if err != nil {
		return nil, err
	}
	var locations []clablabruntime.NodeLocation
	for _, node := range state.Nodes {
		if len(req.Nodes) > 0 && !slices.Contains(req.Nodes, node.Name) {
			continue
		}
		locations = append(locations, clablabruntime.NodeLocation{
			NodeName: node.Name, Namespace: namespace, Pod: node.Pod, Container: node.Container,
			NodeUID: node.NodeUID, ExposedPorts: node.ExposedPorts,
		})
	}
	return locations, nil
}

// Attach runs a tiny line-based shell: it echoes every input line as "echo: <line>", and
// "exit N" ends the session with exit code N.
func (r *instance) Attach(ctx context.Context, req clablabruntime.AttachRequest, streams clablabruntime.AttachStreams) error {
	namespace := r.namespace(req.Namespace, req.Name)
	if err := r.record(Call{Op: "attach", Lab: req.Name, Namespace: namespace, Identity: r.identity(req.Identity),
		Nodes: []string{req.NodeName}, Command: req.Command}); err != nil {
		return err
	}
	if _, err := r.lab(namespace, req.Name); err != nil {
		return err
	}
	if streams.Resize != nil {
		go func() {
			for size := range streams.Resize {
				r.fake.mu.Lock()
				r.fake.resizes = append(r.fake.resizes, size)
				r.fake.mu.Unlock()
			}
		}()
	}
	_, _ = fmt.Fprintf(streams.Stdout, "%s$ ", strings.Join(req.Command, " "))
	lines := make(chan string)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(streams.Stdin)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case line, open := <-lines:
			if !open {
				return nil
			}
			var code int
			if _, err := fmt.Sscanf(line, "exit %d", &code); err == nil {
				if code == 0 {
					return nil
				}
				return &clablabruntime.CommandExitError{Code: code}
			}
			_, _ = fmt.Fprintf(streams.Stdout, "echo: %s\r\n", line)
		}
	}
}

func (r *instance) StreamLogs(_ context.Context, req clablabruntime.LogRequest, w io.Writer) error {
	namespace := r.namespace(req.Namespace, req.Name)
	call := Call{Op: "logs", Lab: req.Name, Namespace: namespace, Identity: r.identity(req.Identity), Nodes: []string{req.NodeName}}
	if req.Tail != nil {
		call.Port = int(*req.Tail)
	}
	if err := r.record(call); err != nil {
		return err
	}
	if _, err := r.lab(namespace, req.Name); err != nil {
		return err
	}
	r.fake.mu.Lock()
	logs := r.fake.Logs
	r.fake.mu.Unlock()
	_, err := io.WriteString(w, logs)
	return err
}

func (r *instance) DialPort(_ context.Context, req clablabruntime.NodeRequest, port int) (net.Conn, error) {
	namespace := r.namespace(req.Namespace, req.Name)
	if err := r.record(Call{Op: "dial", Lab: req.Name, Namespace: namespace, Identity: r.identity(req.Identity), Nodes: req.Nodes, Port: port}); err != nil {
		return nil, err
	}
	if _, err := r.lab(namespace, req.Name); err != nil {
		return nil, err
	}
	client, server := net.Pipe()
	handler := r.fake.PortHandler
	if handler == nil {
		handler = func(_ int, conn net.Conn) {
			defer func() { _ = conn.Close() }()
			_, _ = io.Copy(conn, conn)
		}
	}
	go handler(port, server)
	return client, nil
}

func (r *instance) SampleStats(_ context.Context, req clablabruntime.InspectRequest) ([]clablabruntime.NodeStats, error) {
	namespace := r.namespace(req.Namespace, req.Name)
	if err := r.record(Call{Op: "stats", Lab: req.Name, Namespace: namespace, Identity: r.identity(req.Identity)}); err != nil {
		return nil, err
	}
	r.fake.mu.Lock()
	defer r.fake.mu.Unlock()
	if r.fake.StatsErr != nil {
		return nil, r.fake.StatsErr
	}
	return slices.Clone(r.fake.Stats), nil
}

// ErrMetricsUnavailable is the error SampleStats returns without a metrics API.
var ErrMetricsUnavailable = fmt.Errorf("%w: the server could not find the requested resource",
	clablabruntime.ErrMetricsUnavailable)

func (r *instance) CaptureInterfaces(_ context.Context, req clablabruntime.NodeRequest) ([]clablabruntime.CaptureInterface, error) {
	namespace := r.namespace(req.Namespace, req.Name)
	if err := r.record(Call{Op: "capture-interfaces", Lab: req.Name, Namespace: namespace, Identity: r.identity(req.Identity), Nodes: req.Nodes}); err != nil {
		return nil, err
	}
	state, err := r.lab(namespace, req.Name)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, node := range state.Nodes {
		known[node.Name] = true
	}
	nodes := req.Nodes
	if len(nodes) == 0 {
		for _, node := range state.Nodes {
			nodes = append(nodes, node.Name)
		}
	}
	r.fake.mu.Lock()
	defer r.fake.mu.Unlock()
	var result []clablabruntime.CaptureInterface
	for _, node := range nodes {
		if !known[node] {
			// the library's message for a node the lab does not have
			return nil, fmt.Errorf("node %q was not found in c9s lab %s/%s", node, namespace, req.Name)
		}
		result = append(result, r.fake.CaptureIfaces[node]...)
	}
	return result, nil
}

func (r *instance) Capture(ctx context.Context, req clablabruntime.CaptureRequest, w io.Writer) error {
	namespace := r.namespace(req.Namespace, req.Name)
	targets := make([]string, 0, len(req.Targets))
	for _, target := range req.Targets {
		targets = append(targets, target.Node+":"+target.Interface)
	}
	if err := r.record(Call{Op: "capture", Lab: req.Name, Namespace: namespace, Identity: r.identity(req.Identity), Nodes: targets}); err != nil {
		return err
	}
	if _, err := r.lab(namespace, req.Name); err != nil {
		return err
	}
	r.fake.mu.Lock()
	capture := r.fake.CaptureFunc
	r.fake.mu.Unlock()
	if capture == nil {
		return nil
	}
	return capture(ctx, req, w)
}
