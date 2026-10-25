package clab

import (
	"encoding/json"
	"reflect"
	"testing"

	clabconst "github.com/srl-labs/containerlab/constants"
	clabruntime "github.com/srl-labs/containerlab/runtime"
)

func testContainer(name, lab, node string, extra map[string]string) clabruntime.GenericContainer {
	labels := map[string]string{
		clabconst.Containerlab: lab,
		clabconst.NodeName:     node,
	}
	for k, v := range extra {
		labels[k] = v
	}
	return clabruntime.GenericContainer{Names: []string{name}, Labels: labels, Image: "img"}
}

func TestExecListFiltersAlwaysRestrictToLab(t *testing.T) {
	filters := execListFilters("demo", []LabelFilter{
		{Key: "role", Value: "spine"},
		{Key: clabconst.Containerlab, Value: "other"},
	})
	last := filters[len(filters)-1]
	if last.Field != clabconst.Containerlab || last.Match != "demo" || last.Operator != "=" {
		t.Fatalf("last filter = %+v, want containerlab=demo", last)
	}
	if len(filters) != 3 {
		t.Fatalf("got %d filters, want 3", len(filters))
	}
}

func TestSelectExecContainers(t *testing.T) {
	containers := []clabruntime.GenericContainer{
		testContainer("clab-demo-spine1", "demo", "spine1", map[string]string{"role": "spine"}),
		testContainer("clab-demo-leaf1", "demo", "leaf1", map[string]string{"role": "leaf"}),
		testContainer("clab-demo-leaf2", "demo", "leaf2", map[string]string{"role": "leaf"}),
		testContainer("clab-other-leaf1", "other", "leaf1", map[string]string{"role": "leaf"}),
		testContainer("clab-demo-leaf1-netns", "demo", "leaf1", map[string]string{clabconst.InternalNode: "true", "role": "leaf"}),
	}
	names := func(selected []clabruntime.GenericContainer) []string {
		out := []string{}
		for _, c := range selected {
			out = append(out, c.Names[0])
		}
		return out
	}

	for _, tc := range []struct {
		name   string
		nodes  []string
		labels []LabelFilter
		want   []string
	}{
		{"labels", nil, []LabelFilter{{"role", "leaf"}}, []string{"clab-demo-leaf1", "clab-demo-leaf2"}},
		{"nodes", []string{"spine1", "leaf2"}, nil, []string{"clab-demo-leaf2", "clab-demo-spine1"}},
		{"nodes and labels", []string{"spine1", "leaf2"}, []LabelFilter{{"role", "leaf"}}, []string{"clab-demo-leaf2"}},
		{"no match", []string{"spine1"}, []LabelFilter{{"role", "leaf"}}, []string{}},
		{"other lab label ignored", nil, []LabelFilter{{clabconst.Containerlab, "other"}}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := names(selectExecContainers(containers, "demo", tc.nodes, tc.labels))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("selected %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMissingNodeNames(t *testing.T) {
	containers := []clabruntime.GenericContainer{
		testContainer("clab-demo-a", "demo", "a", nil),
		testContainer("clab-demo-b", "demo", "b", nil),
	}
	got := missingNodeNames(containers, []string{"a", "x", "b", "x", "y"})
	if !reflect.DeepEqual(got, []string{"x", "y"}) {
		t.Fatalf("missingNodeNames = %v", got)
	}
	if got := missingNodeNames(containers, nil); got != nil {
		t.Fatalf("missingNodeNames(nil) = %v", got)
	}
}

func TestGroupContainerDetails(t *testing.T) {
	containers := []clabruntime.GenericContainer{
		testContainer("clab-demo-b", "demo", "b", nil),
		testContainer("clab-demo-a", "demo", "a", nil),
	}
	grouped := groupContainerDetails(containers)
	if len(grouped) != 1 || len(grouped["demo"]) != 2 {
		t.Fatalf("grouped = %+v", grouped)
	}
	if grouped["demo"][0].Names[0] != "clab-demo-a" {
		t.Fatalf("containers not sorted: %v", grouped["demo"][0].Names)
	}
	if containers[0].Names[0] != "clab-demo-b" {
		t.Fatal("input slice was reordered")
	}
	raw, err := json.Marshal(grouped)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string][]map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["demo"][0]["Runtime"] != nil {
		t.Fatalf("runtime handle leaked into details: %v", decoded["demo"][0]["Runtime"])
	}
	if _, ok := decoded["demo"][0]["Labels"]; !ok {
		t.Fatalf("details are missing container fields: %v", decoded["demo"][0])
	}
}
