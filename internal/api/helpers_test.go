package api

import "testing"

func TestIsValidNodeFilterAllowsDottedNodeNames(t *testing.T) {
	valid := []string{
		"",
		"node1",
		"node.1",
		"node.1,node.2",
		"srl-1,leaf_2,spine.a",
	}
	for _, filter := range valid {
		if !isValidNodeFilter(filter) {
			t.Errorf("isValidNodeFilter(%q) = false, want true", filter)
		}
	}

	invalid := []string{
		"node 1",
		"node;rm",
		"node/1",
		"node$(id)",
		"node1|node2",
	}
	for _, filter := range invalid {
		if isValidNodeFilter(filter) {
			t.Errorf("isValidNodeFilter(%q) = true, want false", filter)
		}
	}
}

func TestIsValidNodeNameAllowsDottedNodeNames(t *testing.T) {
	valid := []string{
		"node1",
		"node.1",
		"clab-my-lab-node.1",
		"leaf_2",
	}
	for _, name := range valid {
		if !isValidNodeName(name) {
			t.Errorf("isValidNodeName(%q) = false, want true", name)
		}
	}

	invalid := []string{
		"",
		"node.1,node.2",
		"node 1",
		"node/1",
		"node;rm",
	}
	for _, name := range invalid {
		if isValidNodeName(name) {
			t.Errorf("isValidNodeName(%q) = true, want false", name)
		}
	}
}
