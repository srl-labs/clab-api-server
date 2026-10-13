package terminal

import "testing"

func TestResolveSSHUsernameUsesKindDefaults(t *testing.T) {
	tests := map[string]string{
		"nokia_srlinux": "admin",
		"srl":           "admin",
		"cisco_xrd":     "clab",
		"juniper_crpd":  "root",
		"nokia_sros":    "admin",
		"cisco_xrv9k":   "clab",
		"arista_ceos":   "admin",
		"frr":           "admin",
		"frrouting":     "admin",
		"linux":         "admin",
		"unknown-kind":  "admin",
	}
	for kind, want := range tests {
		if got := resolveSSHUsername(kind, ""); got != want {
			t.Errorf("resolveSSHUsername(%q) = %q, want %q", kind, got, want)
		}
	}

	if got := resolveSSHUsername("nokia_srlinux", "operator"); got != "operator" {
		t.Errorf("explicit user = %q, want operator", got)
	}
}

func TestResolveShellCommandFRR(t *testing.T) {
	for _, kind := range []string{"frr", "frrouting"} {
		if got := resolveShellCommand(kind); len(got) != 1 || got[0] != "vtysh" {
			t.Errorf("resolveShellCommand(%q) = %v, want [vtysh]", kind, got)
		}
	}
}
