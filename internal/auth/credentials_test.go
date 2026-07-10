package auth

import (
	"errors"
	"reflect"
	"testing"

	"github.com/srl-labs/clab-api-server/internal/config"
)

func setConfiguredAccessGroups(t *testing.T, apiGroup, superuserGroup string) {
	t.Helper()
	previousAPIGroup := config.AppConfig.APIUserGroup
	previousSuperuserGroup := config.AppConfig.SuperuserGroup
	config.AppConfig.APIUserGroup = apiGroup
	config.AppConfig.SuperuserGroup = superuserGroup
	t.Cleanup(func() {
		config.AppConfig.APIUserGroup = previousAPIGroup
		config.AppConfig.SuperuserGroup = previousSuperuserGroup
	})
}

func TestConfiguredLoginGroups(t *testing.T) {
	setConfiguredAccessGroups(t, " api-users ", "admins")

	if got, want := configuredLoginGroups(), []string{"api-users", "admins"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("configuredLoginGroups() = %#v, want %#v", got, want)
	}
}

func TestConfiguredLoginGroupsDeduplicates(t *testing.T) {
	setConfiguredAccessGroups(t, "clab", "clab")

	if got, want := configuredLoginGroups(), []string{"clab"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("configuredLoginGroups() = %#v, want %#v", got, want)
	}
}

func TestUserHasConfiguredLoginAccess(t *testing.T) {
	setConfiguredAccessGroups(t, "api-users", "admins")

	tests := []struct {
		name        string
		memberships map[string]bool
		want        bool
	}{
		{name: "api user", memberships: map[string]bool{"api-users": true}, want: true},
		{name: "superuser", memberships: map[string]bool{"admins": true}, want: true},
		{name: "unrelated user", memberships: map[string]bool{"other": true}, want: false},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := userHasConfiguredLoginAccess("alice", func(_ string, group string) (bool, error) {
				return testCase.memberships[group], nil
			})
			if err != nil {
				t.Fatalf("userHasConfiguredLoginAccess returned error: %v", err)
			}
			if got != testCase.want {
				t.Fatalf("userHasConfiguredLoginAccess = %t, want %t", got, testCase.want)
			}
		})
	}
}

func TestUserHasConfiguredLoginAccessFailsClosed(t *testing.T) {
	setConfiguredAccessGroups(t, "", "")

	called := false
	got, err := userHasConfiguredLoginAccess("alice", func(_, _ string) (bool, error) {
		called = true
		return true, nil
	})
	if err != nil {
		t.Fatalf("userHasConfiguredLoginAccess returned error: %v", err)
	}
	if got || called {
		t.Fatalf("expected empty group policy to deny without checking membership, got=%t called=%t", got, called)
	}
}

func TestUserHasConfiguredLoginAccessPropagatesGroupErrors(t *testing.T) {
	setConfiguredAccessGroups(t, "api-users", "admins")
	sentinel := errors.New("lookup failed")

	got, err := userHasConfiguredLoginAccess("alice", func(_, _ string) (bool, error) {
		return false, sentinel
	})
	if got || !errors.Is(err, sentinel) {
		t.Fatalf("got authorized=%t error=%v, want false and wrapped sentinel", got, err)
	}
}

func TestEnsureConfiguredAccessGroupUsesConfiguredPolicy(t *testing.T) {
	setConfiguredAccessGroups(t, "api-users", "admins")

	got, err := ensureConfiguredAccessGroup([]string{"docker"})
	if err != nil {
		t.Fatalf("ensureConfiguredAccessGroup returned error: %v", err)
	}
	if want := []string{"docker", "api-users"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ensureConfiguredAccessGroup() = %#v, want %#v", got, want)
	}

	got, err = ensureConfiguredAccessGroup([]string{"admins"})
	if err != nil {
		t.Fatalf("ensureConfiguredAccessGroup returned error: %v", err)
	}
	if want := []string{"admins"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ensureConfiguredAccessGroup() = %#v, want %#v", got, want)
	}
}

func TestEnsureConfiguredAccessGroupRequiresPolicy(t *testing.T) {
	setConfiguredAccessGroups(t, "", "")
	if _, err := ensureConfiguredAccessGroup([]string{"docker"}); err == nil {
		t.Fatal("ensureConfiguredAccessGroup accepted an empty access policy")
	}
}
