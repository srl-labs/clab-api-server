package kube

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	clablabruntime "github.com/srl-labs/containerlab/labruntime"

	"github.com/srl-labs/clab-api-server/internal/clab"
)

// ErrAmbiguousLab reports a lab name that several users' labs carry, for a superuser who
// owns none of them.
var ErrAmbiguousLab = errors.New("several users have a lab with this name")

// Users answers questions about Linux users.
type Users interface {
	// IsSuperuser reports whether the user is in SUPERUSER_GROUP.
	IsSuperuser(user string) bool
	// InGroup reports whether the user is in a Linux group.
	InGroup(user, group string) bool
	// SharedGroup returns the Linux group that owns a topology in the shared workspace,
	// and whether the topology is in it.
	SharedGroup(topoPath string) (string, bool)
}

// Scoper makes Kubernetes RBAC the authority over labs on c9s: every lab gets its own
// namespace, provisioned with the server's identity, and every lab call acts as the
// signed-in user (clab:<user>) through impersonation.
type Scoper struct {
	provisioner *Provisioner
	users       Users
}

// NewScoper returns the scoper of a provisioner.
func NewScoper(provisioner *Provisioner, users Users) *Scoper {
	return &Scoper{provisioner: provisioner, users: users}
}

var _ clab.LabScoper = (*Scoper)(nil)

func (s *Scoper) prefix() string { return s.provisioner.settings.UserPrefix }

// identity is the user's identity for a lab namespace: with the shared lab's group when the
// user is a member.
func (s *Scoper) identity(user string, namespace LabNamespace) clablabruntime.Identity {
	var groups []string
	if namespace.SharedGroup != "" && s.users.InGroup(user, namespace.SharedGroup) {
		groups = append(groups, namespace.SharedGroup)
	}
	return Identity(s.prefix(), user, s.users.IsSuperuser(user), groups...)
}

func (s *Scoper) scope(user string, namespace LabNamespace) clab.LabScope {
	return clab.LabScope{
		LabName:   namespace.Lab,
		Namespace: namespace.Name,
		Owner:     namespace.Owner,
		Identity:  s.identity(user, namespace),
	}
}

// findLab picks the user's namespace of a lab name: the user's own lab first, then a shared
// lab of one of the user's groups, then, for a superuser, the only lab of that name.
func (s *Scoper) findLab(ctx context.Context, user, lab string) (LabNamespace, bool, error) {
	namespaces, err := s.provisioner.FindLab(ctx, lab)
	if err != nil {
		return LabNamespace{}, false, err
	}
	var own, shared, others []LabNamespace
	for _, namespace := range namespaces {
		if namespace.Lab != lab {
			continue
		}
		switch {
		case namespace.SharedGroup != "":
			if s.users.InGroup(user, namespace.SharedGroup) {
				shared = append(shared, namespace)
			} else {
				others = append(others, namespace)
			}
		case namespace.Owner == user:
			own = append(own, namespace)
		default:
			others = append(others, namespace)
		}
	}
	switch {
	case len(own) > 0:
		return own[0], true, nil
	case len(shared) > 0:
		return shared[0], true, nil
	case len(others) == 0 || !s.users.IsSuperuser(user):
		return LabNamespace{}, false, nil
	case len(others) == 1:
		return others[0], true, nil
	default:
		owners := make([]string, 0, len(others))
		for _, namespace := range others {
			owners = append(owners, namespace.Owner)
		}
		return LabNamespace{}, false, fmt.Errorf("%w: lab %q of %s", ErrAmbiguousLab, lab, strings.Join(owners, ", "))
	}
}

// ScopeForLab returns the namespace of an existing lab the user can reach, acting as the
// user. Kubernetes decides what the user may do there.
func (s *Scoper) ScopeForLab(ctx context.Context, user, lab string) (clab.LabScope, error) {
	namespace, found, err := s.findLab(ctx, user, lab)
	if err != nil {
		return clab.LabScope{}, err
	}
	if !found {
		return clab.LabScope{}, fmt.Errorf("%w: %s", clab.ErrLabNotFound, lab)
	}
	return s.scope(user, namespace), nil
}

// PrepareDeploy provisions the lab's namespace before containerlab deploys into it as the
// user. A lab in the shared workspace gets the shared namespace, bound to the group that
// owns the topology; a lab the user can already reach is deployed where it is.
func (s *Scoper) PrepareDeploy(ctx context.Context, user, lab, topoPath string) (clab.LabScope, error) {
	target := LabNamespace{Owner: user, Lab: lab}
	if group, shared := s.users.SharedGroup(topoPath); shared {
		if group == "" {
			return clab.LabScope{}, fmt.Errorf("the shared topology %s has no owning group", topoPath)
		}
		if !s.users.InGroup(user, group) && !s.users.IsSuperuser(user) {
			return clab.LabScope{}, fmt.Errorf("user %q is not in group %q, which owns the shared lab %q", user, group, lab)
		}
		target.SharedGroup = group
	} else if existing, found, err := s.findLab(ctx, user, lab); err != nil {
		return clab.LabScope{}, err
	} else if found {
		target = existing
	}

	namespace, err := s.provisioner.EnsureLabNamespace(ctx, target)
	if err != nil {
		return clab.LabScope{}, err
	}
	return s.scope(user, namespace), nil
}

// ListScopes returns the namespaces of the user's labs and of the shared labs of the user's
// groups. A superuser lists every namespace at once, as clab:admins.
func (s *Scoper) ListScopes(ctx context.Context, user string) ([]clab.LabScope, error) {
	if s.users.IsSuperuser(user) {
		return []clab.LabScope{{Owner: user, Identity: Identity(s.prefix(), user, true)}}, nil
	}
	own, err := s.provisioner.OwnedBy(ctx, user)
	if err != nil {
		return nil, err
	}
	scopes := make([]clab.LabScope, 0, len(own))
	for _, namespace := range own {
		scopes = append(scopes, s.scope(user, namespace))
	}

	all, err := s.provisioner.listNamespaces(ctx, nil)
	if err != nil {
		return nil, err
	}
	var groups []string
	for _, namespace := range all {
		if namespace.SharedGroup != "" && !slices.Contains(groups, namespace.SharedGroup) {
			groups = append(groups, namespace.SharedGroup)
		}
	}
	for _, group := range groups {
		if !s.users.InGroup(user, group) {
			continue
		}
		shared, err := s.provisioner.SharedWith(ctx, group)
		if err != nil {
			return nil, err
		}
		for _, namespace := range shared {
			scopes = append(scopes, s.scope(user, namespace))
		}
	}
	return scopes, nil
}

// AfterDestroy deletes the lab's namespace when nothing of the lab is left in it.
func (s *Scoper) AfterDestroy(ctx context.Context, scope clab.LabScope, cleanup bool) error {
	if scope.Namespace == "" {
		return nil
	}
	_, err := s.provisioner.ReleaseLabNamespace(ctx, scope.Namespace, scope.Identity, cleanup)
	return err
}
