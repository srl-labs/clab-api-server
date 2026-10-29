package kube

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	clablabruntime "github.com/srl-labs/containerlab/labruntime"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Defaults of the identity and namespace settings.
const (
	DefaultUserPrefix        = "clab:"
	DefaultNamespaceTemplate = "c9s-{user}-{lab}"
	// SharedNamespacePrefix names the namespaces of labs in the shared workspace.
	SharedNamespacePrefix = "c9s-shared-"
)

// Group names, after the user prefix.
const (
	usersGroup       = "users"
	adminsGroup      = "admins"
	sharedGroupStart = "shared-"
)

// UserName is the Kubernetes user a Linux user acts as.
func UserName(prefix, linuxUser string) string {
	return prefix + linuxUser
}

// UsersGroup is the group every API user is in.
func UsersGroup(prefix string) string { return prefix + usersGroup }

// AdminsGroup is the group of the users in SUPERUSER_GROUP.
func AdminsGroup(prefix string) string { return prefix + adminsGroup }

// SharedGroup is the group of the members of a Linux group that owns shared labs.
func SharedGroup(prefix, linuxGroup string) string {
	return prefix + sharedGroupStart + linuxGroup
}

// Identity is the Kubernetes identity of a Linux user: the prefixed user name, the users
// group, the admins group for superusers, and the shared group of every Linux group given.
func Identity(prefix, linuxUser string, superuser bool, sharedGroups ...string) clablabruntime.Identity {
	groups := []string{UsersGroup(prefix)}
	if superuser {
		groups = append(groups, AdminsGroup(prefix))
	}
	for _, group := range sharedGroups {
		if group != "" {
			groups = append(groups, SharedGroup(prefix, group))
		}
	}
	return clablabruntime.Identity{User: UserName(prefix, linuxUser), Groups: groups}
}

var nonNameChars = regexp.MustCompile(`[^a-z0-9-]+`)

// sanitizeName lowers a value to the characters a DNS label may hold.
func sanitizeName(value string) string {
	return strings.Trim(nonNameChars.ReplaceAllString(strings.ToLower(value), "-"), "-")
}

// nameHashLength is the length of the hash that keeps long names unique.
const nameHashLength = 10

// fitLabel returns name when it is a valid DNS label, and otherwise a valid label made of
// as much of the name as fits plus a hash of the unsanitized source.
func fitLabel(name, source string) string {
	name = strings.Trim(name, "-")
	if name != "" && (name[0] < 'a' || name[0] > 'z') {
		name = "n-" + name
	}
	if len(validation.IsDNS1123Label(name)) == 0 {
		return name
	}
	digest := sha256.Sum256([]byte(source))
	suffix := hex.EncodeToString(digest[:])[:nameHashLength]
	keep := validation.DNS1123LabelMaxLength - nameHashLength - 1
	if len(name) > keep {
		name = name[:keep]
	}
	name = strings.Trim(name, "-")
	if name == "" {
		return "n-" + suffix
	}
	return name + "-" + suffix
}

// NamespaceName renders the namespace of a user's lab from the template. User and lab are
// sanitized like containerlab sanitizes names; a result longer than a DNS label is cut and
// gets a hash of user and lab, so it stays unique.
func NamespaceName(template, user, lab string) string {
	name := strings.NewReplacer("{user}", sanitizeName(user), "{lab}", sanitizeName(lab)).Replace(template)
	return fitLabel(name, user+"\x00"+lab)
}

// NamespacePattern renders the namespace template for one user and leaves {lab} in, so
// clients can show where that user's labs go. A namespace too long for a DNS label is cut
// and gets a hash (see NamespaceName); the pattern does not show that.
func NamespacePattern(template, user string) string {
	return strings.ReplaceAll(template, "{user}", sanitizeName(user))
}

// SharedNamespacePattern is the namespace of a shared lab, with {lab} left in.
const SharedNamespacePattern = SharedNamespacePrefix + "{lab}"

// SharedNamespaceName is the namespace of a lab in the shared workspace.
func SharedNamespaceName(lab string) string {
	return fitLabel(SharedNamespacePrefix+sanitizeName(lab), "shared\x00"+lab)
}

// LabelValue returns value when Kubernetes accepts it as a label value, and otherwise a
// sanitized value with a hash, so it still selects exactly one user or lab.
func LabelValue(value string) string {
	if len(validation.IsValidLabelValue(value)) == 0 {
		return value
	}
	digest := sha256.Sum256([]byte(value))
	suffix := hex.EncodeToString(digest[:])[:nameHashLength]
	name := sanitizeName(value)
	if keep := validation.LabelValueMaxLength - nameHashLength - 1; len(name) > keep {
		name = strings.Trim(name[:keep], "-")
	}
	if name == "" {
		return suffix
	}
	return name + "-" + suffix
}
