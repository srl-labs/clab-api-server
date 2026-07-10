package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/srl-labs/clab-api-server/internal/models"
)

const (
	uiConfigDirName       = "ui"
	customNodesFileName   = "custom-nodes.json"
	globalIconsDirName    = "icons"
	workspaceIconsDirName = ".clab-icons"
)

var (
	supportedIconExtensions = []string{".svg", ".png"}
	builtinIconNames        = map[string]struct{}{
		"pe":          {},
		"dcgw":        {},
		"leaf":        {},
		"switch":      {},
		"bridge":      {},
		"spine":       {},
		"super-spine": {},
		"server":      {},
		"pon":         {},
		"controller":  {},
		"rgw":         {},
		"ue":          {},
		"cloud":       {},
		"client":      {},
	}
	deprecatedSRLinuxTypeAliases = map[string]string{
		"ixsa1":    "ixs-a1",
		"ixrd1":    "ixr-d1",
		"ixrd2":    "ixr-d2",
		"ixrd3":    "ixr-d3",
		"ixrd2l":   "ixr-d2l",
		"ixrd3l":   "ixr-d3l",
		"ixrd4":    "ixr-d4",
		"ixrd5":    "ixr-d5",
		"ixrh2":    "ixr-h2",
		"ixrh3":    "ixr-h3",
		"ixrh4":    "ixr-h4",
		"ixrh432d": "ixr-h4-32d",
		"ixrh5":    "ixr-h5",
		"ixrh532d": "ixr-h5-32d",
		"ixrh564d": "ixr-h5-64d",
		"ixrh564o": "ixr-h5-64o",
		"ixr6":     "ixr-6",
		"ixr6e":    "ixr-6e",
		"ixr10":    "ixr-10",
		"ixr10e":   "ixr-10e",
		"ixr18e":   "ixr-18e",
		"sxr1x44s": "sxr-1x-44s",
		"sxr1d32d": "sxr-1d-32d",
		"ixrx1b":   "ixr-x1b",
		"ixrx3b":   "ixr-x3b",
	}
)

func defaultCustomNodes() []models.CustomNodeTemplate {
	return []models.CustomNodeTemplate{
		{
			"name":             "SRLinux Latest",
			"kind":             "nokia_srlinux",
			"type":             "ixr-d1",
			"image":            "ghcr.io/nokia/srlinux:latest",
			"icon":             "router",
			"baseName":         "srl",
			"interfacePattern": "e1-{n}",
			"setDefault":       true,
		},
		{
			"name":             "Network Multitool",
			"kind":             "linux",
			"image":            "ghcr.io/srl-labs/network-multitool:latest",
			"icon":             "client",
			"baseName":         "client",
			"interfacePattern": "eth{n}",
			"setDefault":       false,
		},
	}
}

func cloneCustomNodeTemplate(src models.CustomNodeTemplate) models.CustomNodeTemplate {
	dst := make(models.CustomNodeTemplate, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func cloneCustomNodes(nodes []models.CustomNodeTemplate) []models.CustomNodeTemplate {
	cloned := make([]models.CustomNodeTemplate, 0, len(nodes))
	for _, node := range nodes {
		cloned = append(cloned, cloneCustomNodeTemplate(node))
	}
	return cloned
}

func normalizeCustomNodes(nodes []models.CustomNodeTemplate) []models.CustomNodeTemplate {
	normalized := cloneCustomNodes(nodes)
	defaultSeen := false
	for _, node := range normalized {
		if customNodeString(node, "kind") == "nokia_srlinux" {
			if normalizedType, ok := deprecatedSRLinuxTypeAliases[customNodeString(node, "type")]; ok {
				node["type"] = normalizedType
			}
		}
		if customNodeBool(node, "setDefault") {
			if defaultSeen {
				node["setDefault"] = false
				continue
			}
			defaultSeen = true
		}
	}
	return normalized
}

func customNodesResponse(nodes []models.CustomNodeTemplate) models.CustomNodesResponse {
	normalized := normalizeCustomNodes(nodes)
	defaultNode := ""
	for _, node := range normalized {
		if customNodeBool(node, "setDefault") {
			defaultNode = customNodeString(node, "name")
			break
		}
	}
	return models.CustomNodesResponse{
		CustomNodes: normalized,
		DefaultNode: defaultNode,
	}
}

func customNodeString(node models.CustomNodeTemplate, key string) string {
	value, ok := node[key]
	if !ok {
		return ""
	}
	str, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(str)
}

func customNodeBool(node models.CustomNodeTemplate, key string) bool {
	value, ok := node[key]
	if !ok {
		return false
	}
	boolean, ok := value.(bool)
	return ok && boolean
}

func validateCustomNodeTemplate(node models.CustomNodeTemplate) error {
	name := customNodeString(node, "name")
	kind := customNodeString(node, "kind")
	if name == "" {
		return fmt.Errorf("custom node name is required")
	}
	if kind == "" {
		return fmt.Errorf("custom node kind is required")
	}
	return nil
}

func findCustomNodeIndexByName(nodes []models.CustomNodeTemplate, name string) int {
	for idx, node := range nodes {
		if customNodeString(node, "name") == name {
			return idx
		}
	}
	return -1
}

func parseUserIdentity(username string) (homeDir string, uid, gid int, err error) {
	usr, lookupErr := user.Lookup(username)
	if lookupErr != nil {
		return "", -1, -1, fmt.Errorf("could not determine user details: %w", lookupErr)
	}

	parsedUID, uidErr := strconv.Atoi(usr.Uid)
	if uidErr != nil {
		return "", -1, -1, fmt.Errorf("could not process user UID: %w", uidErr)
	}

	parsedGID, gidErr := strconv.Atoi(usr.Gid)
	if gidErr != nil {
		return "", -1, -1, fmt.Errorf("could not process user GID: %w", gidErr)
	}

	return usr.HomeDir, parsedUID, parsedGID, nil
}

func getUserClabDir(username string) (dir string, uid, gid int, err error) {
	homeDir, parsedUID, parsedGID, identityErr := parseUserIdentity(username)
	if identityErr != nil {
		return "", -1, -1, identityErr
	}
	return filepath.Join(homeDir, ".clab"), parsedUID, parsedGID, nil
}

func ensureOwnedDir(username, dir string, uid, gid int) error {
	rootedDir, err := resolveUserRootedFilePath(username, dir)
	if err != nil {
		return err
	}
	root, err := openWorkspaceRoot(rootedDir.rootPath)
	if os.IsNotExist(err) {
		if ensureErr := ensureWorkspaceRoot(rootedDir.rootPath, uid, gid); ensureErr != nil {
			return ensureErr
		}
		root, err = openWorkspaceRoot(rootedDir.rootPath)
	}
	if err != nil {
		return err
	}
	defer root.Close()
	return ensureTopologyRootDirectory(root, rootedDir.relativePath, uid, gid)
}

func writeOwnedFile(username, path string, body []byte, uid, gid int) error {
	if err := ensureOwnedDir(username, filepath.Dir(path), uid, gid); err != nil {
		return err
	}
	rootedPath, err := resolveUserRootedFilePath(username, path)
	if err != nil {
		return err
	}
	return writeRootedFile(rootedPath, body, false)
}

func getCustomNodesFilePath(username string) (string, int, int, error) {
	clabDir, uid, gid, err := getUserClabDir(username)
	if err != nil {
		return "", -1, -1, err
	}
	return filepath.Join(clabDir, uiConfigDirName, customNodesFileName), uid, gid, nil
}

func loadCustomNodes(username string) ([]models.CustomNodeTemplate, error) {
	path, _, _, err := getCustomNodesFilePath(username)
	if err != nil {
		return nil, err
	}

	rootedPath, rootErr := resolveUserRootedFilePath(username, path)
	if rootErr != nil {
		return nil, rootErr
	}
	body, readErr := readRootedFile(rootedPath)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return normalizeCustomNodes(defaultCustomNodes()), nil
		}
		return nil, fmt.Errorf("failed to read custom nodes: %w", readErr)
	}

	var nodes []models.CustomNodeTemplate
	if err := json.Unmarshal(body, &nodes); err != nil {
		return nil, fmt.Errorf("failed to parse custom nodes: %w", err)
	}
	for _, node := range nodes {
		if err := validateCustomNodeTemplate(node); err != nil {
			return nil, err
		}
	}
	return normalizeCustomNodes(nodes), nil
}

func saveCustomNodes(username string, nodes []models.CustomNodeTemplate) error {
	for _, node := range nodes {
		if err := validateCustomNodeTemplate(node); err != nil {
			return err
		}
	}

	path, uid, gid, err := getCustomNodesFilePath(username)
	if err != nil {
		return err
	}

	normalized := normalizeCustomNodes(nodes)
	body, marshalErr := json.MarshalIndent(normalized, "", "  ")
	if marshalErr != nil {
		return fmt.Errorf("failed to encode custom nodes: %w", marshalErr)
	}
	body = append(body, '\n')
	return writeOwnedFile(username, path, body, uid, gid)
}

func getGlobalIconsDir(username string) (string, int, int, error) {
	clabDir, uid, gid, err := getUserClabDir(username)
	if err != nil {
		return "", -1, -1, err
	}
	return filepath.Join(clabDir, globalIconsDirName), uid, gid, nil
}

func sanitizeIconName(filename string) string {
	ext := filepath.Ext(filename)
	baseName := strings.TrimSuffix(filepath.Base(filename), ext)
	result := strings.ToLower(baseName)
	var builder strings.Builder
	builder.Grow(len(result))
	lastHyphen := false
	for _, char := range result {
		switch {
		case char >= 'a' && char <= 'z':
			builder.WriteRune(char)
			lastHyphen = false
		case char >= '0' && char <= '9':
			builder.WriteRune(char)
			lastHyphen = false
		case char == '_' || char == '-':
			builder.WriteRune(char)
			lastHyphen = char == '-'
		default:
			if !lastHyphen {
				builder.WriteByte('-')
				lastHyphen = true
			}
		}
	}

	sanitized := strings.TrimLeft(builder.String(), "-")
	sanitized = strings.TrimRight(sanitized, "-")
	for strings.Contains(sanitized, "--") {
		sanitized = strings.ReplaceAll(sanitized, "--", "-")
	}
	return sanitized
}

func isSupportedIconExtension(ext string) bool {
	lower := strings.ToLower(ext)
	for _, candidate := range supportedIconExtensions {
		if lower == candidate {
			return true
		}
	}
	return false
}

func iconMimeType(ext string) string {
	if strings.EqualFold(ext, ".png") {
		return "image/png"
	}
	return "image/svg+xml"
}

func iconFormat(ext string) string {
	if strings.EqualFold(ext, ".png") {
		return "png"
	}
	return "svg"
}

func isBuiltInIconName(name string) bool {
	_, exists := builtinIconNames[name]
	return exists
}

func isValidIconName(name string) bool {
	if name == "" {
		return false
	}
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func openUserRootedDirectory(username, dir string) (*os.Root, string, error) {
	rootedDir, err := resolveUserRootedFilePath(username, dir)
	if err != nil {
		return nil, "", err
	}
	root, err := openWorkspaceRoot(rootedDir.rootPath)
	if err != nil {
		return nil, "", err
	}
	info, err := root.Lstat(rootedDir.relativePath)
	if err != nil {
		_ = root.Close()
		return nil, "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		_ = root.Close()
		return nil, "", fmt.Errorf("icon directory must not be a symbolic link")
	}
	return root, rootedDir.relativePath, nil
}

func listIconsFromDir(username, dir, source string) ([]models.CustomIconInfo, error) {
	root, rootedDir, err := openUserRootedDirectory(username, dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []models.CustomIconInfo{}, nil
		}
		return nil, err
	}
	defer root.Close()

	directory, err := root.Open(rootedDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []models.CustomIconInfo{}, nil
		}
		return nil, err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return nil, err
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	icons := make([]models.CustomIconInfo, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if !isSupportedIconExtension(ext) {
			continue
		}
		iconPath := filepath.Join(rootedDir, entry.Name())
		info, lstatErr := root.Lstat(iconPath)
		if lstatErr != nil {
			return nil, lstatErr
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			continue
		}
		body, readErr := root.ReadFile(iconPath)
		if readErr != nil {
			return nil, readErr
		}
		icons = append(icons, models.CustomIconInfo{
			Name:    strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name())),
			Source:  source,
			DataURI: fmt.Sprintf("data:%s;base64,%s", iconMimeType(ext), base64.StdEncoding.EncodeToString(body)),
			Format:  iconFormat(ext),
		})
	}

	return icons, nil
}

func iconNameExistsInDir(username, dir, iconName string) bool {
	root, rootedDir, err := openUserRootedDirectory(username, dir)
	if err != nil {
		return false
	}
	defer root.Close()
	for _, ext := range supportedIconExtensions {
		if info, err := root.Lstat(filepath.Join(rootedDir, iconName+ext)); err == nil && info.Mode().IsRegular() {
			return true
		}
	}
	return false
}

func uniqueIconName(username, dir, baseName string) string {
	name := baseName
	counter := 1
	for iconNameExistsInDir(username, dir, name) {
		name = fmt.Sprintf("%s-%d", baseName, counter)
		counter++
	}
	return name
}

func iconFilePathByName(username, dir, iconName string) (string, string, bool, error) {
	if !isValidIconName(iconName) {
		return "", "", false, nil
	}
	root, rootedDir, err := openUserRootedDirectory(username, dir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", false, nil
		}
		return "", "", false, err
	}
	defer root.Close()
	for _, ext := range supportedIconExtensions {
		path := filepath.Join(dir, iconName+ext)
		info, statErr := root.Lstat(filepath.Join(rootedDir, iconName+ext))
		if os.IsNotExist(statErr) {
			continue
		}
		if statErr != nil {
			return "", "", false, statErr
		}
		if info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() {
			return path, ext, true, nil
		}
	}
	return "", "", false, nil
}

func deleteIconByName(username, dir, iconName string) (bool, error) {
	if !isValidIconName(iconName) {
		return false, nil
	}
	root, rootedDir, err := openUserRootedDirectory(username, dir)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer root.Close()
	deleted := false
	for _, ext := range supportedIconExtensions {
		path := filepath.Join(rootedDir, iconName+ext)
		if err := root.Remove(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return deleted, err
		}
		deleted = true
	}
	return deleted, nil
}

func removeEmptyDir(username, dir string) {
	root, rootedDir, err := openUserRootedDirectory(username, dir)
	if err != nil {
		return
	}
	defer root.Close()
	directory, err := root.Open(rootedDir)
	if err != nil {
		return
	}
	entries, readErr := directory.ReadDir(1)
	_ = directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return
	}
	if len(entries) > 0 {
		return
	}
	_ = root.Remove(rootedDir)
}

func cleanWorkspaceIconsDir(username, dir string) error {
	root, rootedDir, err := openUserRootedDirectory(username, dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer root.Close()
	directory, err := root.Open(rootedDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	entries, err := directory.ReadDir(-1)
	_ = directory.Close()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !isSupportedIconExtension(filepath.Ext(entry.Name())) {
			continue
		}
		if err := root.Remove(filepath.Join(rootedDir, entry.Name())); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	_ = root.Remove(rootedDir)
	return nil
}

func workspaceIconsDir(username, labName string) (string, int, int, error) {
	labDir, uid, gid, err := getLabDirectoryInfo(username, labName)
	if err != nil {
		return "", -1, -1, err
	}
	return filepath.Join(labDir, workspaceIconsDirName), uid, gid, nil
}

func loadMergedLabIcons(username, labName string) ([]models.CustomIconInfo, error) {
	globalDir, _, _, err := getGlobalIconsDir(username)
	if err != nil {
		return nil, err
	}
	workspaceDir, _, _, workspaceErr := workspaceIconsDir(username, labName)
	if workspaceErr != nil {
		return nil, workspaceErr
	}

	globalIcons, globalErr := listIconsFromDir(username, globalDir, "global")
	if globalErr != nil {
		return nil, globalErr
	}
	workspaceIcons, workspaceListErr := listIconsFromDir(username, workspaceDir, "workspace")
	if workspaceListErr != nil {
		return nil, workspaceListErr
	}

	iconMap := make(map[string]models.CustomIconInfo, len(globalIcons)+len(workspaceIcons))
	for _, icon := range globalIcons {
		iconMap[icon.Name] = icon
	}
	for _, icon := range workspaceIcons {
		iconMap[icon.Name] = icon
	}

	names := make([]string, 0, len(iconMap))
	for name := range iconMap {
		names = append(names, name)
	}
	sort.Strings(names)

	merged := make([]models.CustomIconInfo, 0, len(names))
	for _, name := range names {
		merged = append(merged, iconMap[name])
	}
	return merged, nil
}

func reconcileLabIcons(username, labName string, usedIcons []string) error {
	workspaceDir, uid, gid, err := workspaceIconsDir(username, labName)
	if err != nil {
		return err
	}
	globalDir, _, _, globalErr := getGlobalIconsDir(username)
	if globalErr != nil {
		return globalErr
	}

	usedCustomIcons := make([]string, 0, len(usedIcons))
	usedSet := make(map[string]struct{}, len(usedIcons))
	for _, iconName := range usedIcons {
		name := strings.TrimSpace(iconName)
		if !isValidIconName(name) || isBuiltInIconName(name) {
			continue
		}
		if _, exists := usedSet[name]; exists {
			continue
		}
		usedSet[name] = struct{}{}
		usedCustomIcons = append(usedCustomIcons, name)
	}

	if len(usedCustomIcons) == 0 {
		return cleanWorkspaceIconsDir(username, workspaceDir)
	}

	if err := ensureOwnedDir(username, workspaceDir, uid, gid); err != nil {
		return err
	}

	for _, iconName := range usedCustomIcons {
		if iconNameExistsInDir(username, workspaceDir, iconName) {
			continue
		}
		sourcePath, ext, found, findErr := iconFilePathByName(username, globalDir, iconName)
		if findErr != nil {
			return findErr
		}
		if !found {
			continue
		}
		rootedSource, resolveErr := resolveUserRootedFilePath(username, sourcePath)
		if resolveErr != nil {
			return resolveErr
		}
		body, readErr := readRootedFile(rootedSource)
		if readErr != nil {
			return readErr
		}
		if err := writeOwnedFile(username, filepath.Join(workspaceDir, iconName+ext), body, uid, gid); err != nil {
			return err
		}
	}

	workspaceIcons, listErr := listIconsFromDir(username, workspaceDir, "workspace")
	if listErr != nil {
		return listErr
	}
	for _, icon := range workspaceIcons {
		if _, exists := usedSet[icon.Name]; exists {
			continue
		}
		if _, err := deleteIconByName(username, workspaceDir, icon.Name); err != nil {
			return err
		}
	}
	removeEmptyDir(username, workspaceDir)
	return nil
}
