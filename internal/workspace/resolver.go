package workspace

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/srl-labs/clab-api-server/internal/config"
)

const LabsRootEnv = "CLAB_LABS_ROOT"

type UserStorage struct {
	Username string
	HomeDir  string
	BaseDir  string
	UID      int
	GID      int
}

// EnsureUserStorage creates the shared storage root, when configured, and the
// per-user workspace with the modes required by every API consumer. Ownership
// errors are returned: the API server is expected to run with the privileges
// needed to make the workspace usable by the authenticated Linux user.
func EnsureUserStorage(storage UserStorage) error {
	return EnsureUserBaseDirectory(storage.BaseDir, storage.UID, storage.GID)
}

// EnsureUserBaseDirectory applies the same directory layout semantics to API
// handlers that already resolved the user's base directory and ownership.
func EnsureUserBaseDirectory(baseDir string, uid, gid int) error {
	labsRoot, err := ConfiguredLabsRoot()
	if err != nil {
		return err
	}

	cleanBaseDir := filepath.Clean(baseDir)
	if labsRoot != "" {
		cleanLabsRoot := filepath.Clean(labsRoot)
		if cleanBaseDir == cleanLabsRoot || !pathIsInside(cleanLabsRoot, cleanBaseDir) {
			return fmt.Errorf("labs base directory escapes %s", LabsRootEnv)
		}
		labsDir, err := ensureDirectory(cleanLabsRoot, 0o755)
		if err != nil {
			return fmt.Errorf("ensure labs root: %w", err)
		}
		if err := labsDir.Close(); err != nil {
			return fmt.Errorf("close labs root: %w", err)
		}
	}

	userDir, err := ensureDirectory(cleanBaseDir, 0o750)
	if err != nil {
		return fmt.Errorf("ensure user labs directory: %w", err)
	}
	defer userDir.Close()
	if err := userDir.Chown(uid, gid); err != nil {
		return fmt.Errorf("set ownership on user labs directory: %w", err)
	}
	// Chown may clear special mode bits, so apply the intended mode last.
	if err := userDir.Chmod(0o750); err != nil {
		return fmt.Errorf("set permissions on user labs directory: %w", err)
	}
	return nil
}

func ensureDirectory(path string, mode os.FileMode) (*os.File, error) {
	if err := os.MkdirAll(path, mode); err != nil {
		return nil, err
	}
	dir, err := openDirectoryNoFollow(path)
	if err != nil {
		return nil, err
	}
	info, err := dir.Stat()
	if err != nil {
		dir.Close()
		return nil, err
	}
	if !info.IsDir() {
		dir.Close()
		return nil, fmt.Errorf("%s is not a directory", path)
	}
	if err := dir.Chmod(mode); err != nil {
		dir.Close()
		return nil, err
	}
	return dir, nil
}

func pathIsInside(rootPath, targetPath string) bool {
	relPath, err := filepath.Rel(rootPath, targetPath)
	if err != nil {
		return false
	}
	return relPath != "." && relPath != ".." && !strings.HasPrefix(relPath, ".."+string(filepath.Separator))
}

func ConfiguredLabsRoot() (string, error) {
	root := strings.TrimSpace(config.AppConfig.ClabLabsRoot)
	if root == "" {
		root = strings.TrimSpace(os.Getenv(LabsRootEnv))
	}
	if root == "" {
		return "", nil
	}
	if strings.HasPrefix(root, "~") {
		return "", fmt.Errorf("%s must be an absolute path; '~' is not supported", LabsRootEnv)
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("%s must be an absolute path", LabsRootEnv)
	}
	return filepath.Clean(root), nil
}

func ResolveUserStorage(username string) (UserStorage, error) {
	usr, err := user.Lookup(username)
	if err != nil {
		return UserStorage{}, fmt.Errorf("could not determine user details: %w", err)
	}
	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return UserStorage{}, fmt.Errorf("could not process user UID: %w", err)
	}
	gid, err := strconv.Atoi(usr.Gid)
	if err != nil {
		return UserStorage{}, fmt.Errorf("could not process user GID: %w", err)
	}

	labsRoot, err := ConfiguredLabsRoot()
	if err != nil {
		return UserStorage{}, err
	}
	baseDir := filepath.Join(usr.HomeDir, ".clab")
	if labsRoot != "" {
		baseDir = filepath.Join(labsRoot, usr.Username)
	}

	return UserStorage{
		Username: usr.Username,
		HomeDir:  usr.HomeDir,
		BaseDir:  filepath.Clean(baseDir),
		UID:      uid,
		GID:      gid,
	}, nil
}

func ResolveLabDirectory(username, labName string) (string, UserStorage, error) {
	storage, err := ResolveUserStorage(username)
	if err != nil {
		return "", UserStorage{}, err
	}

	cleanLabName := filepath.Clean(labName)
	if strings.TrimSpace(labName) == "" || cleanLabName == "." || cleanLabName == ".." ||
		filepath.IsAbs(cleanLabName) || cleanLabName != filepath.Base(cleanLabName) || strings.ContainsAny(labName, `/\`) {
		return "", UserStorage{}, fmt.Errorf("invalid lab name")
	}
	targetDir := filepath.Join(storage.BaseDir, cleanLabName)
	if !pathIsInside(storage.BaseDir, targetDir) {
		return "", UserStorage{}, fmt.Errorf("lab directory escapes user storage")
	}
	return targetDir, storage, nil
}
