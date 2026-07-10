package api

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

func rootedFilePathFromAbsolute(rootPath, absolutePath string, uid, gid int) (rootedFilePath, error) {
	cleanRoot := filepath.Clean(rootPath)
	cleanAbsolute := filepath.Clean(absolutePath)
	if !pathIsInsideRoot(cleanRoot, cleanAbsolute) || cleanRoot == cleanAbsolute {
		return rootedFilePath{}, fmt.Errorf("resolved path escapes allowed root")
	}
	relativePath, err := filepath.Rel(cleanRoot, cleanAbsolute)
	if err != nil || relativePath == "." || relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
		return rootedFilePath{}, fmt.Errorf("invalid file path")
	}
	return rootedFilePath{
		rootPath:     cleanRoot,
		relativePath: relativePath,
		uid:          uid,
		gid:          gid,
	}, nil
}

// resolveUserRootedFilePath confines an absolute path to storage owned by the
// authenticated Linux user. Managed workspace storage is preferred; the home
// directory fallback preserves access to labs deployed from elsewhere in the
// user's home without allowing the root service to follow paths across it.
func resolveUserRootedFilePath(username, absolutePath string) (rootedFilePath, error) {
	managedRoot, uid, gid, managedErr := getUserLabsBaseDirectoryInfo(username)
	if managedErr != nil {
		return rootedFilePath{}, managedErr
	}
	homeDir, homeUID, homeGID, homeErr := parseUserIdentity(username)
	if homeErr != nil {
		return rootedFilePath{}, homeErr
	}

	type candidate struct {
		root string
		uid  int
		gid  int
	}
	candidates := []candidate{{root: managedRoot, uid: uid, gid: gid}}
	if filepath.Clean(homeDir) != filepath.Clean(managedRoot) {
		candidates = append(candidates, candidate{root: homeDir, uid: homeUID, gid: homeGID})
	}
	for _, candidate := range candidates {
		if !pathIsInsideRoot(candidate.root, absolutePath) || filepath.Clean(candidate.root) == filepath.Clean(absolutePath) {
			continue
		}
		return rootedFilePathFromAbsolute(candidate.root, absolutePath, candidate.uid, candidate.gid)
	}

	return rootedFilePath{}, fmt.Errorf("path is outside the user's managed workspace and home directory")
}

func readRootedFile(path rootedFilePath) ([]byte, error) {
	root, err := openWorkspaceRoot(path.rootPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(path.relativePath)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("file path must reference a regular file without symbolic links")
	}
	return root.ReadFile(path.relativePath)
}

func statRootedFile(path rootedFilePath) (os.FileInfo, error) {
	root, err := openWorkspaceRoot(path.rootPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(path.relativePath)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("file path must reference a regular file without symbolic links")
	}
	return info, nil
}

func writeRootedFile(path rootedFilePath, body []byte, ensureRoot bool) error {
	if ensureRoot {
		if err := ensureWorkspaceRoot(path.rootPath, path.uid, path.gid); err != nil {
			return err
		}
	}

	root, err := openWorkspaceRoot(path.rootPath)
	if err != nil {
		return err
	}
	defer root.Close()

	parentPath := filepath.Dir(path.relativePath)
	if parentPath != "." {
		if err := ensureTopologyRootDirectory(root, parentPath, path.uid, path.gid); err != nil {
			return err
		}
	}
	if info, err := root.Lstat(path.relativePath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("file path must not be a symbolic link")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}

	file, err := root.OpenFile(path.relativePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Chown(path.uid, path.gid); err != nil {
		return err
	}
	if err := file.Chmod(0o640); err != nil {
		return err
	}
	_, err = file.Write(body)
	return err
}

func removeManagedLabDirectory(username, labName string) error {
	labDir, _, _, err := getLabDirectoryInfo(username, labName)
	if err != nil {
		return err
	}
	return removeManagedTopLevelDirectory(username, labDir)
}

func removeManagedTopLevelDirectory(username, absolutePath string) error {
	baseDir, _, _, err := getUserLabsBaseDirectoryInfo(username)
	if err != nil {
		return err
	}
	relativePath, err := filepath.Rel(baseDir, filepath.Clean(absolutePath))
	if err != nil || relativePath == "." || filepath.Dir(relativePath) != "." {
		return fmt.Errorf("managed directory must be a direct child of the user workspace")
	}
	root, err := openWorkspaceRoot(baseDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	return root.RemoveAll(relativePath)
}

func createManagedLabStagingDirectory(username, labName string) (absolutePath, entryName string, uid, gid int, err error) {
	labDir, uid, gid, err := getLabDirectoryInfo(username, labName)
	if err != nil {
		return "", "", -1, -1, err
	}
	baseDir := filepath.Dir(labDir)
	if err := ensureUserLabsBaseDirectory(baseDir, uid, gid); err != nil {
		return "", "", -1, -1, err
	}
	root, err := openWorkspaceRoot(baseDir)
	if err != nil {
		return "", "", -1, -1, err
	}
	defer root.Close()

	for range 10 {
		name, nameErr := randomManagedEntryName(managedArchiveEntryPrefix + labName + "-")
		if nameErr != nil {
			return "", "", -1, -1, nameErr
		}
		if mkdirErr := root.Mkdir(name, 0o750); os.IsExist(mkdirErr) {
			continue
		} else if mkdirErr != nil {
			return "", "", -1, -1, mkdirErr
		}
		dir, openErr := root.Open(name)
		if openErr != nil {
			_ = root.RemoveAll(name)
			return "", "", -1, -1, openErr
		}
		chownErr := dir.Chown(uid, gid)
		chmodErr := dir.Chmod(0o750)
		closeErr := dir.Close()
		if chownErr != nil || chmodErr != nil || closeErr != nil {
			_ = root.RemoveAll(name)
			return "", "", -1, -1, errors.Join(chownErr, chmodErr, closeErr)
		}
		return filepath.Join(baseDir, name), name, uid, gid, nil
	}
	return "", "", -1, -1, fmt.Errorf("could not allocate a staging directory")
}

func removeManagedLabStagingDirectory(username, labName, entryName string) error {
	if filepath.Base(entryName) != entryName || !strings.HasPrefix(entryName, managedArchiveEntryPrefix+labName+"-") {
		return fmt.Errorf("invalid managed staging entry")
	}
	baseDir, _, _, err := getUserLabsBaseDirectoryInfo(username)
	if err != nil {
		return err
	}
	root, err := openWorkspaceRoot(baseDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	return root.RemoveAll(entryName)
}

type managedLabDirectoryTransactionState uint8

const (
	managedLabDirectoryTransactionActive managedLabDirectoryTransactionState = iota
	managedLabDirectoryTransactionCommitted
	managedLabDirectoryTransactionRolledBack
)

// managedLabDirectoryTransaction keeps the previous workspace under a hidden,
// rooted backup name until the caller knows containerlab accepted the staged
// topology. Commit and Rollback are safe to call repeatedly.
type managedLabDirectoryTransaction struct {
	mu          sync.Mutex
	baseDir     string
	targetEntry string
	backupEntry string
	state       managedLabDirectoryTransactionState
}

func beginManagedLabDirectoryTransaction(username, labName, stagingEntry string) (*managedLabDirectoryTransaction, error) {
	if filepath.Base(stagingEntry) != stagingEntry || !strings.HasPrefix(stagingEntry, managedArchiveEntryPrefix+labName+"-") {
		return nil, fmt.Errorf("invalid managed staging entry")
	}
	labDir, _, _, err := getLabDirectoryInfo(username, labName)
	if err != nil {
		return nil, err
	}
	targetEntry := filepath.Base(labDir)
	baseDir := filepath.Dir(labDir)
	root, err := openWorkspaceRoot(baseDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	stagingInfo, err := root.Lstat(stagingEntry)
	if err != nil {
		return nil, err
	}
	if stagingInfo.Mode()&os.ModeSymlink != 0 || !stagingInfo.IsDir() {
		return nil, fmt.Errorf("managed staging entry is not a directory")
	}

	targetInfo, statErr := root.Lstat(targetEntry)
	targetExists := statErr == nil
	if statErr != nil && !os.IsNotExist(statErr) {
		return nil, statErr
	}
	if targetExists && targetInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("existing managed lab workspace must not be a symbolic link")
	}

	backupEntry := ""
	if targetExists {
		backupEntry, err = unusedManagedEntryName(root, managedArchiveBackupEntryPrefix+labName+"-")
		if err != nil {
			return nil, err
		}
		if err := root.Rename(targetEntry, backupEntry); err != nil {
			return nil, err
		}
	}

	if err := root.Rename(stagingEntry, targetEntry); err != nil {
		if backupEntry != "" {
			if rollbackErr := root.Rename(backupEntry, targetEntry); rollbackErr != nil {
				return nil, errors.Join(err, fmt.Errorf("failed to restore previous lab workspace: %w", rollbackErr))
			}
		}
		return nil, err
	}

	return &managedLabDirectoryTransaction{
		baseDir:     baseDir,
		targetEntry: targetEntry,
		backupEntry: backupEntry,
		state:       managedLabDirectoryTransactionActive,
	}, nil
}

func (tx *managedLabDirectoryTransaction) Commit() error {
	if tx == nil {
		return nil
	}
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.state == managedLabDirectoryTransactionRolledBack {
		return nil
	}
	// Mark committed before cleanup. A cleanup error must never make a later
	// deferred Rollback undo a deployment that already succeeded.
	tx.state = managedLabDirectoryTransactionCommitted
	if tx.backupEntry == "" {
		return nil
	}

	root, err := openWorkspaceRoot(tx.baseDir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.RemoveAll(tx.backupEntry); err != nil {
		return err
	}
	tx.backupEntry = ""
	return nil
}

func (tx *managedLabDirectoryTransaction) Rollback() error {
	if tx == nil {
		return nil
	}
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.state != managedLabDirectoryTransactionActive {
		return nil
	}

	root, err := openWorkspaceRoot(tx.baseDir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.RemoveAll(tx.targetEntry); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove failed lab workspace: %w", err)
	}
	if tx.backupEntry != "" {
		if err := root.Rename(tx.backupEntry, tx.targetEntry); err != nil {
			return fmt.Errorf("restore previous lab workspace: %w", err)
		}
		tx.backupEntry = ""
	}
	tx.state = managedLabDirectoryTransactionRolledBack
	return nil
}

func unusedManagedEntryName(root *os.Root, prefix string) (string, error) {
	for range 10 {
		name, err := randomManagedEntryName(prefix)
		if err != nil {
			return "", err
		}
		if _, err := root.Lstat(name); os.IsNotExist(err) {
			return name, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("could not allocate a managed entry name")
}

func randomManagedEntryName(prefix string) (string, error) {
	var randomBytes [12]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(randomBytes[:]), nil
}
