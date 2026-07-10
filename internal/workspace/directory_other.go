//go:build !linux

package workspace

import (
	"fmt"
	"os"
)

func openDirectoryNoFollow(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s must not be a symbolic link", path)
	}
	return os.Open(path)
}
