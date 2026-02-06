package ops

import (
	"path/filepath"
	"strings"
)

func IsSafePath(p string) bool {
	clean := filepath.Clean(p)
	return !strings.Contains(clean, "..")
}
