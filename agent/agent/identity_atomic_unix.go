//go:build !windows

package agent

import "os"

// atomicReplaceIdentityFile relies on rename(2)'s same-filesystem atomic
// replacement semantics. The caller fsyncs the containing directory after the
// rename so the selector survives a power loss.
func atomicReplaceIdentityFilePlatform(source, target string) error {
	return os.Rename(source, target)
}

func syncIdentityDirectoryPlatform(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
