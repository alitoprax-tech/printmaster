//go:build windows

package agent

import (
	"golang.org/x/sys/windows"
)

// MoveFileEx with REPLACE_EXISTING and WRITE_THROUGH is the Windows analogue
// of a same-volume atomic rename. os.Rename cannot replace an existing file on
// every supported Windows filesystem, so pointer switching uses this API.
func atomicReplaceIdentityFilePlatform(source, target string) error {
	sourcePtr, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	targetPtr, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(sourcePtr, targetPtr, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// Windows does not permit opening a directory as a normal file. A directory
// handle opened with BACKUP_SEMANTICS can still be flushed, which gives the
// generation and pointer directory changes an explicit durability boundary.
func syncIdentityDirectoryPlatform(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(
		p,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_WRITE_THROUGH,
		0,
	)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.FlushFileBuffers(h)
}
