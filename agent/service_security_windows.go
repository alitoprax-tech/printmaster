//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

const windowsAgentServiceAccount = `NT SERVICE\PrintMasterAgent`

// configureInstalledWindowsService enables the service SID after the service
// has been created. The SID is then used as the only non-administrative
// principal allowed to read the Agent state directory.
func configureInstalledWindowsService(serviceName string) error {
	if strings.TrimSpace(serviceName) == "" {
		return fmt.Errorf("service name required")
	}
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open installed service: %w", err)
	}
	defer service.Close()
	cfg, err := service.Config()
	if err != nil {
		return fmt.Errorf("read service configuration: %w", err)
	}
	cfg.ServiceStartName = windowsAgentServiceAccount
	cfg.Password = ""
	cfg.SidType = windows.SERVICE_SID_TYPE_UNRESTRICTED
	if err := service.UpdateConfig(cfg); err != nil {
		return fmt.Errorf("configure virtual service account and service SID: %w", err)
	}
	return nil
}

func hardenWindowsAgentDataDirectory(dataDir string) error {
	if strings.TrimSpace(dataDir) == "" {
		return fmt.Errorf("Agent data directory required")
	}
	if !filepath.IsAbs(dataDir) {
		return fmt.Errorf("Agent data directory must be absolute")
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("create Agent data directory: %w", err)
	}
	// Create the sensitive subtrees before applying ACLs so newly-created
	// generations inherit the same protected DACL.
	for _, subdir := range []string{
		filepath.Join(dataDir, "agent"),
		filepath.Join(dataDir, "agent", "logs"),
		filepath.Join(dataDir, "agent", "identity"),
		filepath.Join(dataDir, "agent", "identity", "active"),
		filepath.Join(dataDir, "agent", "identity", "pending"),
		filepath.Join(dataDir, "agent", "identity", "enrollment"),
		filepath.Join(dataDir, "agent", "config"),
		filepath.Join(dataDir, "agent", "secrets"),
	} {
		if err := os.MkdirAll(subdir, 0700); err != nil {
			return fmt.Errorf("create protected Agent directory %s: %w", subdir, err)
		}
	}
	if err := rejectWindowsReparsePoints(dataDir); err != nil {
		return err
	}
	sid, _, _, err := windows.LookupSID("", windowsAgentServiceAccount)
	if err != nil {
		return fmt.Errorf("resolve Agent service SID: %w", err)
	}
	sddl := fmt.Sprintf("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)", sid.String())
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("build Agent data ACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read Agent data ACL: %w", err)
	}
	return applyWindowsAgentACL(dataDir, dacl)
}

func ensureWindowsAgentDataDirectory(dataDir string) error {
	// Re-validate the complete tree at every service start. This catches a
	// junction/reparse-point replacement that occurred after installation.
	return hardenWindowsAgentDataDirectory(dataDir)
}

func applyWindowsAgentACL(root string, dacl *windows.ACL) error {
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing reparse/symlink path in Agent data directory: %s", path)
		}
		name, attrErr := windows.UTF16PtrFromString(path)
		if attrErr != nil {
			return attrErr
		}
		attrs, attrErr := windows.GetFileAttributes(name)
		if attrErr != nil {
			return fmt.Errorf("inspect Agent data path %s: %w", path, attrErr)
		}
		if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("refusing reparse-point path in Agent data directory: %s", path)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, dacl, nil); err != nil {
			return fmt.Errorf("apply Agent data ACL to %s: %w", path, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func rejectWindowsReparsePoints(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing reparse/symlink path in Agent data directory: %s", path)
		}
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		attrs, err := windows.GetFileAttributes(name)
		if err != nil {
			return fmt.Errorf("inspect Agent data path %s: %w", path, err)
		}
		if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("refusing reparse-point path in Agent data directory: %s", path)
		}
		return nil
	})
}
