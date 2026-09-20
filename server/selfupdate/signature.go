package selfupdate

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	"printmaster/common/updateauth"
)

// This authenticates release contents. Restricting the helper's privileges and
// installation paths is a separate requirement of the service broker design.
func verifyApplyInstruction(inst *ApplyInstruction, now time.Time) error {
	if inst == nil || inst.Manifest == nil {
		return fmt.Errorf("independently signed release required")
	}
	keys, err := updateauth.LoadKeyring(os.Getenv("PRINTMASTER_UPDATE_TRUST_FILE"))
	if err != nil {
		return err
	}
	if err := keys.Verify(inst.Manifest, updateauth.Target{Component: "server", Platform: runtime.GOOS, Arch: runtime.GOARCH, Channel: inst.Channel}, now); err != nil {
		return err
	}
	if inst.Component != "server" || inst.Platform != runtime.GOOS || inst.Arch != runtime.GOARCH || inst.TargetVersion != inst.Manifest.Version {
		return fmt.Errorf("apply target mismatch")
	}
	current, err := semver.NewVersion(inst.CurrentVersion)
	if err != nil {
		return fmt.Errorf("invalid installed version")
	}
	target, err := semver.NewVersion(inst.TargetVersion)
	if err != nil || !target.GreaterThan(current) {
		return fmt.Errorf("self-update downgrade or replay rejected")
	}
	if err := updateauth.VerifyFile(inst.StagePath, inst.Manifest); err != nil {
		return err
	}
	for name, path := range map[string]string{
		"stage":  inst.StagePath,
		"backup": inst.BackupPath,
		"binary": inst.BinaryPath,
	} {
		if strings.TrimSpace(path) == "" {
			continue
		}
		clean := filepath.Clean(path)
		info, err := os.Lstat(clean)
		if err != nil {
			if name == "backup" || name == "binary" {
				continue
			}
			return fmt.Errorf("%s path unavailable: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s path must not be a symbolic link", name)
		}
	}
	return nil
}
