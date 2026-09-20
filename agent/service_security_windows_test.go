//go:build windows
// +build windows

package main

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsAgentACLAllowsOnlyServiceAndAdministrators(t *testing.T) {
	root := t.TempDir()
	sid, err := windows.StringToSid("S-1-5-80-123456789-123456789-123456789-123456789-123456789")
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := applyWindowsAgentACL(root, dacl); err != nil {
		t.Fatalf("apply protected ACL: %v", err)
	}
	actual, err := windows.GetNamedSecurityInfo(root, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read protected ACL: %v", err)
	}
	sddl := actual.String()
	if !strings.Contains(sddl, "BA") || !strings.Contains(sddl, "SY") || !strings.Contains(sddl, sid.String()) {
		t.Fatalf("protected ACL missing required principals: %s", sddl)
	}
	if strings.Contains(sddl, "WD") || strings.Contains(sddl, "BU") || strings.Contains(sddl, "AU") {
		t.Fatalf("protected ACL grants broad interactive access: %s", sddl)
	}
}

func TestWindowsAgentDataDirectoryRejectsReparsePoint(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	link := root + "\\junction"
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}
	if err := rejectWindowsReparsePoints(root); err == nil {
		t.Fatal("reparse point was accepted in Agent data directory")
	}
}
