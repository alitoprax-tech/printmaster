//go:build windows
// +build windows

package agent

import (
	"fmt"

	"golang.org/x/sys/windows"
)

const windowsPrintMasterServiceAccount = `NT SERVICE\PrintMasterAgent`

// These function variables keep the security boundary testable without
// changing the production token/SID lookup. They are never configured by the
// server or by Agent configuration.
var (
	currentWindowsProcessSID    = currentWindowsProcessSIDPlatform
	lookupPrintMasterServiceSID = lookupPrintMasterServiceSIDPlatform
)

func currentWindowsProcessSIDPlatform() (*windows.SID, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return nil, fmt.Errorf("open current process token: %w", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read current process token user: %w", err)
	}
	if user == nil || user.User.Sid == nil {
		return nil, fmt.Errorf("current process token has no user SID")
	}
	return user.User.Sid, nil
}

func lookupPrintMasterServiceSIDPlatform() (*windows.SID, error) {
	sid, _, _, err := windows.LookupSID("", windowsPrintMasterServiceAccount)
	if err != nil {
		return nil, fmt.Errorf("resolve %s SID: %w", windowsPrintMasterServiceAccount, err)
	}
	if sid == nil {
		return nil, fmt.Errorf("resolve %s SID returned nil", windowsPrintMasterServiceAccount)
	}
	return sid, nil
}

// requirePrintMasterServiceIdentity is the last gate before user-scoped
// DPAPI. DPAPI user scope is recoverable only when encryption and decryption
// run under the installed virtual service account; an interactive/admin
// process must fail closed instead of producing an unusable or exposed key.
func requirePrintMasterServiceIdentity() error {
	actual, err := currentWindowsProcessSID()
	if err != nil {
		return fmt.Errorf("verify current Windows service identity: %w", err)
	}
	expected, err := lookupPrintMasterServiceSID()
	if err != nil {
		return fmt.Errorf("verify installed Windows service identity: %w", err)
	}
	if !expected.Equals(actual) {
		return fmt.Errorf("user-scoped DPAPI requires process identity %s", windowsPrintMasterServiceAccount)
	}
	return nil
}
