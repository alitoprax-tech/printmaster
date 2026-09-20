//go:build !windows
// +build !windows

package main

// Windows service identity and ACL hardening are intentionally platform
// specific. Other platforms retain their existing service-manager security
// configuration and PEM key behavior.
func configureInstalledWindowsService(string) error { return nil }

func hardenWindowsAgentDataDirectory(string) error { return nil }

func ensureWindowsAgentDataDirectory(string) error { return nil }
