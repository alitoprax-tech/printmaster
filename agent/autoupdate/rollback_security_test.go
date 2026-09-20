package autoupdate

import (
	"context"
	"strings"
	"testing"
)

func TestExecuteRejectsRollbackBeforeDownloadOrPackageManager(t *testing.T) {
	version, err := parseSemverVersion("1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{currentSemver: version, usePackageManager: true, packageName: "printmaster-agent"}
	if err := m.executeUpdate(context.Background(), &UpdateManifest{Version: "1.2.2"}); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("rollback not blocked: %v", err)
	}
	m.currentSemver = nil
	if err := m.executeUpdate(context.Background(), &UpdateManifest{Version: "1.2.4"}); err == nil {
		t.Fatal("unknown current version accepted")
	}
}
