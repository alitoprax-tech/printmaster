package selfupdate

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"printmaster/server/storage"
)

func TestApplyHelperRequiresSignatureAndUnchangedStagedBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.bin")
	if err := os.WriteFile(path, []byte("binary"), 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("binary"))
	manifest := provisionSignedRelease(t, &storage.ReleaseArtifact{Component: "server", Version: "1.2.4", Platform: runtime.GOOS, Arch: runtime.GOARCH, Channel: "stable", SHA256: fmt.Sprintf("%x", hash[:]), SizeBytes: 6})
	inst := &ApplyInstruction{Manifest: manifest, Component: "server", Platform: runtime.GOOS, Arch: runtime.GOARCH, Channel: "stable", CurrentVersion: "1.2.3", TargetVersion: "1.2.4", StagePath: path}
	if err := verifyApplyInstruction(inst, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	inst.CurrentVersion = "1.2.5"
	if err := verifyApplyInstruction(inst, time.Now().UTC()); err == nil {
		t.Fatal("rollback accepted")
	}
	inst.CurrentVersion = "1.2.3"
	if err := os.WriteFile(path, []byte("forged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyApplyInstruction(inst, time.Now().UTC()); err == nil {
		t.Fatal("modified staged binary accepted")
	}
	// No logger or service/database dependency is configured: rejection must occur first.
	worker := &applyWorker{inst: inst}
	if err := worker.execute(context.Background()); err == nil {
		t.Fatal("apply worker accepted forged bytes")
	}
	inst.Manifest = nil
	if err := verifyApplyInstruction(inst, time.Now().UTC()); err == nil {
		t.Fatal("unsigned apply accepted")
	}
}

func TestSelfUpdateRejectsMissingOfflineTrustBeforeLaunch(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	createArtifact(t, store, ctx, "server", "0.9.6", "stable", "windows", "amd64")
	t.Setenv("PRINTMASTER_UPDATE_TRUST_FILE", "")
	launcher := &stubLauncher{}
	mgr, err := NewManager(Options{Store: store, DataDir: t.TempDir(), Enabled: true, CurrentVersion: "0.9.5", Platform: "windows", Arch: "amd64", BinaryPath: createDummyBinary(t), ApplyLauncher: launcher, RuntimeSkipCheck: func() string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	mgr.tick(ctx)
	if launcher.inst != nil {
		t.Fatal("unsigned update reached apply launcher")
	}
	runs, err := store.ListSelfUpdateRuns(ctx, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].Status != storage.SelfUpdateStatusFailed {
		t.Fatalf("expected failed update: %#v", runs)
	}
}
