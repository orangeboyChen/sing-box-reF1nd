package clashapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUpdateCoreRequiresConfiguredScript(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/upgrade", nil)
	recorder := httptest.NewRecorder()
	updateCore(&Server{})(recorder, request)
	if recorder.Code != http.StatusNotImplemented {
		t.Fatalf("unexpected status: %d", recorder.Code)
	}
}

func TestUpdateCoreStartsConfiguredScript(t *testing.T) {
	temporaryDirectory := t.TempDir()
	markerPath := filepath.Join(temporaryDirectory, "arguments")
	scriptPath := filepath.Join(temporaryDirectory, "upgrade.sh")
	script := "#!/bin/sh\nprintf '%s %s' \"$1\" \"$2\" > \"" + markerPath + "\"\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/upgrade?channel=alpha", nil)
	recorder := httptest.NewRecorder()
	updateCore(&Server{coreUpgradeScript: scriptPath})(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", recorder.Code)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if content, err := os.ReadFile(markerPath); err == nil {
			if string(content) != "update_core alpha" {
				t.Fatalf("unexpected script arguments: %q", content)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("upgrade script was not started")
}

func TestUpdateCoreRejectsUnknownChannel(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/upgrade?channel=beta", nil)
	recorder := httptest.NewRecorder()
	updateCore(&Server{coreUpgradeScript: "/bin/false"})(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: %d", recorder.Code)
	}
}
