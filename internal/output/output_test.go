package output

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"scanner/internal/core"
)

func TestWriteJSON(t *testing.T) {
	file := filepath.Join(t.TempDir(), "report.json")
	report := core.Report{ToolVersion: "test", StartedAt: time.Now(), FinishedAt: time.Now()}
	if err := Write(report, OutputOptions{File: file, Format: "json"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Fatal("report was empty")
	}
}
