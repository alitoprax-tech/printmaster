package report

import (
	"net/url"
	"strings"
	"testing"
)

func TestBuildGitHubIssueURLEscapesQueryDelimiters(t *testing.T) {
	r := &DiagnosticReport{
		IssueType:     IssueOther,
		DeviceModel:   "model%26injected=1",
		ExpectedValue: "expected&extra=1",
		UserMessage:   "note?x=1#fragment",
		ReportID:      "RPT-1",
		AgentVersion:  "test",
	}
	got := BuildGitHubIssueURL(r, "https://gist.example/report")
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse issue URL: %v", err)
	}
	query := parsed.Query()
	if query.Get("expected") != r.ExpectedValue || query.Get("description") != r.UserMessage {
		t.Fatalf("query values were not preserved: %v", query)
	}
	if strings.Contains(got, "&extra=1") || strings.Contains(got, "#fragment") {
		t.Fatalf("unescaped query delimiter in URL: %s", got)
	}
}
