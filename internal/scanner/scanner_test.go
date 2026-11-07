package scanner

import (
	"testing"

	"github.com/Armoooo/mail-sentry/internal/message"
)

func TestSuspiciousMessageIsHighRisk(t *testing.T) {
	msg := message.Message{
		From:                  "security@trusted.example",
		ReplyTo:               "collect@attacker.example",
		ReturnPath:            "bounce@attacker.example",
		Subject:               "Final warning: immediate action required",
		TextBody:              "Verify your account within 24 hours.",
		AuthenticationResults: "spf=fail dkim=fail dmarc=fail",
		Links: []message.Link{{
			URL:     "http://192.0.2.1/login",
			Display: "https://trusted.example/login",
		}},
	}
	result := New().Scan(msg)
	if result.Score != 100 {
		t.Fatalf("score = %d, want 100", result.Score)
	}
	if result.Classification != "high-risk" {
		t.Fatalf("classification = %q", result.Classification)
	}
}

func TestAuthenticatedMessageIsLowRisk(t *testing.T) {
	msg := message.Message{
		From:                  "team@example.com",
		ReturnPath:            "bounce@mail.example.com",
		Subject:               "Weekly engineering update",
		TextBody:              "Here is this week's update.",
		AuthenticationResults: "spf=pass dkim=pass dmarc=pass",
		Links:                 []message.Link{{URL: "https://example.com/update"}},
	}
	result := New().Scan(msg)
	if result.Score != 0 {
		t.Fatalf("score = %d, want 0", result.Score)
	}
	if result.Classification != "low-risk" {
		t.Fatalf("classification = %q", result.Classification)
	}
}

func TestExecutableAttachmentAddsRisk(t *testing.T) {
	result := New().Scan(message.Message{
		Attachments: []message.Attachment{{Filename: "invoice.exe"}},
	})
	if result.Score != 35 {
		t.Fatalf("score = %d, want 35", result.Score)
	}
}
