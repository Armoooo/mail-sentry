package message

import (
	"errors"
	"strings"
	"testing"
)

func TestParseMultipartMessage(t *testing.T) {
	raw := `From: Example <sender@example.com>
Reply-To: help@other.example
Subject: =?UTF-8?Q?Account_update?=
Content-Type: multipart/alternative; boundary="test-boundary"

--test-boundary
Content-Type: text/plain

Visit https://example.com/account
--test-boundary
Content-Type: text/html

<a href="http://evil.example/login">https://example.com/account</a>
--test-boundary--
`
	msg, err := Parse(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if msg.From != "sender@example.com" {
		t.Fatalf("From = %q", msg.From)
	}
	if msg.Subject != "Account update" {
		t.Fatalf("Subject = %q", msg.Subject)
	}
	if len(msg.Links) != 2 {
		t.Fatalf("links = %#v, want 2", msg.Links)
	}
	if msg.Links[0].Display != "https://example.com/account" {
		t.Fatalf("anchor display = %q", msg.Links[0].Display)
	}
}

func TestParseRejectsOversizedMessage(t *testing.T) {
	_, err := Parse(strings.NewReader(strings.Repeat("x", MaxMessageSize+1)))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("error = %v, want ErrTooLarge", err)
	}
}
