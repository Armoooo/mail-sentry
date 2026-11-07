// Package scanner implements MailSentry's explainable, deterministic rules engine.
package scanner

import (
	"net"
	"net/mail"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/Armoooo/mail-sentry/internal/message"
)

type Finding struct {
	Rule        string `json:"rule"`
	Points      int    `json:"points"`
	Description string `json:"description"`
}

type Result struct {
	Score          int       `json:"score"`
	Classification string    `json:"classification"`
	Findings       []Finding `json:"findings"`
}

type rule func(message.Message) []Finding

type Scanner struct {
	rules []rule
}

func New() *Scanner {
	return &Scanner{rules: []rule{
		authenticationRule,
		addressMismatchRule,
		linkRule,
		attachmentRule,
		languageRule,
		bodyRule,
	}}
}

func (s *Scanner) Scan(msg message.Message) Result {
	var findings []Finding
	score := 0
	for _, check := range s.rules {
		for _, finding := range check(msg) {
			findings = append(findings, finding)
			score += finding.Points
		}
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return Result{Score: score, Classification: classify(score), Findings: findings}
}

func classify(score int) string {
	switch {
	case score >= 80:
		return "high-risk"
	case score >= 60:
		return "likely-spam"
	case score >= 30:
		return "review"
	default:
		return "low-risk"
	}
}

func authenticationRule(msg message.Message) []Finding {
	auth := strings.ToLower(msg.AuthenticationResults + " " + msg.ReceivedSPF)
	var findings []Finding
	checks := []struct {
		failure string
		pass    string
		points  int
		rule    string
	}{
		{"dmarc=fail", "dmarc=pass", 30, "dmarc-failed"},
		{"spf=fail", "spf=pass", 20, "spf-failed"},
		{"dkim=fail", "dkim=pass", 20, "dkim-failed"},
	}
	passCount := 0
	for _, check := range checks {
		if strings.Contains(auth, check.failure) {
			findings = append(findings, Finding{check.rule, check.points, strings.ToUpper(strings.Split(check.failure, "=")[0]) + " authentication failed"})
		} else if strings.Contains(auth, check.pass) {
			passCount++
		}
	}
	if passCount == len(checks) {
		findings = append(findings, Finding{"authentication-passed", -15, "DMARC, SPF and DKIM authentication passed"})
	}
	return findings
}

func addressMismatchRule(msg message.Message) []Finding {
	fromDomain := emailDomain(msg.From)
	var findings []Finding
	if replyDomain := emailDomain(msg.ReplyTo); fromDomain != "" && replyDomain != "" && fromDomain != replyDomain {
		findings = append(findings, Finding{"reply-to-mismatch", 20, "Reply-To domain differs from the sender domain"})
	}
	if returnDomain := emailDomain(msg.ReturnPath); fromDomain != "" && returnDomain != "" && !relatedDomains(fromDomain, returnDomain) {
		findings = append(findings, Finding{"return-path-mismatch", 15, "Return-Path domain differs from the sender domain"})
	}
	return findings
}

func linkRule(msg message.Message) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	for _, link := range msg.Links {
		parsed, err := url.Parse(link.URL)
		if err != nil {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		if parsed.Scheme == "http" && !seen["insecure-link"] {
			findings = append(findings, Finding{"insecure-link", 10, "Message contains a non-HTTPS link"})
			seen["insecure-link"] = true
		}
		if net.ParseIP(host) != nil && !seen["ip-address-link"] {
			findings = append(findings, Finding{"ip-address-link", 25, "Message links directly to an IP address"})
			seen["ip-address-link"] = true
		}
		if isShortener(host) && !seen["shortened-link"] {
			findings = append(findings, Finding{"shortened-link", 15, "Message uses a shortened link that conceals its destination"})
			seen["shortened-link"] = true
		}
		if displayHost := displayedHost(link.Display); displayHost != "" && !relatedDomains(displayHost, host) && !seen["disguised-link"] {
			findings = append(findings, Finding{"disguised-link", 30, "Displayed link domain differs from its destination"})
			seen["disguised-link"] = true
		}
	}
	return findings
}

func attachmentRule(msg message.Message) []Finding {
	dangerous := map[string]bool{
		".app": true, ".bat": true, ".cmd": true, ".com": true, ".exe": true,
		".hta": true, ".js": true, ".jar": true, ".msi": true, ".scr": true,
		".vbs": true, ".ps1": true,
	}
	var findings []Finding
	for _, attachment := range msg.Attachments {
		if dangerous[strings.ToLower(filepath.Ext(attachment.Filename))] {
			findings = append(findings, Finding{"dangerous-attachment", 35, "Message contains a potentially executable attachment: " + attachment.Filename})
		}
	}
	return findings
}

func languageRule(msg message.Message) []Finding {
	content := strings.ToLower(msg.Subject + " " + msg.TextBody + " " + stripHTML(msg.HTMLBody))
	groups := []struct {
		rule        string
		points      int
		description string
		phrases     []string
	}{
		{"urgent-language", 10, "Message uses urgent or threatening language", []string{"act now", "immediate action", "account suspended", "within 24 hours", "final warning"}},
		{"credential-request", 20, "Message asks the recipient to verify credentials or account access", []string{"verify your account", "confirm your password", "validate your login", "reset your password"}},
		{"payment-language", 10, "Message contains an unexpected payment or prize prompt", []string{"wire transfer", "gift card", "claim your prize", "you have won", "crypto wallet"}},
	}
	var findings []Finding
	for _, group := range groups {
		for _, phrase := range group.phrases {
			if strings.Contains(content, phrase) {
				findings = append(findings, Finding{group.rule, group.points, group.description})
				break
			}
		}
	}
	return findings
}

func bodyRule(msg message.Message) []Finding {
	if strings.TrimSpace(msg.TextBody) == "" && strings.TrimSpace(msg.HTMLBody) != "" {
		return []Finding{{"html-only", 5, "Message contains HTML but no plain-text alternative"}}
	}
	return nil
}

func emailDomain(value string) string {
	if value == "" {
		return ""
	}
	parsed, err := mail.ParseAddress(value)
	if err == nil {
		value = parsed.Address
	}
	index := strings.LastIndex(value, "@")
	if index < 0 {
		return ""
	}
	return strings.ToLower(strings.Trim(value[index+1:], "> "))
}

func displayedHost(display string) string {
	display = strings.TrimSpace(display)
	if !strings.HasPrefix(strings.ToLower(display), "http://") && !strings.HasPrefix(strings.ToLower(display), "https://") {
		return ""
	}
	parsed, err := url.Parse(display)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

func relatedDomains(first, second string) bool {
	first = strings.TrimPrefix(strings.ToLower(first), "www.")
	second = strings.TrimPrefix(strings.ToLower(second), "www.")
	return first == second || strings.HasSuffix(first, "."+second) || strings.HasSuffix(second, "."+first)
}

func isShortener(host string) bool {
	switch strings.TrimPrefix(host, "www.") {
	case "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly", "cutt.ly":
		return true
	default:
		return false
	}
}

func stripHTML(value string) string {
	var out strings.Builder
	inTag := false
	for _, char := range value {
		switch char {
		case '<':
			inTag = true
		case '>':
			inTag = false
		default:
			if !inTag {
				out.WriteRune(char)
			}
		}
	}
	return out.String()
}
