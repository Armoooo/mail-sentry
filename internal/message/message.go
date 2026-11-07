// Package message parses email messages into the small, safe representation
// consumed by MailSentry's rules engine.
package message

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

const MaxMessageSize = 10 << 20 // 10 MiB

var (
	urlPattern    = regexp.MustCompile(`(?i)https?://[^\s<>"']+`)
	anchorPattern = regexp.MustCompile(`(?is)<a\s+[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>`)
	tagPattern    = regexp.MustCompile(`(?s)<[^>]*>`)
)

// ErrTooLarge is returned before parsing an email larger than MaxMessageSize.
var ErrTooLarge = errors.New("email exceeds the 10 MiB size limit")

type Attachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
}

type Link struct {
	URL     string `json:"url"`
	Display string `json:"display,omitempty"`
}

type Message struct {
	From                  string       `json:"from"`
	ReplyTo               string       `json:"reply_to,omitempty"`
	ReturnPath            string       `json:"return_path,omitempty"`
	Subject               string       `json:"subject"`
	TextBody              string       `json:"-"`
	HTMLBody              string       `json:"-"`
	AuthenticationResults string       `json:"-"`
	ReceivedSPF           string       `json:"-"`
	Attachments           []Attachment `json:"attachments,omitempty"`
	Links                 []Link       `json:"links,omitempty"`
}

func Parse(r io.Reader) (Message, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxMessageSize+1))
	if err != nil {
		return Message{}, fmt.Errorf("read email: %w", err)
	}
	if len(raw) > MaxMessageSize {
		return Message{}, ErrTooLarge
	}

	parsed, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return Message{}, fmt.Errorf("parse email: %w", err)
	}

	msg := Message{
		From:                  address(parsed.Header.Get("From")),
		ReplyTo:               address(parsed.Header.Get("Reply-To")),
		ReturnPath:            address(parsed.Header.Get("Return-Path")),
		Subject:               decodeHeader(parsed.Header.Get("Subject")),
		AuthenticationResults: parsed.Header.Get("Authentication-Results"),
		ReceivedSPF:           parsed.Header.Get("Received-SPF"),
	}

	if err := readEntity(textproto.MIMEHeader(parsed.Header), parsed.Body, &msg); err != nil {
		return Message{}, fmt.Errorf("parse MIME body: %w", err)
	}
	msg.Links = extractLinks(msg.TextBody, msg.HTMLBody)
	return msg, nil
}

func readEntity(header textproto.MIMEHeader, body io.Reader, msg *Message) error {
	mediaType, params, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || mediaType == "" {
		mediaType = "text/plain"
	}

	decoded := decodeTransfer(body, header.Get("Content-Transfer-Encoding"))
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return errors.New("multipart message has no boundary")
		}
		parts := multipart.NewReader(decoded, boundary)
		for {
			part, partErr := parts.NextPart()
			if errors.Is(partErr, io.EOF) {
				break
			}
			if partErr != nil {
				return partErr
			}
			if err := readEntity(part.Header, part, msg); err != nil {
				part.Close()
				return err
			}
			part.Close()
		}
		return nil
	}

	disposition, dispositionParams, _ := mime.ParseMediaType(header.Get("Content-Disposition"))
	filename := decodeHeader(dispositionParams["filename"])
	if filename == "" {
		filename = decodeHeader(params["name"])
	}
	if disposition == "attachment" || filename != "" {
		msg.Attachments = append(msg.Attachments, Attachment{
			Filename:    filepath.Base(filename),
			ContentType: mediaType,
		})
		return nil
	}

	content, err := io.ReadAll(decoded)
	if err != nil {
		return err
	}
	switch mediaType {
	case "text/plain":
		msg.TextBody += "\n" + string(content)
	case "text/html":
		msg.HTMLBody += "\n" + string(content)
	}
	return nil
}

func decodeTransfer(r io.Reader, encoding string) io.Reader {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, r)
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	default:
		return r
	}
}

func decodeHeader(value string) string {
	decoded, err := new(mime.WordDecoder).DecodeHeader(value)
	if err != nil {
		return value
	}
	return decoded
}

func address(value string) string {
	if value == "" {
		return ""
	}
	parsed, err := mail.ParseAddress(value)
	if err == nil {
		return strings.ToLower(parsed.Address)
	}
	return strings.ToLower(strings.Trim(value, "<> \t"))
}

func extractLinks(textBody, htmlBody string) []Link {
	links := make([]Link, 0)
	seen := make(map[string]bool)
	for _, match := range anchorPattern.FindAllStringSubmatch(htmlBody, -1) {
		target := html.UnescapeString(strings.TrimSpace(match[1]))
		if !isHTTPURL(target) {
			continue
		}
		display := strings.TrimSpace(html.UnescapeString(tagPattern.ReplaceAllString(match[2], "")))
		links = append(links, Link{URL: target, Display: display})
		seen[target] = true
	}
	for _, found := range urlPattern.FindAllString(textBody+"\n"+htmlBody, -1) {
		found = strings.TrimRight(html.UnescapeString(found), ".,);]")
		if !seen[found] && isHTTPURL(found) {
			links = append(links, Link{URL: found})
			seen[found] = true
		}
	}
	return links
}

func isHTTPURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Hostname() != ""
}
