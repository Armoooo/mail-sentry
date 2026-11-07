# MailSentry

MailSentry is an explainable email risk analyser written in Go. It parses
standard `.eml` messages, evaluates transparent security rules and reports a
risk score with the reasons behind it.

The current release is deliberately offline and read-only. It does not connect
to a mailbox, execute message content, load remote images, delete mail or send
message bodies to a third party.

## What it checks

- SPF, DKIM and DMARC failures
- Sender, Reply-To and Return-Path domain mismatches
- Disguised, shortened, non-HTTPS and IP-address links
- Potentially executable attachments
- Credential, payment and urgent-language patterns
- HTML-only messages

MailSentry is a risk-ranking tool, not a replacement for the anti-spam and
anti-malware controls provided by an email service.

## Run the demo

Go 1.26 or later is required.

```sh
go run ./cmd/mailsentry scan samples/suspicious.eml samples/legitimate.eml
```

For machine-readable output:

```sh
go run ./cmd/mailsentry scan --format json samples/suspicious.eml
```

To scan a message from standard input:

```sh
cat message.eml | go run ./cmd/mailsentry scan -
```

## Build and test

```sh
make build
make check
```

The resulting binary is written to `bin/mailsentry`.

## Scoring

Every finding adds or subtracts a documented number of points. The total is
clamped to a range of 0-100:

| Score | Classification |
| ---: | --- |
| 0-29 | `low-risk` |
| 30-59 | `review` |
| 60-79 | `likely-spam` |
| 80-100 | `high-risk` |

This first version favours deterministic rules over an opaque classifier. That
makes decisions reproducible, testable and easy to explain. Scores indicate
risk; they do not prove that a message is malicious.

## Roadmap

- Gmail integration using OAuth and label-only dry-run mode
- IMAP adapter for provider-independent inbox access
- Feedback-driven Bayesian classification
- Review dashboard and screening metrics
- Configurable allowlists and rule weights

## Privacy and security

Treat email files as sensitive. MailSentry processes them locally and does not
persist message bodies. Sample messages in this repository use reserved
`example` domains and documentation-only IP addresses.

## Licence

[MIT](LICENSE)
