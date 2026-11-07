package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Armoooo/mail-sentry/internal/message"
	"github.com/Armoooo/mail-sentry/internal/scanner"
)

const version = "0.1.0"

type output struct {
	Input          string            `json:"input"`
	From           string            `json:"from"`
	Subject        string            `json:"subject"`
	Score          int               `json:"score"`
	Classification string            `json:"classification"`
	Findings       []scanner.Finding `json:"findings"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version)
		return 0
	case "help", "--help", "-h":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func runScan(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "text", "output format: text or json")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintln(stderr, "format must be text or json")
		return 2
	}
	if flags.NArg() == 0 {
		fmt.Fprintln(stderr, "provide at least one .eml file, or - to read from stdin")
		return 2
	}

	engine := scanner.New()
	outputs := make([]output, 0, flags.NArg())
	hadError := false
	for _, path := range flags.Args() {
		result, err := scanPath(path, engine)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", path, err)
			hadError = true
			continue
		}
		outputs = append(outputs, result)
	}

	if *format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(outputs); err != nil {
			fmt.Fprintf(stderr, "write JSON: %v\n", err)
			return 1
		}
	} else {
		writeText(stdout, outputs)
	}
	if hadError {
		return 1
	}
	return 0
}

func scanPath(path string, engine *scanner.Scanner) (output, error) {
	var (
		reader io.Reader
		file   *os.File
		err    error
	)
	if path == "-" {
		reader = os.Stdin
	} else {
		file, err = os.Open(filepath.Clean(path))
		if err != nil {
			return output{}, err
		}
		defer file.Close()
		reader = file
	}
	msg, err := message.Parse(reader)
	if err != nil {
		if errors.Is(err, message.ErrTooLarge) {
			return output{}, message.ErrTooLarge
		}
		return output{}, err
	}
	result := engine.Scan(msg)
	return output{
		Input:          path,
		From:           msg.From,
		Subject:        msg.Subject,
		Score:          result.Score,
		Classification: result.Classification,
		Findings:       result.Findings,
	}, nil
}

func writeText(w io.Writer, outputs []output) {
	for index, result := range outputs {
		if index > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "%s\n", result.Input)
		fmt.Fprintf(w, "  From:    %s\n", result.From)
		fmt.Fprintf(w, "  Subject: %s\n", result.Subject)
		fmt.Fprintf(w, "  Result:  %d/100 (%s)\n", result.Score, result.Classification)
		if len(result.Findings) == 0 {
			fmt.Fprintln(w, "  Findings: none")
			continue
		}
		fmt.Fprintln(w, "  Findings:")
		for _, finding := range result.Findings {
			fmt.Fprintf(w, "    %+d  %s\n", finding.Points, finding.Description)
		}
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "MailSentry - explainable email risk analysis")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  mailsentry scan [--format text|json] <message.eml> [...]")
	fmt.Fprintln(w, "  mailsentry version")
}
