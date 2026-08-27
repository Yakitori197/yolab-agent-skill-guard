// Command covercheck parses a Go coverprofile and enforces a minimum
// aggregate statement coverage over the packages whose file paths contain
// the -match substring (default: /internal/). It exists so CI and the local
// verify scripts share one exact, dependency-free gate.
//
// Merged profiles repeat blocks once per test binary, so blocks are deduped
// by position and a block counts as covered when any run executed it.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	profile := flag.String("profile", "cover.out", "coverprofile file to read")
	min := flag.Float64("min", 90, "minimum aggregate statement coverage percent")
	match := flag.String("match", "/internal/", "only count files whose import path contains this substring")
	flag.Parse()

	percent, err := aggregate(*profile, *match)
	if err != nil {
		fmt.Fprintf(os.Stderr, "covercheck: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("covercheck: aggregate statement coverage for %q = %.1f%% (minimum %.1f%%)\n", *match, percent, *min)
	if percent < *min {
		fmt.Fprintln(os.Stderr, "covercheck: coverage below minimum")
		os.Exit(1)
	}
}

type block struct {
	stmts   int
	covered bool
}

func aggregate(profile, match string) (float64, error) {
	f, err := os.Open(profile)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	blocks := map[string]*block{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "mode:") || strings.TrimSpace(line) == "" {
			continue
		}
		// file.go:startLine.startCol,endLine.endCol numStmts count
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return 0, fmt.Errorf("malformed profile line: %q", line)
		}
		if !strings.Contains(fields[0], match) {
			continue
		}
		stmts, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0, fmt.Errorf("malformed statement count in %q", line)
		}
		count, err := strconv.Atoi(fields[2])
		if err != nil {
			return 0, fmt.Errorf("malformed hit count in %q", line)
		}
		b, ok := blocks[fields[0]]
		if !ok {
			b = &block{stmts: stmts}
			blocks[fields[0]] = b
		}
		if count > 0 {
			b.covered = true
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	total, covered := 0, 0
	for _, b := range blocks {
		total += b.stmts
		if b.covered {
			covered += b.stmts
		}
	}
	if total == 0 {
		return 0, fmt.Errorf("no statements matched %q in %s", match, profile)
	}
	return float64(covered) * 100 / float64(total), nil
}
