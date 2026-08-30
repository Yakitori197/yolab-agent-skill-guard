package app

import (
	"bytes"
	"fmt"
	"io"
)

// Machine output is a different protocol from human output, and the two must
// not share a writer.
//
// `skillguard action-paths` prints `key=value` lines that
// scripts/action-entrypoint.sh parses and forwards into GITHUB_OUTPUT. Those
// values are filesystem paths that were already accepted by
// internal/actionpath, and the caller then writes a report to exactly the path
// it was handed back. Passing them through the human-facing sanitizer was a
// real bug: a legal filename containing U+202E RIGHT-TO-LEFT OVERRIDE came out
// as the six characters backslash-u-2-0-2-e, so the action would have written
// its report to a *different file* than the one the user asked for — silently.
//
// The rule is therefore inverted here compared with safeout.go. Nothing is
// escaped, ever. Instead every value is validated before a byte is written: a
// value that could break the line-based protocol is refused outright, and the
// command exits with an error rather than emitting a rewritten value. Refusing
// is honest; rewriting is not.
//
// The check covers the C0 controls (which include NUL, CR and LF, the ones
// that actually break `key=value` framing), DEL, and the C1 controls. That is
// wider than strictly necessary and deliberately so: it is one simple rule,
// and internal/actionpath already refuses the same set in its relative inputs,
// so a value only reaches here carrying one of them if the workspace path
// itself does.

// machineWriter emits `key=value` lines verbatim.
//
// Lines are buffered and only written once every value has been validated, so
// a run that refuses the fourth value has not already emitted the first three
// and left the caller parsing a truncated protocol.
type machineWriter struct {
	w   io.Writer
	buf bytes.Buffer
	err error
}

func (a *App) newMachineWriter() *machineWriter { return &machineWriter{w: a.Stdout} }

// Line records one protocol line. The first invalid value is remembered and
// reported by Flush; later calls are no-ops.
func (m *machineWriter) Line(key, value string) {
	if m.err != nil {
		return
	}
	if err := validateMachineValue(key, value); err != nil {
		m.err = err
		return
	}
	fmt.Fprintf(&m.buf, "%s=%s\n", key, value)
}

// Flush writes every recorded line, byte for byte, or returns the first
// validation error without writing anything at all.
func (m *machineWriter) Flush() error {
	if m.err != nil {
		return m.err
	}
	if m.w == nil || m.buf.Len() == 0 {
		return nil
	}
	_, err := m.w.Write(m.buf.Bytes())
	return err
}

// validateMachineValue refuses anything that cannot survive a line-based
// key=value protocol. The error names the key and the offending code point,
// never the value: the value is exactly the untrusted text that must not reach
// a terminal unescaped, and the error is human-facing.
func validateMachineValue(key, value string) error {
	for i := 0; i < len(value); i++ {
		if b := value[i]; b < 0x20 || b == 0x7f {
			return fmt.Errorf("cannot emit %s: the path contains a control character (0x%02x), which a line-based key=value protocol cannot carry", key, b)
		}
	}
	for _, r := range value {
		if r >= 0x80 && r <= 0x9f {
			return fmt.Errorf("cannot emit %s: the path contains a C1 control character (U+%04X), which a line-based key=value protocol cannot carry", key, r)
		}
	}
	return nil
}
