// Package termsafe neutralizes text that is about to be written to a
// terminal.
//
// Everything the scanner prints in human-readable form can originate outside
// the tool: a filename on disk (POSIX filenames may contain ESC, CR, LF and
// any other byte except NUL and '/'), a path the user typed, or a fragment of
// a scanned document echoed back in a finding message. Written straight to a
// terminal, such text can move the cursor, repaint the screen, set the window
// title through an OSC sequence, or use bidirectional overrides to display
// words in an order the bytes do not have — which means a scanned file could
// forge a finding line, hide a real one, or rewrite the verdict a human reads.
//
// Sanitize is the single boundary where that is stopped. It is deliberately
// not an encoder: printable text, including Traditional Chinese and every
// other script, is returned byte-for-byte unchanged, so normal reports are
// unaffected. Only runes a terminal can act on, or that reorder what is
// displayed, become visible escapes.
//
// The machine-readable formats do not use this package. JSON, SARIF and HTML
// each escape at their own layer, and applying terminal escapes there would
// corrupt data consumers depend on.
package termsafe

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Sanitize returns s with every terminal-actionable or text-reordering rune
// replaced by a visible, deterministic escape.
//
// The escapes are:
//
//	backslash-n, backslash-r, backslash-t   the three familiar C0 controls
//	backslash-x plus two hex digits         every other C0/C1 control,
//	                                        including ESC and DEL
//	backslash-u plus four hex digits        Unicode format controls (bidi
//	                                        overrides and isolates, zero-width
//	                                        joiners, soft hyphen, byte-order
//	                                        mark) and the line and paragraph
//	                                        separators
//	backslash-x plus two hex digits         each byte of malformed UTF-8,
//	                                        taken one byte at a time
//
// The transformation is one-way by design: a literal backslash is left alone,
// so the output is not a quoted string and must not be parsed back. Its only
// contract is that the result contains no rune a terminal will interpret and
// no rune that changes the display order of what surrounds it.
func Sanitize(s string) string { return sanitize(s, false) }

// SanitizeBlock is Sanitize for multi-line text this tool composed itself: a
// usage block, a flag's default list, a formatted table. Line feeds and tabs
// are layout there, so they are kept, and every other terminal-actionable rune
// is still escaped.
//
// It must never be handed text that carries a value from outside the tool. Use
// Sanitize for that: it escapes line feeds too, so an injected newline cannot
// forge a line. The rule this package follows is that a *format string* is
// ours and may keep its layout, while every *argument* is untrusted and goes
// through Sanitize.
func SanitizeBlock(s string) string { return sanitize(s, true) }

func sanitize(s string, keepLayout bool) string {
	if !needsEscaping(s, keepLayout) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// A byte that is not part of a valid encoding. Emitting it would
			// hand the terminal a byte we have not classified.
			writeHexByte(&b, s[i])
			i++
			continue
		}
		if unsafeRune(r, keepLayout) {
			writeEscape(&b, r)
		} else {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// SanitizeAll applies Sanitize to every element, returning a new slice so the
// caller's data is not modified.
func SanitizeAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = Sanitize(s)
	}
	return out
}

// needsEscaping is the fast path: the overwhelming majority of report strings
// are ordinary text, and this lets them be returned without allocating.
func needsEscaping(s string, keepLayout bool) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return true
		}
		if unsafeRune(r, keepLayout) {
			return true
		}
		i += size
	}
	return false
}

// unsafeRune classifies a rune as something a terminal can act on or that can
// reorder the surrounding text.
//
//   - Cc covers the C0 controls (including ESC, CR, LF, TAB and DEL) and the
//     C1 controls, whose 8-bit forms some terminals still interpret.
//   - Cf covers the Unicode format characters: the bidirectional overrides and
//     isolates (U+202A–U+202E, U+2066–U+2069, U+200E/U+200F, U+061C) that can
//     display text in an order the bytes do not have, plus zero-width joiners,
//     the soft hyphen, and the byte-order mark.
//   - Cs covers surrogate code points, which are never valid in UTF-8 text.
//   - Zl and Zp are the Unicode line and paragraph separators; some terminals
//     and many downstream tools treat them as line breaks.
//
// Everything else — letters, marks, digits, punctuation, symbols, and every
// space character including U+3000 — is left exactly as it is.
func unsafeRune(r rune, keepLayout bool) bool {
	// 0x0a and 0x09: line feed and tab. Written as code points so this
	// source file contains no control character of its own.
	if keepLayout && (r == 0x0a || r == 0x09) {
		return false
	}
	switch {
	case unicode.Is(unicode.Cc, r),
		unicode.Is(unicode.Cf, r),
		unicode.Is(unicode.Cs, r),
		unicode.Is(unicode.Zl, r),
		unicode.Is(unicode.Zp, r):
		return true
	}
	return false
}

func writeEscape(b *strings.Builder, r rune) {
	switch r {
	case '\n':
		b.WriteString(`\n`)
	case '\r':
		b.WriteString(`\r`)
	case '\t':
		b.WriteString(`\t`)
	default:
		switch {
		// Only ASCII uses the byte form, so a two-hex escape is always an
		// ASCII control and never collides with the escape of a malformed
		// byte, which is always 0x80 or above.
		case r < 0x80:
			b.WriteString(`\x`)
			writeHex(b, uint32(r), 2)
		case r <= 0xffff:
			b.WriteString(`\u`)
			writeHex(b, uint32(r), 4)
		default:
			b.WriteString(`\U`)
			writeHex(b, uint32(r), 8)
		}
	}
}

func writeHexByte(b *strings.Builder, c byte) {
	b.WriteString(`\x`)
	writeHex(b, uint32(c), 2)
}

// writeHex writes v as lowercase hex, left-padded to width digits, so the same
// input always produces the same bytes.
func writeHex(b *strings.Builder, v uint32, width int) {
	h := strconv.FormatUint(uint64(v), 16)
	for i := len(h); i < width; i++ {
		b.WriteByte('0')
	}
	b.WriteString(h)
}
