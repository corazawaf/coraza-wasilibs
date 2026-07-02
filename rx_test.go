// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.rule.no_regex_multiline

package wasilibs

import (
	"fmt"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func TestRx(t *testing.T) {
	tests := []struct {
		pattern string
		input   string
		want    bool
	}{
		{
			pattern: "som(.*)ta",
			input:   "somedata",
			want:    true,
		},
		{
			pattern: "som(.*)ta",
			input:   "notdata",
			want:    false,
		},
		{
			pattern: "ハロー",
			input:   "ハローワールド",
			want:    true,
		},
		{
			pattern: "ハロー",
			input:   "グッバイワールド",
			want:    false,
		},
		{
			pattern: `\xac\xed\x00\x05`,
			input:   "\xac\xed\x00\x05t\x00\x04test",
			want:    true,
		},
		{
			pattern: `\xac\xed\x00\x05`,
			input:   "\xac\xed\x00t\x00\x04test",
			want:    false,
		},
		{
			// Braced hex escape \x{NN} form (used by CRS 4.25+ regex-assembly output)
			pattern: `\x{ac}\x{ed}\x{00}\x{05}`,
			input:   "\xac\xed\x00\x05t\x00\x04test",
			want:    true,
		},
		{
			pattern: `\x{ac}\x{ed}\x{00}\x{05}`,
			input:   "\xac\xed\x00t\x00\x04test",
			want:    false,
		},
		{
			// Mixed braced and unbraced hex escapes
			pattern: `\x{bc}[^\x{be}>]*[\x{be}>]`,
			input:   "\xbcfoo\xbe",
			want:    true,
		},
		{
			// Braced hex no match
			pattern: `\x{bc}[^\x{be}>]*[\x{be}>]`,
			input:   "no binary bytes here",
			want:    false,
		},
		{
			// CRS 941310 main pattern (v4.25.0) - alternation with braced hex
			pattern: `\x{bc}[^>\x{be}]*[>\x{be}]|<[^\x{be}]*\x{be}`,
			input:   "\xbctest\xbe",
			want:    true,
		},
		{
			// CRS 941310 main pattern - second alternative
			pattern: `\x{bc}[^>\x{be}]*[>\x{be}]|<[^\x{be}]*\x{be}`,
			input:   "<test\xbe",
			want:    true,
		},
		{
			// CRS 941310 main pattern - no match
			pattern: `\x{bc}[^>\x{be}]*[>\x{be}]|<[^\x{be}]*\x{be}`,
			input:   "clean input",
			want:    false,
		},
		{
			// Mixed braced hex and unbraced in same pattern
			pattern: `\xac\x{ed}`,
			input:   "\xac\xed",
			want:    true,
		},
		{
			// Requires dotall
			pattern: `hello.*world`,
			input:   "hello\nworld",
			want:    true,
		},
		{
			// Requires multiline
			pattern: `^hello.*world`,
			input:   "test\nhello\nworld",
			want:    true,
		},
		{
			// Makes sure, (?sm) passed by the user does not
			// break the regex.
			pattern: `(?sm)hello.*world`,
			input:   "hello\nworld",
			want:    true,
		},
		{
			// Make sure user flags are also applied
			pattern: `(?i)^hello.*world`,
			input:   "test\nHELLO\nworld",
			want:    true,
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(fmt.Sprintf("%s/%s", tt.pattern, tt.input), func(t *testing.T) {
			opts := plugintypes.OperatorOptions{
				Arguments: tt.pattern,
			}
			rx, err := newRX(opts)
			if err != nil {
				t.Fatal(err)
			}
			waf, err := coraza.NewWAF(coraza.NewWAFConfig())
			if err != nil {
				t.Error(err)
			}
			tx := waf.NewTransaction()
			res := rx.Evaluate(tx.(plugintypes.TransactionState), tt.input)
			if res != tt.want {
				t.Errorf("want %v, got %v", tt.want, res)
			}
		})
	}
}

func TestMatchesArbitraryBytes(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want bool
	}{
		// No hex escapes
		{"plain ascii", `hello`, false},
		{"empty string", ``, false},
		{"only backslash escapes", `\d+\s*\w`, false},

		// Unbraced hex escapes (\xNN)
		{"unbraced non-utf8", `\xac\xed`, true},
		{"unbraced utf8", `\x41\x42`, false}, // A, B

		// Braced hex escapes (\x{NN})
		{"braced non-utf8", `\x{ac}\x{ed}`, true},
		{"braced utf8", `\x{41}\x{42}`, false},
		{"braced single hex digit", `\x{a}`, false}, // 0x0a is valid utf8 (newline)
		{"braced single hex digit non-utf8", `\x{80}`, true},
		{"braced uppercase hex", `\x{BC}\x{BE}`, true},
		{"braced multi-byte unicode codepoint", `\x{00e9}`, false}, // é - valid utf8

		// Mixed braced and unbraced
		{"mixed braced and unbraced non-utf8", `\xbc[^\x{be}>]`, true},
		{"mixed unbraced and braced non-utf8", `\x{bc}[^\xbe>]`, true},

		// Patterns resembling CRS 941310 v4.25.0
		{"CRS 941310 main pattern", `\x{bc}[^>\x{be}]*[>\x{be}]|<[^\x{be}]*\x{be}`, true},
		{"CRS 941310 chained pattern", `\x{bc}[\s\x0b]*/[\s\x0b]*[^>\x{be}]*[>\x{be}]|<[\s\x0b]*/[\s\x0b]*[^\x{be}]*\x{be}`, true},

		// Edge cases
		{"backslash at end", `test\`, false},
		{"backslash x at end", `test\x`, false},
		{"truncated braced hex no closing brace", `\x{bc`, false},
		{"empty braces", `\x{}`, false},
		{"braced hex with surrounding text", `foo\x{ff}bar`, true},
		{"backslash not followed by x", `\n\t\r`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesArbitraryBytes(tc.expr); got != tc.want {
				t.Errorf("matchesArbitraryBytes(%q) = %v, want %v", tc.expr, got, tc.want)
			}
		})
	}
}
