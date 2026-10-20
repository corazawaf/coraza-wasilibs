// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasilibs

import (
	"fmt"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestMemoizeKey(t *testing.T) {
	if memoizeKey("pm", "a", "b") == memoizeKey("pmFromDataset", "a", "b") {
		t.Error("different operators share a key")
	}
	if memoizeKey("pm", "a\x00b") == memoizeKey("pm", "a", "b") {
		t.Error("an element containing a NUL byte hashes like two elements")
	}
	if memoizeKey("pm", "ab", "c") == memoizeKey("pm", "a", "bc") {
		t.Error("lists split at different points share a key")
	}
}

// newWAFNoPanic turns a panic in NewWAF, such as a failed type assertion on a
// memoized entry, into an error.
func newWAFNoPanic(directives string) (waf coraza.WAF, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("NewWAF panicked: %v", r)
		}
	}()
	return coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
}

func matchesArg(waf coraza.WAF, value string) bool {
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessURI("/?a="+value, "GET", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	return len(tx.MatchedRules()) > 0
}

// TestMemoizeDatasetPerWAF checks that two WAFs defining the same dataset name
// with different entries each enforce their own list. The memoizer's cache is
// shared by every WAF in the process, so a key naming the dataset instead of
// its content hands the second WAF the first WAF's matcher.
func TestMemoizeDatasetPerWAF(t *testing.T) {
	RegisterPM()

	rules := "SecDataset shared `\n%s\n`\nSecRule ARGS \"@pmFromDataset shared\" \"id:1,phase:1,deny\""
	first, err := newWAFNoPanic(fmt.Sprintf(rules, "memo-alpha"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := newWAFNoPanic(fmt.Sprintf(rules, "memo-bravo"))
	if err != nil {
		t.Fatal(err)
	}

	if !matchesArg(first, "memo-alpha") || matchesArg(first, "memo-bravo") {
		t.Error("first WAF does not enforce its own list")
	}
	if !matchesArg(second, "memo-bravo") {
		t.Error("second WAF does not match its own entry")
	}
	if matchesArg(second, "memo-alpha") {
		t.Error("second WAF enforces the first WAF's list")
	}
}

// wrongTypeMemoizer returns a value of the wrong type for every key, as the
// shared cache does when another component stored its own entry under a key
// wasilibs uses.
type wrongTypeMemoizer struct{}

func (wrongTypeMemoizer) Do(string, func() (any, error)) (any, error) { return 42, nil }

func TestMemoizeDoWrongType(t *testing.T) {
	v, err := memoizeDo(wrongTypeMemoizer{}, "k", func() (string, error) { return "built", nil })
	if err != nil {
		t.Fatal(err)
	}
	if v != "built" {
		t.Errorf("got %q, want the value built without the cache", v)
	}
}

// TestMemoizeKeysDoNotCollide checks that operators with the same argument
// never get each other's memoized entry, which fails a type assertion and
// panics in NewWAF. The Coraza rows need a Coraza release after v3.8.1, which
// namespaces Coraza's own keys; before that, Coraza panics when it finds a
// wasilibs entry under the raw string it uses as a key.
func TestMemoizeKeysDoNotCollide(t *testing.T) {
	RegisterPM()
	RegisterRX()

	// The cache outlives each subtest, so every Coraza row uses its own pattern.
	rxKey := func(p string) string { return memoizeKeyPrefix + "rx:false:(?sm)" + p }
	pmKey := func(p string) string { return memoizeKeyPrefix + memoizeKey("pm", p) }

	tests := []struct {
		name       string
		directives string
	}{
		{
			name:       "variable selector then @pm",
			directives: "SecRule ARGS:/memoselector/ \"@rx x\" \"id:1,phase:1,pass\"\nSecRule ARGS \"@pm memoselector\" \"id:2,phase:1,pass\"",
		},
		{
			name:       "@pm then variable selector",
			directives: "SecRule ARGS \"@pm memopmfirst\" \"id:1,phase:1,pass\"\nSecRule ARGS:/memopmfirst/ \"@rx x\" \"id:2,phase:1,pass\"",
		},
		{
			name:       "binary @rx then @pm",
			directives: "SecRule ARGS \"@rx \\xff\\xfe\" \"id:1,phase:1,pass\"\nSecRule ARGS \"@pm \\xff\\xfe\" \"id:2,phase:1,pass\"",
		},
		{
			name:       "Coraza directive then @rx",
			directives: "SecAuditLogRelevantStatus \"" + rxKey("memocorazarx1") + "\"\nSecRule ARGS \"@rx memocorazarx1\" \"id:1,phase:1,pass\"",
		},
		{
			name:       "@rx then Coraza directive",
			directives: "SecRule ARGS \"@rx memocorazarx2\" \"id:1,phase:1,pass\"\nSecAuditLogRelevantStatus \"" + rxKey("memocorazarx2") + "\"",
		},
		{
			name:       "Coraza directive then @pm",
			directives: "SecAuditLogRelevantStatus \"" + pmKey("memocorazapm1") + "\"\nSecRule ARGS \"@pm memocorazapm1\" \"id:1,phase:1,pass\"",
		},
		{
			name:       "@pm then Coraza directive",
			directives: "SecRule ARGS \"@pm memocorazapm2\" \"id:1,phase:1,pass\"\nSecAuditLogRelevantStatus \"" + pmKey("memocorazapm2") + "\"",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newWAFNoPanic(tc.directives); err != nil {
				t.Error(err)
			}
		})
	}
}
