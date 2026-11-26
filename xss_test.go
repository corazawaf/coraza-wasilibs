// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasilibs

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func newTestTx(t *testing.T) plugintypes.TransactionState {
	t.Helper()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}
	return waf.NewTransaction().(plugintypes.TransactionState)
}

func TestDetectXSS(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// GHSA-r97g-xfh2-h3jj, fixed in libinjection 4.0.3: TAB and CR, raw or
		// encoded, hid the javascript: scheme.
		{name: "raw tab", input: "<a href=\"ja\tvascript:alert(1)\">", want: true},
		{name: "decimal tab", input: "<a href=\"ja&#9;vascript:alert(1)\">", want: true},
		{name: "named tab", input: "<a href=\"ja&Tab;vascript:alert(1)\">", want: true},
		{name: "raw cr", input: "<a href=\"ja\rvascript:alert(1)\">", want: true},
		{name: "decimal cr", input: "<a href=\"ja&#13;vascript:alert(1)\">", want: true},
		{name: "hex tab", input: "<a href=\"ja&#x9;vascript:alert(1)\">", want: true},
		{name: "hex cr", input: "<a href=\"ja&#x0D;vascript:alert(1)\">", want: true},
		{name: "zero-padded tab", input: "<a href=\"ja&#0009;vascript:alert(1)\">", want: true},
		{name: "plain javascript", input: "<a href=\"javascript:alert(1)\">", want: true},
		{name: "benign", input: "<a href=\"https://example.com\">", want: false},
	}

	op, err := newDetectXSS(plugintypes.OperatorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := op.Evaluate(newTestTx(t), tt.input); got != tt.want {
				t.Errorf("detectXSS(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
