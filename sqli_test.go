// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasilibs

import (
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func TestDetectSQLi(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// MySQL charset introducers, recognized since libinjection 4.0.2.
		{name: "charset introducer", input: "' OR NOT _utf8mb4''#", want: true},
		{name: "tautology", input: "1' OR '1'='1", want: true},
		{name: "benign", input: "hello world", want: false},
	}

	op, err := newDetectSQLi(plugintypes.OperatorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := op.Evaluate(newTestTx(t), tt.input); got != tt.want {
				t.Errorf("detectSQLi(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
