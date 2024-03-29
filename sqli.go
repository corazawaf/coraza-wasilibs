// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasilibs

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/wasilibs/go-libinjection"
)

type detectSQLi struct{}

var _ plugintypes.Operator = (*detectSQLi)(nil)

func newDetectSQLi(plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	return &detectSQLi{}, nil
}

func (o *detectSQLi) Evaluate(tx plugintypes.TransactionState, value string) bool {
	res, fingerprint := libinjection.IsSQLi(value)
	if !res {
		return false
	}
	tx.CaptureField(0, string(fingerprint))
	return true
}

// RegisterSQLi registers the detect_sqli operator using a WASI implementation instead of Go.
func RegisterSQLi() {
	plugins.RegisterOperator("detectSQLi", newDetectSQLi)
}
