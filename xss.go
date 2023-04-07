// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasilibs

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/wasilibs/go-libinjection"
)

type detectXSS struct{}

var _ plugintypes.Operator = (*detectXSS)(nil)

func newDetectXSS(plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	return &detectXSS{}, nil
}

func (o *detectXSS) Evaluate(_ plugintypes.TransactionState, value string) bool {
	return libinjection.IsXSS(value)
}

// RegisterXSS registers the detect_xss operator using a WASI implementation instead of Go.
func RegisterXSS() {
	plugins.RegisterOperator("detectXSS", newDetectXSS)
}
