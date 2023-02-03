// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasilibs

import (
	"github.com/corazawaf/coraza/v3/operators"
	"github.com/corazawaf/coraza/v3/rules"
	"github.com/wasilibs/go-libinjection"
)

type detectXSS struct{}

var _ rules.Operator = (*detectXSS)(nil)

func newDetectXSS(rules.OperatorOptions) (rules.Operator, error) {
	return &detectXSS{}, nil
}

func (o *detectXSS) Evaluate(_ rules.TransactionState, value string) bool {
	return libinjection.IsXSS(value)
}

// RegisterXSS registers the detect_xss operator using a WASI implementation instead of Go.
func RegisterXSS() {
	operators.Register("detectXSS", newDetectXSS)
}
