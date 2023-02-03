// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !wasilibs_bench_default

package waf

import wasilibs "github.com/corazawaf/coraza-wasilibs"

func init() {
	wasilibs.Register()
}
