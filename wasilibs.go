// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasilibs

// Register registers the rx and detect_xss operators using WASI implementations
// instead of Go. It does not register the pm and detect_sqli operators, whose WASI
// implementations have not been found to outperform the Go ones. Call RegisterPM or
// RegisterSQLi to enable them explicitly.
func Register() {
	RegisterRX()
	RegisterXSS()
}
