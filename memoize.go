// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasilibs

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
)

// memoizeKey builds the cache key for an operator's compiled artifact from the
// operator name and the content the artifact is built from, as Coraza does
// since GHSA-wc2q-x24m-8c5f. The memoizer's cache is shared by every WAF in the
// process, so a key that names where the content came from (a dataset name)
// instead of the content itself hands one WAF another WAF's matcher, and a key
// without the operator name lets two operators with the same argument collide
// on an entry of the wrong type.
//
// Every key is prefixed with "wasilibs/" so it never matches one of Coraza's
// own keys, whose entries hold different types. Each element is
// length-prefixed so that a list crafted to hash like another list cannot
// take over its matcher.
func memoizeKey(op string, content ...string) string {
	h := sha256.New()
	var n [binary.MaxVarintLen64]byte
	for _, c := range content {
		h.Write(n[:binary.PutUvarint(n[:], uint64(len(c)))])
		_, _ = io.WriteString(h, c)
	}
	return "wasilibs/" + op + ":" + hex.EncodeToString(h.Sum(nil))
}
