// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasilibs

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"

	"github.com/corazawaf/coraza-wasilibs/internal/memoize"
)

// memoizeKeyPrefix namespaces every key wasilibs stores in the memoizer. In
// Coraza releases after v3.8.1, all of Coraza's own keys start with a prefix of
// their own ("regexp:", "rx:" or the operator name), so they never start with
// this one.
const memoizeKeyPrefix = "wasilibs/"

// memoizeKey builds the cache key for an operator's compiled artifact from the
// operator name and the content the artifact is built from, as Coraza does
// since GHSA-wc2q-x24m-8c5f. The memoizer's cache is shared by every WAF in the
// process, so a key that names where the content came from (a dataset name)
// instead of the content itself hands one WAF another WAF's matcher, and a key
// without the operator name lets two operators with the same argument collide
// on an entry of the wrong type.
//
// Each element is length-prefixed so that a list crafted to hash like another
// list cannot take over its matcher.
func memoizeKey(op string, content ...string) string {
	h := sha256.New()
	var n [binary.MaxVarintLen64]byte
	for _, c := range content {
		h.Write(n[:binary.PutUvarint(n[:], uint64(len(c)))])
		_, _ = io.WriteString(h, c)
	}
	return op + ":" + hex.EncodeToString(h.Sum(nil))
}

// memoizeDo returns the value cached under key, building it with fn on a miss.
// The key is namespaced with memoizeKeyPrefix. If the cached value is not a T,
// another component stored a different type under the same key, so the value
// is built again without the cache instead of failing a type assertion.
func memoizeDo[T any](m plugintypes.Memoizer, key string, fn func() (T, error)) (T, error) {
	key = memoizeKeyPrefix + key
	build := func() (any, error) { return fn() }

	var (
		v   any
		err error
	)
	if m != nil {
		v, err = m.Do(key, build)
	} else {
		v, err = memoize.Do(key, build)
	}
	if err != nil {
		var zero T
		return zero, err
	}
	if t, ok := v.(T); ok {
		return t, nil
	}
	return fn()
}
