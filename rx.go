// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasilibs

import (
	"fmt"
	"regexp/syntax"
	"strconv"
	"strings"
	"unicode/utf8"

	re2 "github.com/wasilibs/go-re2"
	"github.com/wasilibs/go-re2/experimental"

	"github.com/corazawaf/coraza-wasilibs/internal/memoize"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type rx struct {
	re           *re2.Regexp
	minLen       int
	prefilter    func(string) bool
	exactMatch   string
	exactMatchCI bool
}

type rxCompiled struct {
	re           *re2.Regexp
	minLen       int
	prefilter    func(string) bool
	exactMatch   string
	exactMatchCI bool
}

var _ plugintypes.Operator = (*rx)(nil)

func newRX(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	var data string
	if shouldNotUseMultilineRegexesOperatorByDefault {
		data = fmt.Sprintf("(?s)%s", options.Arguments)
	} else {
		data = fmt.Sprintf("(?sm)%s", options.Arguments)
	}

	if matchesArbitraryBytes(data) {
		return newBinaryRX(options)
	}

	cacheKey := fmt.Sprintf("rx:%v:%s", options.RxPreFilterEnabled, data)
	compiled, err := memoizeDo(options.Memoizer, cacheKey, func() (any, error) {
		re, err := re2.Compile(data)
		if err != nil {
			return nil, err
		}
		c := &rxCompiled{re: re}
		if options.RxPreFilterEnabled {
			c.minLen = minMatchLength(data)
			c.prefilter = prefilterFunc(data)
			// Gap 2: detect pure ^literal$ patterns and bypass the NFA entirely.
			// Parse options.Arguments (the original, un-wrapped pattern) so that
			// ^ is OpBeginText and $ is OpEndText — without the (?m) flag that
			// newRX prepends, which would convert them to OpBeginLine/OpEndLine
			// and make position-0 reasoning unsound.
			if origParsed, err2 := syntax.Parse(options.Arguments, syntax.Perl); err2 == nil {
				if lit, ci := extractExactMatch(origParsed.Simplify()); lit != "" {
					c.exactMatch = lit
					c.exactMatchCI = ci
				}
			}
		}
		return c, nil
	})
	if err != nil {
		return nil, err
	}
	c := compiled.(*rxCompiled)
	return &rx{
		re:           c.re,
		minLen:       c.minLen,
		prefilter:    c.prefilter,
		exactMatch:   c.exactMatch,
		exactMatchCI: c.exactMatchCI,
	}, nil
}

func (o *rx) Evaluate(tx plugintypes.TransactionState, value string) bool {
	if len(value) < o.minLen {
		return false
	}
	if o.prefilter != nil && !o.prefilter(value) {
		return false
	}
	// Gap 2: exact-match bypass for patterns like ^Upload$ — skip the NFA entirely.
	// The \n guard protects against multi-line inputs where (?m)$ matches
	// before a newline (e.g. "Upload\nmore" would satisfy (?sm)^Upload$).
	if o.exactMatch != "" && !strings.ContainsRune(value, '\n') {
		if o.exactMatchCI {
			return strings.EqualFold(value, o.exactMatch)
		}
		return value == o.exactMatch
	}

	if tx.Capturing() {
		match := o.re.FindStringSubmatchIndex(value)
		if match == nil {
			return false
		}
		for i := 0; i < len(match)/2; i++ {
			if i == 9 {
				return true
			}
			if match[2*i] >= 0 {
				tx.CaptureField(i, value[match[2*i]:match[2*i+1]])
			} else {
				tx.CaptureField(i, "")
			}
		}
		return true
	} else {
		return o.re.MatchString(value)
	}
}

type binaryRX struct {
	re *re2.Regexp
}

var _ plugintypes.Operator = (*binaryRX)(nil)

func newBinaryRX(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	re, err := memoizeDo(options.Memoizer, data, func() (any, error) { return experimental.CompileLatin1(data) })
	if err != nil {
		return nil, err
	}
	return &binaryRX{re: re.(*re2.Regexp)}, nil
}

func (o *binaryRX) Evaluate(tx plugintypes.TransactionState, value string) bool {
	if tx.Capturing() {
		match := o.re.FindStringSubmatch(value)
		if len(match) == 0 {
			return false
		}
		for i, c := range match {
			if i == 9 {
				return true
			}
			tx.CaptureField(i, c)
		}
		return true
	} else {
		return o.re.MatchString(value)
	}
}

// RegisterRX registers the rx operator using a WASI implementation instead of Go.
func RegisterRX() {
	plugins.RegisterOperator("rx", newRX)
}

func memoizeDo(m plugintypes.Memoizer, key string, fn func() (any, error)) (any, error) {
	if m != nil {
		return m.Do(key, fn)
	}
	return memoize.Do(key, fn)
}

// matchesArbitraryBytes checks for control sequences for byte matches in the expression.
// If the sequences are not valid utf8, it returns true.
func matchesArbitraryBytes(expr string) bool {
	decoded := make([]byte, 0, len(expr))
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if c != '\\' {
			decoded = append(decoded, c)
			continue
		}
		if i+3 >= len(expr) {
			decoded = append(decoded, expr[i:]...)
			break
		}
		if expr[i+1] != 'x' {
			decoded = append(decoded, expr[i])
			continue
		}

		sub := expr[i:]
		advance := 3
		if len(sub) >= 6 && sub[2] == '{' {
			if end := strings.IndexByte(sub, '}'); end != -1 {
				sub = `\x` + sub[3:end]
				advance = end
			}
		}

		v, mb, _, err := strconv.UnquoteChar(sub, 0)
		if err != nil || mb {
			decoded = append(decoded, expr[i])
			continue
		}

		decoded = append(decoded, byte(v))
		i += advance
	}

	return !utf8.Valid(decoded)
}
