// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasilibs

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/corazawaf/coraza-wasilibs/internal/memoize"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	ahocorasick "github.com/wasilibs/go-aho-corasick"
)

type pm struct {
	matcher ahocorasick.AhoCorasick
}

var _ plugintypes.Operator = (*pm)(nil)

func newPM(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	data = strings.ToLower(data)
	dict := strings.Split(data, " ")
	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: true,
		MatchOnlyWholeWords:  false,
		MatchKind:            ahocorasick.LeftMostLongestMatch,
		DFA:                  true,
	})

	m, _ := memoize.Do(data, func() (interface{}, error) { return builder.Build(dict), nil })

	// TODO this operator is supposed to support snort data syntax: "@pm A|42|C|44|F"
	return &pm{matcher: m.(ahocorasick.AhoCorasick)}, nil
}

func (o *pm) Evaluate(tx plugintypes.TransactionState, value string) bool {
	return pmEvaluate(o.matcher, tx, value)
}

func pmEvaluate(matcher ahocorasick.AhoCorasick, tx plugintypes.TransactionState, value string) bool {
	if !tx.Capturing() {
		// Not capturing so just one match is enough.
		return len(matcher.FindN(value, 1)) > 0
	}

	var numMatches int
	for _, m := range matcher.FindN(value, 10) {
		tx.CaptureField(numMatches, value[m.Start():m.End()])
		numMatches++
	}

	return numMatches > 0
}

func newPMFromFile(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	path := options.Arguments

	data, err := loadFromFile(path, options.Path, options.Root)
	if err != nil {
		return nil, err
	}

	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		l := sc.Text()
		l = strings.TrimSpace(l)
		if len(l) == 0 {
			continue
		}
		if l[0] == '#' {
			continue
		}
		lines = append(lines, strings.ToLower(l))
	}

	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: true,
		MatchOnlyWholeWords:  false,
		MatchKind:            ahocorasick.LeftMostLongestMatch,
		DFA:                  false,
	})

	return &pm{matcher: builder.Build(lines)}, nil
}

var errEmptyPaths = errors.New("empty paths")

func loadFromFile(filepath string, paths []string, root fs.FS) ([]byte, error) {
	if path.IsAbs(filepath) {
		return fs.ReadFile(root, filepath)
	}

	if len(paths) == 0 {
		return nil, errEmptyPaths
	}

	// handling files by operators is hard because we must know the paths where we can
	// search, for example, the policy path or the binary path...
	// CRS stores the .data files in the same directory as the directives
	var (
		content []byte
		err     error
	)

	for _, p := range paths {
		absFilepath := path.Join(p, filepath)
		content, err = fs.ReadFile(root, absFilepath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			} else {
				return nil, err
			}
		}

		return content, nil
	}

	return nil, err
}

// RegisterPM registers the pm operator using a WASI implementation instead of Go.
func RegisterPM() {
	plugins.RegisterOperator("pm", newPM)
	plugins.RegisterOperator("pmFromFile", newPMFromFile)
}
