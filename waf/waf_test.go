// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package waf

import (
	"bufio"
	_ "embed"
	b64 "encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/bmatcuk/doublestar/v4"
	coreruleset "github.com/corazawaf/coraza-coreruleset"
	crstests "github.com/corazawaf/coraza-coreruleset/tests"
	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/output"
	"github.com/coreruleset/go-ftw/runner"
	"github.com/coreruleset/go-ftw/test"
	"github.com/rs/zerolog"
)

//go:embed coraza.conf-recommended
var confRecommended string

func TestWAF(t *testing.T) {
	errorLogPath, server := setupWAF(t)
	defer server.Close()

	runFTW(t, errorLogPath, server)
}

func BenchmarkWAF(b *testing.B) {
	errorLogPath, server := setupWAF(b)
	defer server.Close()

	b.Run("FTW", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			runFTW(b, errorLogPath, server)
		}
	})

	for _, size := range []int{1, 1000, 10000, 100000} {
		payload := strings.Repeat("a", size)
		b.Run(fmt.Sprintf("POST/%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := http.Post(server.URL+"/anything", "text/plain", strings.NewReader(payload))
				if err != nil {
					b.Error(err)
				}
			}
		})
	}
}

func runFTW(tb testing.TB, errorLogPath string, server *httptest.Server) {
	tb.Helper()

	var tests []test.FTWTest
	err := doublestar.GlobWalk(crstests.FS, "**/*.yaml", func(path string, d os.DirEntry) error {
		yaml, err := fs.ReadFile(crstests.FS, path)
		if err != nil {
			return err
		}
		t, err := test.GetTestFromYaml(yaml)
		if err != nil {
			return err
		}
		tests = append(tests, t)
		return nil
	})
	if err != nil {
		tb.Fatal(err)
	}
	if len(tests) == 0 {
		tb.Fatal("no tests found")
	}

	u, _ := url.Parse(server.URL)
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	// TODO(anuraaga): Don't use global config for FTW for better support of programmatic.
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	ftwConf, err := config.NewConfigFromFile(".ftw.yml")
	if err != nil {
		tb.Fatal(err)
	}
	ftwConf.LogFile = errorLogPath
	ftwConf.TestOverride.Input.DestAddr = &host
	ftwConf.TestOverride.Input.Port = &port

	res, err := runner.Run(ftwConf, tests, runner.RunnerConfig{
		ShowTime: false,
	}, output.NewOutput("quiet", os.Stdout))
	if err != nil {
		tb.Fatal(err)
	}

	if len(res.Stats.Failed) > 0 {
		tb.Errorf("failed tests: %v", res.Stats.Failed)
	}
}

func setupWAF(tb testing.TB) (string, *httptest.Server) {
	tb.Helper()

	conf := coraza.NewWAFConfig()
	customTestingConfig := `
SecResponseBodyMimeType text/plain
SecDefaultAction "phase:3,log,auditlog,pass"
SecDefaultAction "phase:4,log,auditlog,pass"
SecDefaultAction "phase:5,log,auditlog,pass"
# Rule 900005 from https://github.com/coreruleset/coreruleset/blob/v4.0/dev/tests/regression/README.md#requirements
SecAction "id:900005,\
  phase:1,\
  nolog,\
  pass,\
  ctl:ruleEngine=DetectionOnly,\
  ctl:ruleRemoveById=910000,\
  setvar:tx.blocking_paranoia_level=4,\
  setvar:tx.crs_validate_utf8_encoding=1,\
  setvar:tx.arg_name_length=100,\
  setvar:tx.arg_length=400,\
  setvar:tx.total_arg_length=64000,\
  setvar:tx.max_num_args=255,\
  setvar:tx.max_file_size=64100,\
  setvar:tx.combined_file_sizes=65535"
# Write the value from the X-CRS-Test header as a marker to the log
# Requests with X-CRS-Test header will not be matched by any rule. See https://github.com/coreruleset/go-ftw/pull/133
SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" \
  "id:999999,\
  phase:1,\
  pass,\
  t:none,\
  log,\
  msg:'X-CRS-Test %{MATCHED_VAR}',\
  ctl:ruleRemoveById=1-999999"
`
	// Configs are loaded with a precise order:
	// 1. Coraza config
	// 2. Custom Rules for testing and eventually overrides of the basic Coraza config
	// 3. CRS basic config
	// 4. CRS rules (on top of which are applied the previously defined SecDefaultAction)
	conf = conf.
		WithRootFS(coreruleset.FS).
		WithDirectives(confRecommended).
		WithDirectives(customTestingConfig).
		WithDirectives("Include @crs-setup.conf.example").
		WithDirectives("Include @owasp_crs/*.conf")

	errorPath := filepath.Join(tb.TempDir(), "error.log")
	errorFile, err := os.Create(errorPath)
	if err != nil {
		tb.Fatalf("failed to create error log: %v", err)
	}
	errorWriter := bufio.NewWriter(errorFile)
	conf = conf.WithErrorCallback(func(rule types.MatchedRule) {
		msg := rule.ErrorLog() + "\n"
		if _, err := io.WriteString(errorWriter, msg); err != nil {
			tb.Fatal(err)
		}
		if err := errorWriter.Flush(); err != nil {
			tb.Fatal(err)
		}
	})

	waf, err := coraza.NewWAF(conf)
	if err != nil {
		tb.Fatal(err)
	}

	s := httptest.NewServer(txhttp.WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		w.Header().Set("Content-Type", "text/plain")
		switch {
		case r.URL.Path == "/anything":
			body, err := io.ReadAll(r.Body)
			// Emulated httpbin behaviour: /anything endpoint acts as an echo server, writing back the request body
			if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
				// Tests 954120-1 and 954120-2 are the only two calling /anything with a POST and payload is urlencoded
				if err != nil {
					tb.Fatalf("handler can not read request body: %v", err)
				}
				urldecodedBody, err := url.QueryUnescape(string(body))
				if err != nil {
					tb.Fatalf("handler can not unescape urlencoded request body: %v", err)
				}
				fmt.Fprintf(w, urldecodedBody)
			} else {
				_, err = w.Write(body)
			}

		case strings.HasPrefix(r.URL.Path, "/base64/"):
			// Emulated httpbin behaviour: /base64 endpoint write the decoded base64 into the response body
			b64Decoded, err := b64.StdEncoding.DecodeString(strings.TrimPrefix(r.URL.Path, "/base64/"))
			if err != nil {
				tb.Fatalf("handler can not decode base64: %v", err)
			}
			fmt.Fprintf(w, string(b64Decoded))
		default:
			// Common path "/status/200" defaults here
			fmt.Fprintf(w, "Hello!")
		}
	})))
	return errorPath, s
}
