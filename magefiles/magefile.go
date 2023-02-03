package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// Test runs unit tests
func Test() error {
	return sh.RunV("go", "test", "-v", "-timeout=20m", "./waf")
}

func Format() error {
	if err := sh.RunV("go", "run", fmt.Sprintf("mvdan.cc/gofumpt@%s", gofumptVersion), "-l", "-w", "."); err != nil {
		return err
	}
	if err := sh.RunV("go", "run", fmt.Sprintf("github.com/rinchsan/gosimports/cmd/gosimports@%s", gosImportsVer), "-w",
		"-local", "github.com/corazawaf/coraza-wasilibs",
		"."); err != nil {
		return nil
	}
	return nil
}

func Lint() error {
	return sh.RunV("go", "run", fmt.Sprintf("github.com/golangci/golangci-lint/cmd/golangci-lint@%s", golangCILintVer), "run")
}

// Check runs lint and tests.
func Check() {
	mg.SerialDeps(Lint, Test)
}

// WAFBench runs benchmarks in the default configuration for a Go app, using wasilibs.
func WAFBench() error {
	return sh.RunV("go", benchArgs("./waf", 1, benchModeWASILibs)...)
}

// WAFBenchDefault runs benchmarks using the default implementations.
func WAFBenchDefault() error {
	return sh.RunV("go", benchArgs("./waf", 1, benchModeDefault)...)
}

// WAFBenchAll runs all benchmark types and outputs with benchstat.
func WAFBenchAll() error {
	if err := os.MkdirAll("build", 0o755); err != nil {
		return err
	}

	fmt.Println("Executing wasilibs benchmarks")
	wasilibs, err := sh.Output("go", benchArgs("./waf", 5, benchModeWASILibs)...)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join("build", "wafbench.txt"), []byte(wasilibs), 0o644); err != nil {
		return err
	}

	fmt.Println("Executing default benchmarks")
	def, err := sh.Output("go", benchArgs("./waf", 5, benchModeDefault)...)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join("build", "wafbench_default.txt"), []byte(def), 0o644); err != nil {
		return err
	}

	return sh.RunV("go", "run", fmt.Sprintf("golang.org/x/perf/cmd/benchstat@%s", benchstatVer),
		"build/wafbench_default.txt", "build/wafbench.txt")
}

var Default = Test

type benchMode int

const (
	benchModeWASILibs benchMode = iota
	benchModeDefault
)

func benchArgs(pkg string, count int, mode benchMode) []string {
	args := []string{"test", "-bench=.", "-run=^$", "-v", "-timeout=60m"}
	if count > 0 {
		args = append(args, fmt.Sprintf("-count=%d", count))
	}
	switch mode {
	case benchModeDefault:
		args = append(args, "-tags=wasilibs_bench_default")
	}
	args = append(args, pkg)

	return args
}
