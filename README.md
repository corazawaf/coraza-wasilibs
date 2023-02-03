## Coraza WASI plugins

This package provides operator plugins using implementations that are compiled from other
languages like C, C++, Rust to WebAssembly. The pure Go WebAssembly runtime wazero is used
so there is no limitation on the Go application that can use the plugins - notably, cgo is
not required.

Performance improves significantly, at the expense of slightly higher memory usage. You should
always benchmark to confirm improvements in your use cases but it should generally be helpful
to enable this plugin.

Note, it is possible to use cgo for some more performance improvement at the cost of requiring
build tooling. See the READMEs of the implementation libraries for details on how to enable it.
In general, pure Go should run fine.

### Usage

Install the package as normal:

```bash
go get github.com/corazawaf/coraza-wasilibs
```

and before initializing `WAF`, for example in an `init()` function, call `Register`.

```go
package main

import (
    "github.com/corazawaf/coraza-wasilibs"
)

func init() {
	wasilibs.Register()
}
```

Alternatively, you can use the `RegisterX` functions to register the plugins individually.


```go
package main

import (
    "github.com/corazawaf/coraza-wasilibs"
)

func init() {
	wasilibs.RegisterPM()
	wasilibs.RegisterRX()
	wasilibs.RegisterSQLi()
	wasilibs.RegisterXSS()
}
```

### Operators

The overridden operators are

- `rx`: Uses [re2](https://github.com/wasilibs/go-re2)
- `pm`: Uses [BurntMill/aho-corasick](https://github.com/wasilibs/go-aho-corasick)
- `detect_sqli`, `detect_xss`: Uses [libinjection](https://github.com/wasilibs/go-libinjection)

Note that `wasilibs.Register()` does not enable the `detect_sqli` plugin as it does not
outperform the default implementation.

### Performance

Benchmarks are run against every commit in the [bench](https://github.com/corazawaf/coraza-wasilibs/actions/workflows/bench.yaml)
workflow. GitHub action runners are highly virtualized and do not have stable performance across runs, but the relative
numbers within a run should still be informative.

The benchmarks set up an HTTP server with the WAF enabled and CoreRuleSet loaded.

```
WAF/FTW-2           34.6s ± 1%   32.5s ± 1%   -5.91%  (p=0.008 n=5+5)
WAF/POST/1-2       3.53ms ± 1%  3.93ms ± 2%  +11.39%  (p=0.008 n=5+5)
WAF/POST/1000-2    19.5ms ± 1%   5.6ms ± 5%  -71.14%  (p=0.008 n=5+5)
WAF/POST/10000-2    177ms ± 1%    16ms ± 2%  -90.81%  (p=0.008 n=5+5)
WAF/POST/100000-2   1.75s ± 0%   0.12s ± 1%  -93.23%  (p=0.008 n=5+5)
```

FTW issues the standard CRS regression test suite, which is composed of a variety of generally small requests.
We see that the version with plugins is faster for this baseline case.

POST issues a request of fixed payload of various sizes to the server. We see that only in the case of a 1-byte
payload does the default implementation outperform. For larger payloads, the version with wasilibs plugins
greatly outperforms.
