# Code AST analysis guardrail

Parses R code and fails if it calls a blocked function. Because it reads
the parsed code rather than the text, it also finds calls made through
`do.call("system", ...)` and namespaced calls like
[`base::system()`](https://rdrr.io/r/base/system.html).

## Usage

``` r
guard_code_analysis(
  blocked_functions = default_blocked_functions(),
  allow_namespaces = NULL,
  detect_indirect = TRUE
)
```

## Arguments

- blocked_functions:

  Character vector of function names to block. Defaults to
  [`default_blocked_functions()`](https://ian-flores.github.io/secureguard/reference/default_blocked_functions.md).
  A bare name like `"system"` also blocks
  [`base::system()`](https://rdrr.io/r/base/system.html). A name with a
  package prefix, like `"processx::run"`, blocks only that package's
  function.

- allow_namespaces:

  Character vector of package names. Namespaced calls into these
  packages are allowed even if the function is in `blocked_functions`.
  For example, `allow_namespaces = "processx"` lets
  [`processx::run()`](http://processx.r-lib.org/reference/run.md)
  through.

- detect_indirect:

  Logical(1). If `TRUE` (default), also catch calls like
  `do.call("system", ...)`, where the first argument is a string naming
  a blocked function.

## Value

A guardrail object of class `"secureguard"` with type `"code"`.

## Examples

``` r
g <- guard_code_analysis()
run_guardrail(g, "x <- 1 + 2")
#> <guardrail_result> PASS
run_guardrail(g, "system('ls')")
#> <guardrail_result> FAIL
#> Reason: Blocked function(s) detected: system
```
