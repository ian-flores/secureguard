# Code AST analysis guardrail

Creates a guardrail that inspects R code for calls to blocked functions.
Uses AST walking to detect direct calls and optionally indirect
invocation via [`do.call()`](https://rdrr.io/r/base/do.call.html).

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
  Names can include namespace prefixes (e.g. `"processx::run"`).

- allow_namespaces:

  Character vector of package prefixes to allow even if a function from
  that package appears in `blocked_functions`. For example,
  `allow_namespaces = "dplyr"` would allow `dplyr::filter`.

- detect_indirect:

  Logical(1). If `TRUE` (default), also detect indirect calls via
  `do.call("system", ...)` where the first argument is a string literal
  matching a blocked function.

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
