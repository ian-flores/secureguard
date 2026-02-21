# Code dependency guardrail

Creates a guardrail that controls which packages can be used in R code.
Detects package usage via
[`library()`](https://rdrr.io/r/base/library.html),
[`require()`](https://rdrr.io/r/base/library.html), `pkg::fn`,
`pkg:::fn`, and [`loadNamespace()`](https://rdrr.io/r/base/ns-load.html)
calls.

## Usage

``` r
guard_code_dependencies(
  allowed_packages = NULL,
  denied_packages = NULL,
  allow_base = TRUE
)
```

## Arguments

- allowed_packages:

  Character vector of permitted package names (allowlist mode). If
  non-`NULL`, only these packages (plus base packages if
  `allow_base = TRUE`) are permitted. Cannot be used together with
  `denied_packages`.

- denied_packages:

  Character vector of denied package names (denylist mode). If
  non-`NULL`, these packages are blocked. Cannot be used together with
  `allowed_packages`.

- allow_base:

  Logical(1). If `TRUE` (default), base R packages (`base`, `utils`,
  `stats`, `methods`, `grDevices`, `graphics`, `datasets`) are always
  permitted regardless of allowlist/denylist.

## Value

A guardrail object of class `"secureguard"` with type `"code"`.

## Examples

``` r
g <- guard_code_dependencies(denied_packages = "processx")
run_guardrail(g, "library(dplyr)")
#> <guardrail_result> PASS
run_guardrail(g, "processx::run('ls')")
#> <guardrail_result> FAIL
#> Reason: Disallowed package(s): processx
```
