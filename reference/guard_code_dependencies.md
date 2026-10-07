# Code dependency guardrail

Controls which packages R code may use. It finds packages loaded with
[`library()`](https://rdrr.io/r/base/library.html),
[`require()`](https://rdrr.io/r/base/library.html), or
[`loadNamespace()`](https://rdrr.io/r/base/ns-load.html), and packages
called with `pkg::fn` or `pkg:::fn`.

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

  Character vector of package names to allow. If set, only these
  packages (plus base packages if `allow_base = TRUE`) may be used.
  Cannot be used together with `denied_packages`.

- denied_packages:

  Character vector of package names to block. If set, every other
  package is allowed. Cannot be used together with `allowed_packages`.

- allow_base:

  Logical(1). If `TRUE` (default), base R packages (`base`, `utils`,
  `stats`, `methods`, `grDevices`, `graphics`, `datasets`) are always
  allowed, whatever the other two arguments say.

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
