# Code data flow guardrail

Creates a guardrail that detects data flow patterns in R code using AST
analysis. Can block environment access, network operations, file writes,
and file reads.

## Usage

``` r
guard_code_dataflow(
  block_env_access = TRUE,
  block_network = TRUE,
  block_file_write = TRUE,
  block_file_read = FALSE
)
```

## Arguments

- block_env_access:

  Logical(1). Block environment variable access (`Sys.getenv`,
  `Sys.setenv`, `Sys.unsetenv`, `.GlobalEnv`,
  [`globalenv()`](https://rdrr.io/r/base/environment.html),
  [`parent.env()`](https://rdrr.io/r/base/environment.html)). Default
  `TRUE`.

- block_network:

  Logical(1). Block network operations
  ([`url()`](https://rdrr.io/r/base/connections.html), `download.file`,
  `curl::*`, `httr::*`, `httr2::*`, `socketConnection`). Default `TRUE`.

- block_file_write:

  Logical(1). Block file write operations (`writeLines`, `write.csv`,
  `write.table`, `saveRDS`, `save`, `cat(..., file=)`, `sink`,
  `file.create`, `file.copy`, `file.rename`, `unlink`, `file.remove`).
  Default `TRUE`.

- block_file_read:

  Logical(1). Block file read operations (`readLines`, `read.csv`,
  `read.table`, `readRDS`, `load`, `scan`, `source`, `file`). Default
  `FALSE`.

## Value

A guardrail object of class `"secureguard"` with type `"code"`.

## Examples

``` r
g <- guard_code_dataflow()
run_guardrail(g, "x <- 1 + 2")
#> <guardrail_result> PASS
run_guardrail(g, "Sys.getenv('SECRET_KEY')")
#> <guardrail_result> FAIL
#> Reason: Data flow violation(s): Sys.getenv
```
