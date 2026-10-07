# Code data flow guardrail

Parses R code and fails if it reads environment variables, uses the
network, or reads or writes files. You can turn each of these off
separately. Namespaced calls such as
[`base::Sys.getenv()`](https://rdrr.io/r/base/Sys.getenv.html) are
caught too.

## Usage

``` r
guard_code_dataflow(
  block_env_access = TRUE,
  block_network = TRUE,
  block_file_write = TRUE,
  block_file_read = TRUE
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
  `TRUE`. Before secureguard 0.3.0 the default was `FALSE`, which meant
  code could still read a file and leak its contents while writes and
  network calls were blocked. Set it to `FALSE` if your code needs to
  read files.

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
