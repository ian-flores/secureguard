# S7 class: guardrail_result

An S7 value type representing a structured return value from guardrail
checks.

## Usage

``` r
guardrail_result_class(
  pass = logical(0),
  reason = NULL,
  warnings = character(0),
  details = list()
)
```

## Arguments

- pass:

  Logical(1). Did the check pass?

- reason:

  Character(1) or `NULL`. Why the check failed.

- warnings:

  Character vector of advisory warnings.

- details:

  Named list of additional information (e.g. matched patterns, redacted
  text).

## Examples

``` r
# Prefer guardrail_result() constructor over direct construction
r <- guardrail_result_class(pass = TRUE)
r@pass
#> [1] TRUE

r2 <- guardrail_result_class(
  pass = FALSE,
  reason = "blocked",
  warnings = "advisory note"
)
r2@reason
#> [1] "blocked"
```
