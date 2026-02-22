# Create a guardrail result

Structured return value from guardrail checks.

## Usage

``` r
guardrail_result(
  pass,
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

## Value

An S7 object of class `guardrail_result`.

## Examples

``` r
# A passing result
r <- guardrail_result(pass = TRUE)
r@pass
#> [1] TRUE

# A failing result with details
r <- guardrail_result(
  pass = FALSE,
  reason = "Blocked function detected",
  details = list(blocked_calls = "system")
)
r@reason
#> [1] "Blocked function detected"
r@details
#> $blocked_calls
#> [1] "system"
#> 
```
