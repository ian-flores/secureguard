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

A list of class `"guardrail_result"`.
