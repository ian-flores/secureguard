# Input PII guardrail

Creates a guardrail that detects personally identifiable information in
input text and either blocks or warns.

## Usage

``` r
guard_input_pii(
  detect = c("ssn", "email", "phone", "credit_card"),
  action = c("block", "warn")
)
```

## Arguments

- detect:

  Character vector of PII types to look for. Default:
  `c("ssn", "email", "phone", "credit_card")`. See
  [`pii_patterns()`](https://ian-flores.github.io/secureguard/reference/pii_patterns.md)
  for valid types.

- action:

  Character(1). What to do when PII is found: `"block"` (default) fails
  the check, `"warn"` passes with advisory warnings.

## Value

A guardrail object of class `"secureguard"` with type `"input"`.

## Examples

``` r
g <- guard_input_pii()
run_guardrail(g, "My SSN is 123-45-6789")
#> <guardrail_result> FAIL
#> Reason: PII detected in input: ssn (1)
run_guardrail(g, "Please help me with R code")
#> <guardrail_result> PASS
```
