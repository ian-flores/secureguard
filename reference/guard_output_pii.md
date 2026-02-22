# PII output guardrail

Creates a guardrail that scans output for personally identifiable
information (PII).

## Usage

``` r
guard_output_pii(detect = NULL, action = c("block", "redact", "warn"))
```

## Arguments

- detect:

  Character vector of PII types to detect. Defaults to all types from
  [`pii_patterns()`](https://ian-flores.github.io/secureguard/reference/pii_patterns.md):
  `"ssn"`, `"email"`, `"phone"`, `"credit_card"`, `"ip_address"`.

- action:

  Character(1). What to do when PII is found:

  - `"block"` (default): fail the check.

  - `"redact"`: pass but replace PII with `[REDACTED_SSN]` etc.

  - `"warn"`: pass with advisory warnings.

## Value

A guardrail object of class `"secureguard"` with type `"output"`.

## Examples

``` r
g <- guard_output_pii()
run_guardrail(g, "My SSN is 123-45-6789")
#> <guardrail_result> FAIL
#> Reason: PII detected in output: ssn

g_redact <- guard_output_pii(action = "redact")
result <- run_guardrail(g_redact, "My SSN is 123-45-6789")
result@details$redacted_text
#> [1] "My SSN is [REDACTED_SSN]"
```
