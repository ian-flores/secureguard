# Secret output guardrail

Creates a guardrail that scans output for secrets and credentials.

## Usage

``` r
guard_output_secrets(detect = NULL, action = c("block", "redact", "warn"))
```

## Arguments

- detect:

  Character vector of secret types to detect. Defaults to all types from
  [`secret_patterns()`](https://ian-flores.github.io/secureguard/reference/secret_patterns.md):
  `"api_key"`, `"aws_key"`, `"password"`, `"token"`, `"private_key"`,
  `"github_token"`.

- action:

  Character(1). What to do when secrets are found:

  - `"block"` (default): fail the check.

  - `"redact"`: pass but replace secrets with `[REDACTED_API_KEY]` etc.

  - `"warn"`: pass with advisory warnings.

## Value

A guardrail object of class `"secureguard"` with type `"output"`.

## Examples

``` r
g <- guard_output_secrets()
run_guardrail(g, "AKIAIOSFODNN7EXAMPLE")
#> <guardrail_result> FAIL
#> Reason: Secrets detected in output: aws_key

g_redact <- guard_output_secrets(action = "redact")
result <- run_guardrail(g_redact, "AKIAIOSFODNN7EXAMPLE")
result$details$redacted_text
#> [1] "[REDACTED_AWS_KEY]"
```
