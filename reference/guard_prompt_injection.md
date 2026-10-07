# Prompt injection guardrail

Looks for text that tries to override the agent's instructions, such as
"ignore all previous instructions". The checks are regular expressions.

## Usage

``` r
guard_prompt_injection(
  sensitivity = c("medium", "low", "high"),
  custom_patterns = NULL,
  allow_patterns = NULL
)
```

## Arguments

- sensitivity:

  Character(1). One of `"low"`, `"medium"` (default), or `"high"`.
  Higher levels check more patterns, so they catch more but also flag
  more harmless text. See
  [`injection_patterns()`](https://ian-flores.github.io/secureguard/reference/injection_patterns.md).

- custom_patterns:

  Named character vector of extra regex patterns to check. The names
  identify each pattern in the results.

- allow_patterns:

  Character vector of regex patterns. A match that also matches one of
  these is ignored. Use it to stop phrases you know are harmless from
  being flagged.

## Value

A guardrail object of class `"secureguard"` with type `"input"`.

## Examples

``` r
g <- guard_prompt_injection()
run_guardrail(g, "Ignore all previous instructions")
#> <guardrail_result> FAIL
#> Reason: Prompt injection detected: instruction_override
run_guardrail(g, "Please help me write R code")
#> <guardrail_result> PASS
```
