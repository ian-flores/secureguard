# Entropy output guardrail

Creates a guardrail that scans output for high-entropy substrings that
may indicate leaked secrets, tokens, or keys.

## Usage

``` r
guard_output_entropy(
  min_length = 20L,
  base64_threshold = 4.5,
  hex_threshold = 3,
  action = c("block", "redact", "warn")
)
```

## Arguments

- min_length:

  Integer(1). Minimum token length to check (default 20).

- base64_threshold:

  Numeric(1). Entropy threshold for base64-like strings (default 4.5).

- hex_threshold:

  Numeric(1). Entropy threshold for hex-like strings (default 3.0).

- action:

  Character(1). What to do when high-entropy strings are found:

  - `"block"` (default): fail the check.

  - `"redact"`: pass but replace high-entropy tokens with
    `[HIGH_ENTROPY]`.

  - `"warn"`: pass with advisory warnings.

## Value

A guardrail object of class `"secureguard"` with type `"output"`.

## See also

[`shannon_entropy()`](https://ian-flores.github.io/secureguard/reference/shannon_entropy.md),
[`is_high_entropy()`](https://ian-flores.github.io/secureguard/reference/is_high_entropy.md)

## Examples

``` r
g <- guard_output_entropy()
run_guardrail(g, "Nothing suspicious here")
#> <guardrail_result> PASS
run_guardrail(g, "token=aB3xK9pQ2mR7nL4wS8vDfG5hJ6kT0yU")
#> <guardrail_result> FAIL
#> Reason: High-entropy strings detected (1 token)
```
