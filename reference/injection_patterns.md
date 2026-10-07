# Prompt injection detection patterns

The regular expressions
[`guard_prompt_injection()`](https://ian-flores.github.io/secureguard/reference/guard_prompt_injection.md)
uses. Higher sensitivity levels include more of them.

## Usage

``` r
injection_patterns(sensitivity = c("medium", "low", "high"))
```

## Arguments

- sensitivity:

  Character(1). One of `"low"`, `"medium"` (default), or `"high"`.
  Higher levels include more patterns and flag more harmless text by
  mistake.

## Value

A named list of character(1) regex patterns.

## Examples

``` r
pats <- injection_patterns("low")
names(pats)
#> [1] "instruction_override" "role_play"           

pats_high <- injection_patterns("high")
length(pats_high) > length(pats)
#> [1] TRUE
```
