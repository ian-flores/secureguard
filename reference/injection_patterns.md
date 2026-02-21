# Prompt injection detection patterns

Returns a named list of regex patterns for detecting prompt injection
attacks, filtered by sensitivity level.

## Usage

``` r
injection_patterns(sensitivity = c("medium", "low", "high"))
```

## Arguments

- sensitivity:

  Character(1). One of `"low"`, `"medium"` (default), or `"high"`.
  Higher sensitivity includes more patterns and is more likely to
  produce false positives.

## Value

A named list of character(1) regex patterns.
