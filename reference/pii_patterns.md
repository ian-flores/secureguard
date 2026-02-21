# PII detection patterns

Returns a named list of regex patterns for detecting personally
identifiable information (PII) in text.

## Usage

``` r
pii_patterns()
```

## Value

A named list of character(1) regex patterns. Names: `ssn`, `email`,
`phone`, `credit_card`, `ip_address`.
