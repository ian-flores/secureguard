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

## Examples

``` r
pats <- pii_patterns()
names(pats)
#> [1] "ssn"         "email"       "phone"       "credit_card" "ip_address" 
grepl(pats$ssn, "123-45-6789")
#> [1] TRUE
```
