# Detect PII in text

Scans text for personally identifiable information using regex patterns.

## Usage

``` r
detect_pii(text, types = NULL)
```

## Arguments

- text:

  Character(1). The text to scan.

- types:

  Character vector of PII types to check. Defaults to all available
  types from
  [`pii_patterns()`](https://ian-flores.github.io/secureguard/reference/pii_patterns.md).
  Valid values: `"ssn"`, `"email"`, `"phone"`, `"credit_card"`,
  `"ip_address"`.

## Value

A named list where each element is a character vector of matches found
for that PII type. Empty character vectors indicate no matches.

## Examples

``` r
detect_pii("Call me at 555-123-4567 or email me at test@example.com")
#> $ssn
#> character(0)
#> 
#> $email
#> [1] "test@example.com"
#> 
#> $phone
#> [1] "555-123-4567"
#> 
#> $credit_card
#> character(0)
#> 
#> $ip_address
#> character(0)
#> 
detect_pii("SSN: 123-45-6789", types = "ssn")
#> $ssn
#> [1] "123-45-6789"
#> 
```
