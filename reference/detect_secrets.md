# Detect secrets in text

Scans text for secrets and credentials using regex patterns.

## Usage

``` r
detect_secrets(text, types = NULL)
```

## Arguments

- text:

  Character(1). The text to scan.

- types:

  Character vector of secret types to check. Defaults to all available
  types from
  [`secret_patterns()`](https://ian-flores.github.io/secureguard/reference/secret_patterns.md).
  Valid values: `"api_key"`, `"aws_key"`, `"password"`, `"token"`,
  `"private_key"`, `"github_token"`.

## Value

A named list where each element is a character vector of matches found
for that secret type. Empty character vectors indicate no matches.

## Examples

``` r
detect_secrets("API_KEY = 'sk_live_abc123def456ghi789jkl0'")
#> $api_key
#> [1] "API_KEY = 'sk_live_abc123def456ghi789jkl0"
#> 
#> $aws_key
#> character(0)
#> 
#> $password
#> character(0)
#> 
#> $token
#> character(0)
#> 
#> $private_key
#> character(0)
#> 
#> $github_token
#> character(0)
#> 
detect_secrets("AKIAIOSFODNN7EXAMPLE", types = "aws_key")
#> $aws_key
#> [1] "AKIAIOSFODNN7EXAMPLE"
#> 
```
