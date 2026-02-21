# Secret detection patterns

Returns a named list of regex patterns for detecting secrets and
credentials in text.

## Usage

``` r
secret_patterns()
```

## Value

A named list of character(1) regex patterns. Names: `api_key`,
`aws_key`, `password`, `token`, `private_key`, `github_token`.
