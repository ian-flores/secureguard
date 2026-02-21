# Parse code string into expressions

Parses an R code string into a list of expressions, with clear error
messages on failure.

## Usage

``` r
parse_code(code)
```

## Arguments

- code:

  Character(1). R code to parse.

## Value

A parsed expression object (from
[`base::parse()`](https://rdrr.io/r/base/parse.html)).
