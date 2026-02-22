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

## Examples

``` r
expr <- parse_code("x <- 1 + 2")
length(expr)
#> [1] 1

expr2 <- parse_code("f <- function(x) x + 1\nf(10)")
length(expr2)
#> [1] 2
```
