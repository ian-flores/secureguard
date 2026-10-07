# Parse code string into expressions

Parses a string of R code. If the code doesn't parse, the error says
why.

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
