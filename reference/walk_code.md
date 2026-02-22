# Walk all expressions in a code string

Parses the code and walks each top-level expression with the visitor.

## Usage

``` r
walk_code(code, visitor)
```

## Arguments

- code:

  Character(1). R code to parse and walk.

- visitor:

  A visitor list (see
  [`walk_ast()`](https://ian-flores.github.io/secureguard/reference/walk_ast.md)).

## Value

A list of accumulated findings from all top-level expressions.

## Examples

``` r
# Find all function calls in a code string
visitor <- list(
  on_call = function(expr, fn_name, depth) fn_name
)
walk_code("x <- mean(1:10)\ny <- sum(x)", visitor)
#> [[1]]
#> [1] "<-"
#> 
#> [[2]]
#> [1] "mean"
#> 
#> [[3]]
#> [1] ":"
#> 
#> [[4]]
#> [1] "<-"
#> 
#> [[5]]
#> [1] "sum"
#> 
```
