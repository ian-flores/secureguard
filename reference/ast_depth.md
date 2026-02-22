# Compute maximum AST nesting depth

Compute maximum AST nesting depth

## Usage

``` r
ast_depth(expr, depth = 0L)
```

## Arguments

- expr:

  A language object.

- depth:

  Integer. Current depth (internal).

## Value

Integer. Maximum nesting depth.

## Examples

``` r
expr <- parse_code("f(g(h(1)))")[[1]]
ast_depth(expr)
#> [1] 3

expr2 <- parse_code("x <- 1")[[1]]
ast_depth(expr2)
#> [1] 1
```
