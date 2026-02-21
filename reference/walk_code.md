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
