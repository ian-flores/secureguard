# Walk an AST node recursively

Visits every node in a parsed R expression and calls your callbacks on
function calls, symbols, and literals. Anything a callback returns,
other than `NULL`, is collected and returned.

## Usage

``` r
walk_ast(expr, visitor, depth = 0L)
```

## Arguments

- expr:

  A language object (from
  [`parse_code()`](https://ian-flores.github.io/secureguard/reference/parse_code.md)
  or [`base::parse()`](https://rdrr.io/r/base/parse.html)).

- visitor:

  A list with optional callback functions:

  `on_call`

  :   `function(expr, fn_name, depth)`, called for function calls.
      `fn_name` comes from
      [`call_fn_name()`](https://ian-flores.github.io/secureguard/reference/call_fn_name.md).

  `on_symbol`

  :   `function(expr, name, depth)`, called for symbols (names).

  `on_literal`

  :   `function(expr, depth)`, called for literal values (numbers,
      strings, logicals, `NULL`, and so on).

  A callback returns `NULL` to record nothing, or any other value to add
  it to the results.

- depth:

  Integer. Current nesting depth (used internally for recursion).
  Defaults to 0.

## Value

A list of the non-`NULL` values the callbacks returned.

## Examples

``` r
# Collect all function call names from an expression
expr <- parse_code("mean(x) + sum(y)")[[1]]
visitor <- list(
  on_call = function(expr, fn_name, depth) fn_name
)
walk_ast(expr, visitor)
#> [[1]]
#> [1] "+"
#> 
#> [[2]]
#> [1] "mean"
#> 
#> [[3]]
#> [1] "sum"
#> 
```
