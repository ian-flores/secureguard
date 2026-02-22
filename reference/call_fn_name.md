# Extract function name from a call expression

Returns the function name for simple calls (`fn(x)`), namespaced calls
(`pkg::fn(x)`, `pkg:::fn(x)`), and
[`do.call()`](https://rdrr.io/r/base/do.call.html) with a string literal
first argument (`do.call("fn", list(x))`).

## Usage

``` r
call_fn_name(expr)
```

## Arguments

- expr:

  A call expression.

## Value

Character(1). The function name, or `NA_character_` if it cannot be
determined (e.g., anonymous function calls).

## Examples

``` r
expr <- parse_code("mean(x)")[[1]]
call_fn_name(expr)
#> [1] "mean"

expr2 <- parse_code("stats::median(x)")[[1]]
call_fn_name(expr2)
#> [1] "stats::median"
```
