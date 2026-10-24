# Extract function name from a call expression

Returns the function name for simple calls (`fn(x)`), namespaced calls
(`pkg::fn(x)`, `pkg:::fn(x)`), and
[`do.call()`](https://rdrr.io/r/base/do.call.html) calls that name their
target directly: `do.call("fn", ...)`, `do.call(fn, ...)`, or
`do.call(pkg::fn, ...)`.
[`base::do.call()`](https://rdrr.io/r/base/do.call.html) and
`base:::do.call()` are resolved the same way. A
[`do.call()`](https://rdrr.io/r/base/do.call.html) whose target is
computed, such as `do.call(get_fn(), ...)`, returns its own name.

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

## Details

A symbol target is taken at face value: `do.call(fn, ...)` returns
`"fn"` even if `fn` is a variable holding some other function's name.

## Examples

``` r
expr <- parse_code("mean(x)")[[1]]
call_fn_name(expr)
#> [1] "mean"

expr2 <- parse_code("stats::median(x)")[[1]]
call_fn_name(expr2)
#> [1] "stats::median"

expr3 <- parse_code("do.call(rbind, list(a, b))")[[1]]
call_fn_name(expr3)
#> [1] "rbind"
```
