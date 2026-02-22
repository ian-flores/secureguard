# Default blocked functions

Returns the default character vector of function names considered
dangerous for LLM-generated code. These include system-level calls,
dynamic evaluation, and file/network operations.

## Usage

``` r
default_blocked_functions()
```

## Value

Character vector of blocked function names.

## Examples

``` r
fns <- default_blocked_functions()
"system" %in% fns
#> [1] TRUE
"eval" %in% fns
#> [1] TRUE
```
