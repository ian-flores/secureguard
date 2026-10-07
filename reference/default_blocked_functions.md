# Default blocked functions

The functions
[`guard_code_analysis()`](https://ian-flores.github.io/secureguard/reference/guard_code_analysis.md)
blocks unless you give it your own list. They run shell commands,
evaluate code built at run time, call compiled code, delete files, or
open network connections.

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
