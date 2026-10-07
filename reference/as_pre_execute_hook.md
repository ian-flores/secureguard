# Convert code guardrails to a securer pre-execute hook

Turns code guardrails into a function you can pass to securer's
`pre_execute_hook` argument. securer calls it before running each piece
of code. It returns `FALSE` to block code that fails any guardrail and
`TRUE` to let it run.

## Usage

``` r
as_pre_execute_hook(...)
```

## Arguments

- ...:

  Guardrail objects with `type = "code"`.

## Value

A function with signature `function(code)` that returns `TRUE` if all
guardrails pass, or `FALSE` (with warnings) if any fail.

## Examples

``` r
hook <- as_pre_execute_hook(
  guard_code_analysis(),
  guard_code_complexity(max_ast_depth = 10)
)
hook("x <- 1 + 2")
#> [1] TRUE
hook("system('ls')")
#> Warning: Blocked function(s) detected: system
#> [1] FALSE
```
