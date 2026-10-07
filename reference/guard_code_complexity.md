# Code complexity guardrail

Fails code that is nested too deeply or has too many calls, assignments,
or top-level expressions. The counts come from
[`ast_stats()`](https://ian-flores.github.io/secureguard/reference/ast_stats.md).

## Usage

``` r
guard_code_complexity(
  max_ast_depth = 50L,
  max_calls = 200L,
  max_assignments = 100L,
  max_expressions = 50L
)
```

## Arguments

- max_ast_depth:

  Integer(1). Maximum allowed AST nesting depth. Default `50`.

- max_calls:

  Integer(1). Maximum number of function calls allowed. Default `200`.

- max_assignments:

  Integer(1). Maximum number of assignment operations. Default `100`.

- max_expressions:

  Integer(1). Maximum number of top-level expressions. Default `50`.

## Value

A guardrail object of class `"secureguard"` with type `"code"`.

## Examples

``` r
g <- guard_code_complexity()
run_guardrail(g, "x <- 1 + 2")
#> <guardrail_result> PASS
```
