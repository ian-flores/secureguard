# Compose guardrails

Combines several guardrails of the same type into one. The result is a
guardrail too, so you can run it, compose it again, or put it in a
pipeline.

## Usage

``` r
compose_guardrails(..., mode = c("all", "any"))
```

## Arguments

- ...:

  Guardrail objects to compose.

- mode:

  Character(1). `"all"` requires every guardrail to pass (default).
  `"any"` passes if at least one guardrail passes.

## Value

A composite guardrail of class `secureguard`.

## Examples

``` r
# Compose two code guardrails (both must pass)
g <- compose_guardrails(
  guard_code_analysis(),
  guard_code_complexity()
)
run_guardrail(g, "x <- 1 + 2")
#> <guardrail_result> PASS

# Use "any" mode (at least one must pass)
g2 <- compose_guardrails(
  guard_code_analysis(),
  guard_code_complexity(),
  mode = "any"
)
run_guardrail(g2, "x <- 1")
#> <guardrail_result> PASS
```
