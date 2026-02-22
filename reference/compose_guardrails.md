# Compose guardrails

Combine multiple guardrails into a single composite guardrail.

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
