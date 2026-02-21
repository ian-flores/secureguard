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

A composite guardrail of class `"secureguard"`.
