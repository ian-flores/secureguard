# Run all guardrails and collect results

Run all guardrails and collect results

## Usage

``` r
check_all(guardrails, x)
```

## Arguments

- guardrails:

  A list of guardrail objects.

- x:

  The input to check.

## Value

A list with components `pass` (logical), `results` (list of individual
results), `warnings` (character vector), and `reasons` (character vector
of failure reasons).
