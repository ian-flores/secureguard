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

## Examples

``` r
guards <- list(
  guard_code_analysis(),
  guard_code_complexity()
)
result <- check_all(guards, "x <- 1 + 2")
result$pass
#> [1] TRUE

result2 <- check_all(guards, "system('ls')")
result2$pass
#> [1] FALSE
result2$reasons
#> [1] "Blocked function(s) detected: system"
```
