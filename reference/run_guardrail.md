# Run a single guardrail

Run a single guardrail

## Usage

``` r
run_guardrail(guardrail, x)
```

## Arguments

- guardrail:

  A guardrail object.

- x:

  The input to check (string for input/code, any R object for output).

## Value

A
[`guardrail_result()`](https://ian-flores.github.io/secureguard/reference/guardrail_result.md).

## Examples

``` r
g <- guard_code_analysis()
result <- run_guardrail(g, "x <- 1 + 2")
result@pass
#> [1] TRUE

result2 <- run_guardrail(g, "system('ls')")
result2@pass
#> [1] FALSE
result2@reason
#> [1] "Blocked function(s) detected: system"
```
