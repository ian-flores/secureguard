# Create a complete guardrail pipeline

Bundles input, code, and output guardrails into a single pipeline object
with convenience methods for each stage.

## Usage

``` r
secure_pipeline(
  input_guardrails = list(),
  code_guardrails = list(),
  output_guardrails = list()
)
```

## Arguments

- input_guardrails:

  List of guardrails with `type = "input"`.

- code_guardrails:

  List of guardrails with `type = "code"`.

- output_guardrails:

  List of guardrails with `type = "output"`.

## Value

A list with methods:

- `$check_input(text)`: run input guardrails, returns
  [`check_all()`](https://ian-flores.github.io/secureguard/reference/check_all.md)
  result.

- `$check_code(code)`: run code guardrails, returns
  [`check_all()`](https://ian-flores.github.io/secureguard/reference/check_all.md)
  result.

- `$check_output(result)`: run output guardrails via
  [`guard_output()`](https://ian-flores.github.io/secureguard/reference/guard_output.md).

- `$as_pre_execute_hook()`: convert code guardrails to a securer hook.

## Examples

``` r
pipeline <- secure_pipeline(
  input_guardrails = list(guard_prompt_injection()),
  code_guardrails = list(guard_code_analysis()),
  output_guardrails = list(guard_output_pii())
)
pipeline$check_input("Hello, world")
#> $pass
#> [1] TRUE
#> 
#> $results
#> $results[[1]]
#> <guardrail_result> PASS
#> 
#> 
#> $warnings
#> character(0)
#> 
#> $reasons
#> character(0)
#> 
pipeline$check_code("x <- 1")
#> $pass
#> [1] TRUE
#> 
#> $results
#> $results[[1]]
#> <guardrail_result> PASS
#> 
#> 
#> $warnings
#> character(0)
#> 
#> $reasons
#> character(0)
#> 
```
