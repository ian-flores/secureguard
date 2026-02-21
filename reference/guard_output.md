# Run output guardrails on a result

Checks an R object against one or more output guardrails. For guardrails
with `action = "redact"`, the redacted text is applied to the result.

## Usage

``` r
guard_output(result, ...)
```

## Arguments

- result:

  An R object to check.

- ...:

  Guardrail objects with `type = "output"`.

## Value

A list with components:

- `pass`: logical, `TRUE` if all guardrails pass.

- `result`: the (possibly redacted) result.

- `warnings`: character vector of advisory warnings.

- `reasons`: character vector of failure reasons.

## Examples

``` r
out <- guard_output(
  "My SSN is 123-45-6789",
  guard_output_pii()
)
out$pass
#> [1] FALSE
```
