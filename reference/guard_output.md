# Run output guardrails on a result

Runs output guardrails on an R object. When a guardrail with
`action = "redact"` finds something, the returned `result` is the
redacted text instead of the original object.

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

- `warnings`: character vector of warnings that didn't fail the check.

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
