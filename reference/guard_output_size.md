# Output size guardrail

Creates a guardrail that checks whether output exceeds size limits.

## Usage

``` r
guard_output_size(
  max_chars = 100000L,
  max_lines = 5000L,
  max_elements = 10000L
)
```

## Arguments

- max_chars:

  Integer(1). Maximum number of characters in the text representation.
  Default `100000`.

- max_lines:

  Integer(1). Maximum number of lines in the text representation.
  Default `5000`.

- max_elements:

  Integer(1). Maximum number of elements. For vectors and lists this is
  [`length()`](https://rdrr.io/r/base/length.html). For data frames this
  is `nrow() * ncol()`. Default `10000`.

## Value

A guardrail object of class `"secureguard"` with type `"output"`.

## Examples

``` r
g <- guard_output_size(max_chars = 100, max_lines = 5)
run_guardrail(g, strrep("x", 200))
#> <guardrail_result> FAIL
#> Reason: Output exceeds size limits: chars: 200 > 100
run_guardrail(g, "short")
#> <guardrail_result> PASS
```
