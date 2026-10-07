# Create a new guardrail

Builds a guardrail from a function that does the checking. Use it to
write your own checks. For the built-in checks, use the `guard_*()`
functions.

## Usage

``` r
new_guardrail(name, type, check_fn, description = "")
```

## Arguments

- name:

  Character(1). Short identifier for the guardrail.

- type:

  Character(1). One of `"input"`, `"code"`, or `"output"`.

- check_fn:

  A function taking a single argument and returning a
  [`guardrail_result()`](https://ian-flores.github.io/secureguard/reference/guardrail_result.md).

- description:

  Character(1). A short description of what the guardrail checks.

## Value

An S7 object of class `secureguard`.

## Examples

``` r
g <- new_guardrail(
  name = "no_eval",
  type = "code",
  check_fn = function(code) {
    if (grepl("\\beval\\b", code)) {
      guardrail_result(pass = FALSE, reason = "eval() detected")
    } else {
      guardrail_result(pass = TRUE)
    }
  },
  description = "Blocks eval() calls"
)
g@name
#> [1] "no_eval"
run_guardrail(g, "x <- 1")
#> <guardrail_result> PASS
```
