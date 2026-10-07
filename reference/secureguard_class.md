# The secureguard class

The S7 class behind every guardrail. You rarely need it directly. Use
[`new_guardrail()`](https://ian-flores.github.io/secureguard/reference/new_guardrail.md)
to write your own check, or one of the `guard_*()` functions for a
built-in one.

## Usage

``` r
secureguard_class(
  name = character(0),
  type = character(0),
  check_fn = function() NULL,
  description = character(0)
)
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
# Prefer new_guardrail() or guard_*() factories over direct construction
g <- secureguard_class(
  name = "my_guard",
  type = "input",
  check_fn = function(x) guardrail_result(pass = TRUE),
  description = "A simple guardrail"
)
g@name
#> [1] "my_guard"
g@type
#> [1] "input"
```
