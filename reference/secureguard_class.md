# S7 class: secureguard

An S7 value type representing a guardrail. Prefer the `guard_*()`
factory functions for end-user guardrails.

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

  Character(1). Human-readable description.

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
