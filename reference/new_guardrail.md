# Create a new guardrail

Low-level constructor for guardrail objects. Prefer the `guard_*()`
factory functions for end-user guardrails.

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

  Character(1). Human-readable description.

## Value

An S3 object of class `"secureguard"`.
