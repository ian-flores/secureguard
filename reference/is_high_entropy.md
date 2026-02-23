# Check if a string has high entropy

Determines whether a string has suspiciously high Shannon entropy,
suggesting it may be a secret, key, or random token.

## Usage

``` r
is_high_entropy(s, base64_threshold = 4.5, hex_threshold = 3, min_length = 20L)
```

## Arguments

- s:

  Character(1). The string to check.

- base64_threshold:

  Numeric(1). Entropy threshold for base64-like strings (default 4.5).

- hex_threshold:

  Numeric(1). Entropy threshold for hex-like strings (default 3.0).

- min_length:

  Integer(1). Minimum string length to consider (default 20). Shorter
  strings always return `FALSE`.

## Value

Logical(1).

## See also

[`shannon_entropy()`](https://ian-flores.github.io/secureguard/reference/shannon_entropy.md),
[`guard_output_entropy()`](https://ian-flores.github.io/secureguard/reference/guard_output_entropy.md)

## Examples

``` r
is_high_entropy("aaaaaaaaaaaaaaaaaaaaa")  # FALSE (low entropy)
#> [1] FALSE
is_high_entropy("aB3xK9pQ2mR7nL4wS8vD")  # likely TRUE
#> [1] FALSE
```
