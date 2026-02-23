# Shannon entropy of a string

Calculates the Shannon entropy (in bits) of a character string based on
character frequency.

## Usage

``` r
shannon_entropy(s)
```

## Arguments

- s:

  Character(1). The string to measure.

## Value

Numeric(1). The Shannon entropy in bits. Returns 0 for empty strings or
single-character strings.

## See also

[`is_high_entropy()`](https://ian-flores.github.io/secureguard/reference/is_high_entropy.md),
[`guard_output_entropy()`](https://ian-flores.github.io/secureguard/reference/guard_output_entropy.md)

## Examples

``` r
shannon_entropy("aaaaaa")    # low entropy (0)
#> [1] 0
shannon_entropy("abcdefgh")  # higher entropy
#> [1] 3
shannon_entropy("aB3$xK9!")  # high entropy
#> [1] 3
```
