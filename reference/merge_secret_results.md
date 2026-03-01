# Merge two secret detection result lists

Combines and deduplicates matches from two result lists.

## Usage

``` r
merge_secret_results(a, b)
```

## Arguments

- a:

  Named list of character vectors (from
  [`detect_secrets()`](https://ian-flores.github.io/secureguard/reference/detect_secrets.md)).

- b:

  Named list of character vectors (from
  [`detect_secrets()`](https://ian-flores.github.io/secureguard/reference/detect_secrets.md)).

## Value

Merged named list with unique matches per type.
