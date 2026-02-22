# Convert an R object to scannable text

Converts arbitrary R objects to a single character string for pattern
scanning by output guardrails.

## Usage

``` r
output_to_text(x)
```

## Arguments

- x:

  An arbitrary R object.

## Value

Character(1). A text representation of `x`.

## Examples

``` r
output_to_text("hello")
#> [1] "hello"
output_to_text(data.frame(a = 1:3, b = letters[1:3]))
#> [1] "  a b\n1 1 a\n2 2 b\n3 3 c"
output_to_text(list(x = 1, y = "two"))
#> [1] "List of 2\n $ x: num 1\n $ y: chr \"two\""
```
