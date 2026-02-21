# Compute summary statistics for R code AST

Parses the code and returns counts of calls, assignments, symbols,
expressions, and maximum nesting depth.

## Usage

``` r
ast_stats(code)
```

## Arguments

- code:

  Character(1). R code to analyse.

## Value

A named list with components:

- `n_calls`:

  Number of function calls.

- `n_assignments`:

  Number of assignment operations (including `<-`, `=`, `->`, `<<-`,
  `->>`, and [`assign()`](https://rdrr.io/r/base/assign.html)).

- `n_symbols`:

  Number of symbol (name) references.

- `depth`:

  Maximum AST nesting depth.

- `n_expressions`:

  Number of top-level expressions.
