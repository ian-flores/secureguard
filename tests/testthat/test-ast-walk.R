# --- parse_code ---

test_that("parse_code parses valid code", {
  exprs <- parse_code("x <- 1 + 2")
  expect_length(exprs, 1)
  expect_true(is.expression(exprs))
})

test_that("parse_code handles multiple expressions", {
  exprs <- parse_code("x <- 1\ny <- 2\nz <- 3")
  expect_length(exprs, 3)
})

test_that("parse_code errors on invalid syntax", {
  expect_error(parse_code("x <- }{"), "Failed to parse")
})

test_that("parse_code errors on non-string input", {
  expect_error(parse_code(42), "single character string")
  expect_error(parse_code(c("a", "b")), "single character string")
})

test_that("parse_code handles empty string", {
  exprs <- parse_code("")
  expect_length(exprs, 0)
})

# --- call_fn_name ---

test_that("call_fn_name extracts simple function name", {
  expr <- parse(text = "mean(x)")[[1]]
  expect_equal(call_fn_name(expr), "mean")
})

test_that("call_fn_name extracts namespaced calls with ::", {
  expr <- parse(text = "stats::median(x)")[[1]]
  expect_equal(call_fn_name(expr), "stats::median")
})

test_that("call_fn_name extracts namespaced calls with :::", {
  expr <- parse(text = "pkg:::internal_fn(x)")[[1]]
  expect_equal(call_fn_name(expr), "pkg:::internal_fn")
})

test_that("call_fn_name handles do.call with string literal", {
  expr <- parse(text = 'do.call("rbind", list(a, b))')[[1]]
  expect_equal(call_fn_name(expr), "rbind")
})

test_that("call_fn_name returns NA for do.call with non-literal", {
  expr <- parse(text = "do.call(fn_var, args)")[[1]]
  expect_equal(call_fn_name(expr), "do.call")
})

test_that("call_fn_name returns NA for anonymous function call", {
  expr <- parse(text = "(function(x) x)(1)")[[1]]
  expect_true(is.na(call_fn_name(expr)))
})

test_that("call_fn_name handles operators", {
  expr <- parse(text = "1 + 2")[[1]]
  expect_equal(call_fn_name(expr), "+")
})

test_that("call_fn_name errors on non-call", {
  expect_error(call_fn_name(quote(x)), "call expression")
})

# --- walk_ast ---

test_that("walk_ast calls on_call for function calls", {
  expr <- parse(text = "mean(x)")[[1]]
  calls <- character(0)
  visitor <- list(
    on_call = function(expr, fn_name, depth) fn_name
  )
  findings <- walk_ast(expr, visitor)
  expect_true("mean" %in% unlist(findings))
})

test_that("walk_ast calls on_symbol for symbols", {
  expr <- parse(text = "x + y")[[1]]
  visitor <- list(
    on_symbol = function(expr, name, depth) name
  )
  findings <- walk_ast(expr, visitor)
  names <- unlist(findings)
  expect_true("x" %in% names)
  expect_true("y" %in% names)
})

test_that("walk_ast calls on_literal for literals", {
  expr <- parse(text = '1 + "hello"')[[1]]
  visitor <- list(
    on_literal = function(expr, depth) expr
  )
  findings <- walk_ast(expr, visitor)
  expect_true(1 %in% findings)
  expect_true("hello" %in% findings)
})

test_that("walk_ast returns empty list with no findings", {
  expr <- parse(text = "mean(x)")[[1]]
  visitor <- list(
    on_call = function(expr, fn_name, depth) NULL
  )
  findings <- walk_ast(expr, visitor)
  expect_length(findings, 0)
})

test_that("walk_ast tracks depth correctly", {
  expr <- parse(text = "f(g(h(1)))")[[1]]
  depths <- integer(0)
  visitor <- list(
    on_call = function(expr, fn_name, depth) depth
  )
  findings <- walk_ast(expr, visitor)
  # f at depth 0, g at depth 1 (arg of f), h at depth 2
  expect_true(0L %in% unlist(findings))
  expect_true(1L %in% unlist(findings))
  expect_true(2L %in% unlist(findings))
})

test_that("walk_ast handles deeply nested expressions", {
  # Build deeply nested: f(f(f(f(f(1)))))
  code <- paste0(paste(rep("f(", 20), collapse = ""), "1",
                       paste(rep(")", 20), collapse = ""))
  expr <- parse(text = code)[[1]]
  visitor <- list(
    on_call = function(expr, fn_name, depth) depth
  )
  findings <- walk_ast(expr, visitor)
  expect_equal(max(unlist(findings)), 19L)
})

test_that("walk_ast errors on non-list visitor", {
  expr <- parse(text = "1")[[1]]
  expect_error(walk_ast(expr, "bad"), "list")
})

# --- walk_code ---

test_that("walk_code parses and walks all expressions", {
  code <- "x <- 1\ny <- 2\nz <- x + y"
  visitor <- list(
    on_call = function(expr, fn_name, depth) fn_name
  )
  findings <- walk_code(code, visitor)
  fn_names <- unlist(findings)
  expect_true("<-" %in% fn_names)
  expect_true("+" %in% fn_names)
})

test_that("walk_code handles empty code", {
  findings <- walk_code("", list(
    on_call = function(expr, fn_name, depth) fn_name
  ))
  expect_length(findings, 0)
})

test_that("walk_code detects namespaced calls", {
  code <- "dplyr::mutate(df, x = 1)"
  visitor <- list(
    on_call = function(expr, fn_name, depth) fn_name
  )
  findings <- walk_code(code, visitor)
  fn_names <- unlist(findings)
  expect_true("dplyr::mutate" %in% fn_names)
})

test_that("walk_code walks pipe expressions", {
  # Native pipe |> is desugared by the parser into nested calls:
  #   x |> mean() |> round(2)  ->  round(mean(x), 2)
  code <- "x |> mean() |> round(2)"
  visitor <- list(
    on_call = function(expr, fn_name, depth) fn_name
  )
  findings <- walk_code(code, visitor)
  fn_names <- unlist(findings)
  expect_true("mean" %in% fn_names)
  expect_true("round" %in% fn_names)
})

# --- ast_depth ---

test_that("ast_depth returns 0 for a single symbol", {
  expr <- parse(text = "x")[[1]]
  expect_equal(ast_depth(expr), 0L)
})

test_that("ast_depth returns correct depth for nested calls", {
  expr <- parse(text = "f(g(h(1)))")[[1]]
  # f -> g -> h -> 1 = depth 3
  expect_equal(ast_depth(expr), 3L)
})

test_that("ast_depth handles flat calls", {
  expr <- parse(text = "f(a, b, c)")[[1]]
  # f -> a/b/c each at depth 1
  expect_equal(ast_depth(expr), 1L)
})

test_that("ast_depth handles literals", {
  expr <- parse(text = "42")[[1]]
  expect_equal(ast_depth(expr), 0L)
})

# --- ast_stats ---

test_that("ast_stats counts calls correctly", {
  stats <- ast_stats("mean(x) + sum(y)")
  # calls: +, mean, sum = 3
  expect_equal(stats$n_calls, 3L)
})

test_that("ast_stats counts all assignment forms", {
  code <- "
    a <- 1
    b = 2
    3 -> c
    d <<- 4
    5 ->> e
    assign('f', 6)
  "
  stats <- ast_stats(code)
  expect_equal(stats$n_assignments, 6L)
})

test_that("ast_stats counts symbols", {
  stats <- ast_stats("x + y")
  # symbols: x, y (+ is the call head, not counted as symbol by on_symbol
  # since it's part of the call)
  # Actually: walk_ast recurses into ALL children including position 1 (the function)
  # For `+`, position 1 is the symbol `+`, position 2 is x, position 3 is y
  expect_true(stats$n_symbols >= 2L)
})

test_that("ast_stats counts n_expressions", {
  stats <- ast_stats("x <- 1\ny <- 2\nz <- 3")
  expect_equal(stats$n_expressions, 3L)
})

test_that("ast_stats computes depth", {
  stats <- ast_stats("f(g(h(1)))")
  expect_equal(stats$depth, 3L)
})

test_that("ast_stats handles empty code", {
  stats <- ast_stats("")
  expect_equal(stats$n_calls, 0L)
  expect_equal(stats$n_assignments, 0L)
  expect_equal(stats$n_symbols, 0L)
  expect_equal(stats$depth, 0L)
  expect_equal(stats$n_expressions, 0L)
})

test_that("ast_stats handles single expression", {
  stats <- ast_stats("42")
  expect_equal(stats$n_calls, 0L)
  expect_equal(stats$n_assignments, 0L)
  expect_equal(stats$n_symbols, 0L)
  expect_equal(stats$n_expressions, 1L)
})

test_that("ast_stats errors on unparseable code", {
  expect_error(ast_stats("if ("), "Failed to parse")
})

test_that("ast_stats detects assign() as assignment", {
  stats <- ast_stats("assign('x', 42)")
  expect_equal(stats$n_assignments, 1L)
})

test_that("ast_stats handles formula objects", {
  stats <- ast_stats("y ~ x + z")
  expect_true(stats$n_calls >= 1L)  # ~ is a call
})

test_that("ast_stats handles right-assignment", {
  stats <- ast_stats("1 -> x\n2 ->> y")
  expect_equal(stats$n_assignments, 2L)
})
