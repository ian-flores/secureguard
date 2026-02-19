test_that("guard_code_complexity creates secureguard object", {
  g <- guard_code_complexity()
  expect_s3_class(g, "secureguard")
  expect_equal(g$type, "code")
  expect_equal(g$name, "code_complexity")
})

test_that("simple code passes default limits", {
  g <- guard_code_complexity()
  result <- run_guardrail(g, "x <- 1 + 2")
  expect_true(result$pass)
  expect_true(is.list(result$details$stats))
})

test_that("code exceeding max_ast_depth fails", {
  g <- guard_code_complexity(max_ast_depth = 3L)
  # Deeply nested expression
  code <- "f(g(h(i(j(1)))))"
  result <- run_guardrail(g, code)
  expect_false(result$pass)
  expect_true(grepl("AST depth", result$reason))
})

test_that("code exceeding max_calls fails", {
  g <- guard_code_complexity(max_calls = 2L)
  code <- "a()\nb()\nc()"
  result <- run_guardrail(g, code)
  expect_false(result$pass)
  expect_true(grepl("Call count", result$reason))
})

test_that("code exceeding max_assignments fails", {
  g <- guard_code_complexity(max_assignments = 1L)
  code <- "x <- 1\ny <- 2"
  result <- run_guardrail(g, code)
  expect_false(result$pass)
  expect_true(grepl("Assignment count", result$reason))
})

test_that("code exceeding max_expressions fails", {
  g <- guard_code_complexity(max_expressions = 2L)
  code <- "1\n2\n3"
  result <- run_guardrail(g, code)
  expect_false(result$pass)
  expect_true(grepl("Expression count", result$reason))
})

test_that("multiple violations reported together", {
  g <- guard_code_complexity(max_calls = 1L, max_assignments = 1L)
  code <- "x <- 1\ny <- 2\na()\nb()"
  result <- run_guardrail(g, code)
  expect_false(result$pass)
  expect_true(grepl("Call count", result$reason))
  expect_true(grepl("Assignment count", result$reason))
})

test_that("stats are in details on pass", {
  g <- guard_code_complexity()
  result <- run_guardrail(g, "x <- 1")
  expect_true(result$pass)
  expect_true("stats" %in% names(result$details))
  expect_true("n_calls" %in% names(result$details$stats))
})

test_that("invalid inputs are rejected", {
  expect_error(guard_code_complexity(max_ast_depth = 0))
  expect_error(guard_code_complexity(max_calls = -1))
  expect_error(guard_code_complexity(max_assignments = 0))
  expect_error(guard_code_complexity(max_expressions = 0))
})
