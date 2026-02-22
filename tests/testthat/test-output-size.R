test_that("guard_output_size passes small output", {
  g <- guard_output_size()
  result <- run_guardrail(g, "hello")
  expect_true(result@pass)
})

test_that("guard_output_size fails on too many characters", {
  g <- guard_output_size(max_chars = 10)
  result <- run_guardrail(g, strrep("x", 20))
  expect_false(result@pass)
  expect_true(grepl("chars", result@reason))
  expect_equal(result@details$chars, 20L)
})

test_that("guard_output_size fails on too many lines", {
  g <- guard_output_size(max_lines = 3)
  result <- run_guardrail(g, paste(rep("line", 10), collapse = "\n"))
  expect_false(result@pass)
  expect_true(grepl("lines", result@reason))
})

test_that("guard_output_size fails on too many elements (vector)", {
  g <- guard_output_size(max_elements = 5)
  result <- run_guardrail(g, seq_len(100))
  expect_false(result@pass)
  expect_true(grepl("elements", result@reason))
  expect_equal(result@details$elements, 100L)
})

test_that("guard_output_size fails on too many elements (data.frame)", {
  g <- guard_output_size(max_elements = 10)
  df <- data.frame(a = 1:10, b = 1:10, c = 1:10)
  result <- run_guardrail(g, df)
  expect_false(result@pass)
  # 10 * 3 = 30 elements > 10
  expect_equal(result@details$elements, 30L)
})

test_that("guard_output_size fails on too many elements (list)", {
  g <- guard_output_size(max_elements = 3)
  result <- run_guardrail(g, as.list(1:10))
  expect_false(result@pass)
  expect_equal(result@details$elements, 10L)
})

test_that("guard_output_size reports multiple violations", {
  g <- guard_output_size(max_chars = 5, max_lines = 1)
  result <- run_guardrail(g, "line1\nline2\nline3 extra")
  expect_false(result@pass)
  expect_true(grepl("chars", result@reason))
  expect_true(grepl("lines", result@reason))
})

test_that("guard_output_size reports details on pass", {
  g <- guard_output_size()
  result <- run_guardrail(g, "hello")
  expect_true(result@pass)
  expect_true(!is.null(result@details$chars))
  expect_true(!is.null(result@details$lines))
  expect_true(!is.null(result@details$elements))
})

# -- validation --

test_that("guard_output_size rejects invalid max_chars", {
  expect_error(guard_output_size(max_chars = -1), "positive number")
  expect_error(guard_output_size(max_chars = "a"), "positive number")
})

test_that("guard_output_size rejects invalid max_lines", {
  expect_error(guard_output_size(max_lines = 0), "positive number")
})

test_that("guard_output_size rejects invalid max_elements", {
  expect_error(guard_output_size(max_elements = -5), "positive number")
})

test_that("guard_output_size is type output", {
  g <- guard_output_size()
  expect_equal(g@type, "output")
  expect_true(S7::S7_inherits(g, secureguard_class))
})
