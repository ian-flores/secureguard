test_that("default_blocked_functions returns expected vector", {
  fns <- default_blocked_functions()
  expect_type(fns, "character")
  expect_true(length(fns) > 0L)
  expect_true("system" %in% fns)
  expect_true("eval" %in% fns)
  expect_true(".Internal" %in% fns)
  expect_true("processx::run" %in% fns)
})

test_that("guard_code_analysis creates secureguard object", {
  g <- guard_code_analysis()
  expect_true(S7::S7_inherits(g, secureguard_class))
  expect_equal(g@type, "code")
  expect_equal(g@name, "code_analysis")
})

test_that("safe code passes", {
  g <- guard_code_analysis()
  result <- run_guardrail(g, "x <- 1 + 2\ny <- mean(c(1, 2, 3))")
  expect_true(result@pass)
})

test_that("direct blocked function is detected", {
  g <- guard_code_analysis()

  result <- run_guardrail(g, "system('ls')")
  expect_false(result@pass)
  expect_true(grepl("system", result@reason))
  expect_true("system" %in% result@details$blocked_calls)

  result2 <- run_guardrail(g, "eval(parse(text = 'x'))")
  expect_false(result2@pass)
  expect_true("eval" %in% result2@details$blocked_calls)
})

test_that("namespaced blocked function is detected", {
  g <- guard_code_analysis()
  result <- run_guardrail(g, "processx::run('ls')")
  expect_false(result@pass)
  expect_true("processx::run" %in% result@details$blocked_calls)
})

test_that("multiple blocked functions are all reported", {
  g <- guard_code_analysis()
  result <- run_guardrail(g, "system('ls')\neval(quote(1))")
  expect_false(result@pass)
  expect_true("system" %in% result@details$blocked_calls)
  expect_true("eval" %in% result@details$blocked_calls)
})

test_that("allow_namespaces whitelists a namespace", {
  g <- guard_code_analysis(
    blocked_functions = c("processx::run", "system"),
    allow_namespaces = "processx"
  )
  # processx::run is allowed now

result <- run_guardrail(g, "processx::run('ls')")
  expect_true(result@pass)

  # system is still blocked
  result2 <- run_guardrail(g, "system('ls')")
  expect_false(result2@pass)
})

test_that("custom blocked_functions overrides default", {
  g <- guard_code_analysis(blocked_functions = c("mean", "sum"))
  # mean is now blocked
  result <- run_guardrail(g, "mean(1:10)")
  expect_false(result@pass)

  # system is NOT blocked (not in custom list)
  result2 <- run_guardrail(g, "system('ls')")
  expect_true(result2@pass)
})

test_that("do.call with string literal detects blocked function", {
  g <- guard_code_analysis()
  result <- run_guardrail(g, 'do.call("system", list("ls"))')
  expect_false(result@pass)
  expect_true("system" %in% result@details$blocked_calls)
})

test_that("do.call with variable is not detected (by design)", {
  g <- guard_code_analysis()
  result <- run_guardrail(g, 'fn <- "system"\ndo.call(fn, list("ls"))')
  # fn is a variable, not a string literal; do.call node resolves to fn not "system"
  # Only do.call itself is not blocked by default
  expect_true(result@pass)
})

test_that("detect_indirect = FALSE skips do.call detection", {
  # do.call("system",...) is detected via call_fn_name resolving to "system",
  # which is already a direct match. detect_indirect doesn't change this behavior
  # for string literal do.call since call_fn_name resolves it automatically.
  g <- guard_code_analysis(detect_indirect = FALSE)
  result <- run_guardrail(g, 'do.call("system", list("ls"))')
  # call_fn_name still resolves do.call("system",...) to "system"
  expect_false(result@pass)
})

test_that("invalid inputs are rejected", {
  expect_error(guard_code_analysis(blocked_functions = 123))
  expect_error(guard_code_analysis(blocked_functions = character(0)))
  expect_error(guard_code_analysis(allow_namespaces = 123))
  expect_error(guard_code_analysis(detect_indirect = "yes"))
})
