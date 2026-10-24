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

test_that("pkg:: and pkg::: prefixes don't bypass a bare blocked name", {
  g <- guard_code_analysis()
  for (code in c("base::system('ls')", "base:::system('ls')", "base::eval(quote(1))")) {
    result <- run_guardrail(g, code)
    expect_false(result@pass, label = code)
  }
  result <- run_guardrail(g, "base::system('ls')")
  expect_true("base::system" %in% result@details$blocked_calls)
})

test_that("qualified calls to unblocked functions still pass", {
  g <- guard_code_analysis()
  expect_true(run_guardrail(g, "stats::median(1:10)")@pass)
  expect_true(run_guardrail(g, "base::mean(1:10)")@pass)
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
  g <- guard_code_analysis(detect_indirect = FALSE)
  result <- run_guardrail(g, 'do.call("system", list("ls"))')
  expect_true(result@pass)

  # Direct and namespaced calls are still blocked
  expect_false(run_guardrail(g, "system('ls')")@pass)
  expect_false(run_guardrail(g, "base::system('ls')")@pass)
})

test_that("detect_indirect = FALSE still blocks do.call when it is blocked", {
  g <- guard_code_analysis(
    blocked_functions = c("system", "do.call"),
    detect_indirect = FALSE
  )
  result <- run_guardrail(g, 'do.call("system", list("ls"))')
  expect_false(result@pass)
  expect_equal(result@details$blocked_calls, "do.call")
})

test_that("detect_indirect = TRUE reports the do.call target", {
  g <- guard_code_analysis(detect_indirect = TRUE)
  result <- run_guardrail(g, 'do.call("base::system", list("ls"))')
  expect_false(result@pass)
  expect_true("base::system" %in% result@details$blocked_calls)
})

test_that("do.call with a function name rather than a string is detected", {
  g <- guard_code_analysis()
  for (code in c(
    'do.call(system, list("ls"))',
    'do.call(`system`, list("ls"))',
    'do.call(base::system, list("ls"))',
    'do.call(base:::system, list("ls"))'
  )) {
    result <- run_guardrail(g, code)
    expect_false(result@pass, info = code)
  }
})

test_that("base::do.call and base:::do.call resolve like do.call", {
  g <- guard_code_analysis()
  expect_false(run_guardrail(g, 'base::do.call("system", list("ls"))')@pass)
  expect_false(run_guardrail(g, 'base:::do.call(system, list("ls"))')@pass)

  g_off <- guard_code_analysis(detect_indirect = FALSE)
  expect_true(run_guardrail(g_off, 'base::do.call("system", list("ls"))')@pass)
  expect_true(run_guardrail(g_off, 'do.call(system, list("ls"))')@pass)
})

test_that("blocking do.call catches every do.call form", {
  g <- guard_code_analysis(blocked_functions = "do.call")
  for (code in c(
    'do.call("mean", list(1))',
    'do.call(mean, list(1))',
    'base::do.call(mean, list(1))',
    'do.call(get_fn(), list(1))'
  )) {
    result <- run_guardrail(g, code)
    expect_false(result@pass, info = code)
  }

  g_off <- guard_code_analysis(
    blocked_functions = "do.call", detect_indirect = FALSE
  )
  result <- run_guardrail(g_off, 'base::do.call(mean, list(1))')
  expect_false(result@pass)
  expect_equal(result@details$blocked_calls, "base::do.call")
})

test_that("chained calls don't error", {
  g <- guard_code_analysis()
  expect_true(run_guardrail(g, "g(1)(2)(3)")@pass)
})

test_that("invalid inputs are rejected", {
  expect_error(guard_code_analysis(blocked_functions = 123))
  expect_error(guard_code_analysis(blocked_functions = character(0)))
  expect_error(guard_code_analysis(allow_namespaces = 123))
  expect_error(guard_code_analysis(detect_indirect = "yes"))
})
