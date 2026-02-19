test_that("new_guardrail creates valid object", {
  g <- new_guardrail(
    name = "test",
    type = "code",
    check_fn = function(x) guardrail_result(pass = TRUE),
    description = "A test guardrail"
  )
  expect_s3_class(g, "secureguard")
  expect_equal(g$name, "test")
  expect_equal(g$type, "code")
  expect_true(is.function(g$check_fn))
})

test_that("new_guardrail validates type", {
  expect_error(
    new_guardrail("test", "invalid", function(x) NULL),
    "type"
  )
})

test_that("new_guardrail validates check_fn", {
  expect_error(
    new_guardrail("test", "code", "not a function"),
    "is_function"
  )
})

test_that("guardrail_result creates valid result", {
  r <- guardrail_result(pass = TRUE)
  expect_s3_class(r, "guardrail_result")
  expect_true(r$pass)
  expect_null(r$reason)
  expect_equal(r$warnings, character(0))
  expect_equal(r$details, list())
})

test_that("guardrail_result with failure", {
  r <- guardrail_result(pass = FALSE, reason = "blocked")
  expect_false(r$pass)
  expect_equal(r$reason, "blocked")
})

test_that("guardrail_result with warnings and details", {
  r <- guardrail_result(
    pass = TRUE,
    warnings = c("w1", "w2"),
    details = list(score = 0.8)
  )
  expect_equal(r$warnings, c("w1", "w2"))
  expect_equal(r$details$score, 0.8)
})

test_that("guardrail_result validates inputs", {
  expect_error(guardrail_result(pass = "yes"))
  expect_error(guardrail_result(pass = NA))
  expect_error(guardrail_result(pass = c(TRUE, FALSE)))
  expect_error(guardrail_result(pass = TRUE, reason = 42))
})

test_that("run_guardrail executes check_fn", {
  g <- make_pass_guardrail()
  result <- run_guardrail(g, "x <- 1")
  expect_true(result$pass)
})

test_that("run_guardrail rejects non-guardrail", {
  expect_error(run_guardrail(list(), "x"), "secureguard")
})

test_that("compose_guardrails mode=all requires all pass", {
  g1 <- make_pass_guardrail()
  g2 <- make_pass_guardrail()
  composed <- compose_guardrails(g1, g2, mode = "all")
  result <- run_guardrail(composed, "test")
  expect_true(result$pass)

  g3 <- make_fail_guardrail("blocked")
  composed2 <- compose_guardrails(g1, g3, mode = "all")
  result2 <- run_guardrail(composed2, "test")
  expect_false(result2$pass)
  expect_match(result2$reason, "blocked")
})

test_that("compose_guardrails mode=any passes if one passes", {
  g1 <- make_pass_guardrail()
  g2 <- make_fail_guardrail("no")
  composed <- compose_guardrails(g1, g2, mode = "any")
  result <- run_guardrail(composed, "test")
  expect_true(result$pass)
})

test_that("compose_guardrails mode=any fails if all fail", {
  g1 <- make_fail_guardrail("no1")
  g2 <- make_fail_guardrail("no2")
  composed <- compose_guardrails(g1, g2, mode = "any")
  result <- run_guardrail(composed, "test")
  expect_false(result$pass)
  expect_match(result$reason, "no1")
})

test_that("compose_guardrails collects warnings", {
  g1 <- make_warn_guardrail("w1")
  g2 <- make_warn_guardrail("w2")
  composed <- compose_guardrails(g1, g2)
  result <- run_guardrail(composed, "test")
  expect_true(result$pass)
  expect_equal(result$warnings, c("w1", "w2"))
})

test_that("compose_guardrails rejects mixed types", {
  g1 <- make_pass_guardrail("code")
  g2 <- make_pass_guardrail("input")
  expect_error(compose_guardrails(g1, g2), "different types")
})

test_that("compose_guardrails rejects empty", {
  expect_error(compose_guardrails(), "At least one")
})

test_that("check_all collects all results", {
  g1 <- make_pass_guardrail()
  g2 <- make_fail_guardrail("blocked")
  g3 <- make_warn_guardrail("careful")

  result <- check_all(list(g1, g2, g3), "test")
  expect_false(result$pass)
  expect_length(result$results, 3)
  expect_equal(result$reasons, "blocked")
  expect_equal(result$warnings, "careful")
})

test_that("check_all passes when all pass", {
  g1 <- make_pass_guardrail()
  g2 <- make_pass_guardrail()
  result <- check_all(list(g1, g2), "test")
  expect_true(result$pass)
  expect_length(result$reasons, 0)
})

test_that("print.secureguard works", {
  g <- new_guardrail("test", "code", function(x) NULL, "A test")
  expect_message(print(g), "test")
})

test_that("print.guardrail_result works", {
  r <- guardrail_result(pass = TRUE)
  expect_message(print(r), "PASS")
  r2 <- guardrail_result(pass = FALSE, reason = "bad")
  expect_message(print(r2), "FAIL")
})
