test_that("guard_output_secrets blocks AWS key", {
  g <- guard_output_secrets()
  result <- run_guardrail(g, "AKIAIOSFODNN7EXAMPLE")
  expect_false(result$pass)
  expect_true(grepl("aws_key", result$reason))
})

test_that("guard_output_secrets blocks API key in string", {
  g <- guard_output_secrets()
  result <- run_guardrail(g, "api_key = 'sk_live_abc123def456ghi789jkl012'")
  expect_false(result$pass)
  expect_true(grepl("api_key", result$reason))
})

test_that("guard_output_secrets blocks private key header", {
  g <- guard_output_secrets(detect = "private_key")
  result <- run_guardrail(g, "-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
  expect_false(result$pass)
  expect_true(grepl("private_key", result$reason))
})

test_that("guard_output_secrets blocks GitHub token", {
  g <- guard_output_secrets(detect = "github_token")
  result <- run_guardrail(g, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl")
  expect_false(result$pass)
  expect_true(grepl("github_token", result$reason))
})

test_that("guard_output_secrets passes clean output", {
  g <- guard_output_secrets()
  result <- run_guardrail(g, "Just a normal sentence without secrets.")
  expect_true(result$pass)
})

test_that("guard_output_secrets detects only selected types", {
  g <- guard_output_secrets(detect = "aws_key")
  # Has API key but not checking for it
  result <- run_guardrail(g, "api_key = 'sk_live_abc123def456ghi789jkl012'")
  expect_true(result$pass)

  # Has AWS key and checking for it
  result2 <- run_guardrail(g, "AKIAIOSFODNN7EXAMPLE")
  expect_false(result2$pass)
})

# -- redact mode --

test_that("guard_output_secrets redacts AWS key", {
  g <- guard_output_secrets(action = "redact")
  result <- run_guardrail(g, "Key: AKIAIOSFODNN7EXAMPLE")
  expect_true(result$pass)
  expect_true(grepl("\\[REDACTED_AWS_KEY\\]", result$details$redacted_text))
  expect_false(grepl("AKIAIOSFODNN7EXAMPLE", result$details$redacted_text))
})

test_that("guard_output_secrets redacts API key", {
  g <- guard_output_secrets(detect = "api_key", action = "redact")
  result <- run_guardrail(
    g,
    "api_key = 'sk_live_abc123def456ghi789jkl012'"
  )
  expect_true(result$pass)
  expect_true(grepl("\\[REDACTED_API_KEY\\]", result$details$redacted_text))
})

# -- warn mode --

test_that("guard_output_secrets warns on secrets", {
  g <- guard_output_secrets(action = "warn")
  result <- run_guardrail(g, "AKIAIOSFODNN7EXAMPLE")
  expect_true(result$pass)
  expect_true(length(result$warnings) > 0)
  expect_true(any(grepl("aws_key", result$warnings)))
})

# -- data frame input --

test_that("guard_output_secrets scans data frame output", {
  g <- guard_output_secrets(detect = "aws_key")
  df <- data.frame(key = "AKIAIOSFODNN7EXAMPLE")
  result <- run_guardrail(g, df)
  expect_false(result$pass)
})

# -- validation --

test_that("guard_output_secrets rejects invalid detect types", {
  expect_error(guard_output_secrets(detect = "nonexistent"), "Unknown secret")
})

test_that("guard_output_secrets rejects non-character detect", {
  expect_error(guard_output_secrets(detect = 42), "character vector")
})

test_that("guard_output_secrets is type output", {
  g <- guard_output_secrets()
  expect_equal(g$type, "output")
  expect_s3_class(g, "secureguard")
})
