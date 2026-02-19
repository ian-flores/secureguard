test_that("output_to_text handles character vectors", {
  expect_equal(output_to_text("hello"), "hello")
  expect_equal(output_to_text(c("a", "b", "c")), "a\nb\nc")
})

test_that("output_to_text handles data frames", {
  df <- data.frame(x = 1:2)
  text <- output_to_text(df)
  expect_true(grepl("x", text))
  expect_true(grepl("1", text))
})

test_that("output_to_text handles lists", {
  lst <- list(a = 1, b = "hello")
  text <- output_to_text(lst)
  expect_true(nchar(text) > 0)
})

test_that("output_to_text handles other objects", {
  text <- output_to_text(42)
  expect_true(grepl("42", text))
})

# -- guard_output_pii: block mode --

test_that("guard_output_pii blocks SSN in string", {
  g <- guard_output_pii()
  result <- run_guardrail(g, "My SSN is 123-45-6789")
  expect_false(result$pass)
  expect_true(grepl("ssn", result$reason))
  expect_true(length(result$details$matches$ssn) > 0)
})

test_that("guard_output_pii blocks email in data frame", {
  g <- guard_output_pii(detect = "email")
  df <- data.frame(name = "Alice", email = "alice@example.com")
  result <- run_guardrail(g, df)
  expect_false(result$pass)
  expect_true(grepl("email", result$reason))
})

test_that("guard_output_pii passes clean output", {
  g <- guard_output_pii()
  result <- run_guardrail(g, "No PII here, just a normal sentence.")
  expect_true(result$pass)
})

test_that("guard_output_pii detects only selected types", {
  g <- guard_output_pii(detect = "ssn")
  result <- run_guardrail(g, "email: test@example.com, SSN: 123-45-6789")
  expect_false(result$pass)
  # Only ssn should be reported

  expect_true("ssn" %in% names(result$details$matches))
  expect_false("email" %in% names(result$details$matches))
})

# -- guard_output_pii: redact mode --

test_that("guard_output_pii redacts SSN", {
  g <- guard_output_pii(action = "redact")
  result <- run_guardrail(g, "My SSN is 123-45-6789")
  expect_true(result$pass)
  expect_true(grepl("\\[REDACTED_SSN\\]", result$details$redacted_text))
  expect_false(grepl("123-45-6789", result$details$redacted_text))
})

test_that("guard_output_pii redacts email", {
  g <- guard_output_pii(detect = "email", action = "redact")
  result <- run_guardrail(g, "Contact alice@example.com for info")
  expect_true(result$pass)
  expect_true(grepl("\\[REDACTED_EMAIL\\]", result$details$redacted_text))
})

# -- guard_output_pii: warn mode --

test_that("guard_output_pii warns on PII", {
  g <- guard_output_pii(action = "warn")
  result <- run_guardrail(g, "My SSN is 123-45-6789")
  expect_true(result$pass)
  expect_true(length(result$warnings) > 0)
  expect_true(any(grepl("ssn", result$warnings)))
})

# -- validation --

test_that("guard_output_pii rejects invalid detect types", {
  expect_error(guard_output_pii(detect = "nonexistent"), "Unknown PII type")
})

test_that("guard_output_pii rejects non-character detect", {
  expect_error(guard_output_pii(detect = 42), "character vector")
})

test_that("guard_output_pii is type output", {
  g <- guard_output_pii()
  expect_equal(g$type, "output")
  expect_s3_class(g, "secureguard")
})
