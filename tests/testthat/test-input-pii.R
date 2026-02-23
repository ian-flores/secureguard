test_that("guard_input_pii creates valid guardrail", {
  g <- guard_input_pii()
  expect_true(S7::S7_inherits(g, secureguard_class))
  expect_equal(g@type, "input")
  expect_equal(g@name, "input_pii")
})

# -- Block mode --
test_that("guard_input_pii blocks input with SSN", {
  g <- guard_input_pii()
  r <- run_guardrail(g, "My SSN is 123-45-6789")
  expect_false(r@pass)
  expect_match(r@reason, "PII detected")
  expect_match(r@reason, "ssn")
  expect_true("ssn" %in% names(r@details$matches))
})

test_that("guard_input_pii blocks input with email", {
  g <- guard_input_pii()
  r <- run_guardrail(g, "Contact me at user@example.com")
  expect_false(r@pass)
  expect_match(r@reason, "email")
})

test_that("guard_input_pii blocks input with phone", {
  g <- guard_input_pii()
  r <- run_guardrail(g, "Call me at 555-123-4567")
  expect_false(r@pass)
  expect_match(r@reason, "phone")
})

test_that("guard_input_pii blocks input with credit card", {
  g <- guard_input_pii()
  r <- run_guardrail(g, "My card is 4111-1111-1111-1111")
  expect_false(r@pass)
  expect_match(r@reason, "credit_card")
})

test_that("guard_input_pii blocks input with multiple PII types", {
  g <- guard_input_pii()
  r <- run_guardrail(g, "SSN: 123-45-6789, email: test@example.com")
  expect_false(r@pass)
  expect_true("ssn" %in% names(r@details$matches))
  expect_true("email" %in% names(r@details$matches))
})

test_that("guard_input_pii passes clean input", {
  g <- guard_input_pii()

  r <- run_guardrail(g, "Please help me with R code")
  expect_true(r@pass)

  r2 <- run_guardrail(g, "What is the mean of c(1, 2, 3)?")
  expect_true(r2@pass)

  r3 <- run_guardrail(g, "How do I read a CSV file?")
  expect_true(r3@pass)

  r4 <- run_guardrail(g, "Explain linear regression")
  expect_true(r4@pass)

  r5 <- run_guardrail(g, "Write a function to sort a vector")
  expect_true(r5@pass)
})

# -- Warn mode --
test_that("guard_input_pii warns instead of blocking when action=warn", {
  g <- guard_input_pii(action = "warn")

  r <- run_guardrail(g, "My SSN is 123-45-6789")
  expect_true(r@pass)
  expect_true(length(r@warnings) > 0L)
  expect_true(any(grepl("ssn", r@warnings)))
  expect_true("ssn" %in% names(r@details$matches))
})

test_that("guard_input_pii warn mode passes clean input without warnings", {
  g <- guard_input_pii(action = "warn")
  r <- run_guardrail(g, "Just normal text")
  expect_true(r@pass)
  expect_length(r@warnings, 0L)
})

# -- Custom detect types --
test_that("guard_input_pii respects custom detect types", {
  g <- guard_input_pii(detect = "ssn")

  # SSN should be caught

  r <- run_guardrail(g, "SSN: 123-45-6789")
  expect_false(r@pass)

  # Email should NOT be caught since we only check SSN
  r2 <- run_guardrail(g, "Contact: user@example.com")
  expect_true(r2@pass)
})

test_that("guard_input_pii detects ip_address_v4 when requested", {
  g <- guard_input_pii(detect = c("ssn", "ip_address_v4"))
  r <- run_guardrail(g, "Server at 192.168.1.1")
  expect_false(r@pass)
  expect_match(r@reason, "ip_address_v4")
})

# -- Validation --
test_that("guard_input_pii rejects unknown PII types", {
  expect_error(
    guard_input_pii(detect = "passport"),
    "Unknown PII type"
  )
})

test_that("guard_input_pii rejects non-string input at runtime", {
  g <- guard_input_pii()
  expect_error(run_guardrail(g, 42), "single character string")
})

test_that("guard_input_pii match counts are correct", {
  g <- guard_input_pii()
  # Use two valid SSNs (987-65-4321 is now rejected as 9XX area is ITIN range)
  r <- run_guardrail(g, "SSN1: 123-45-6789, SSN2: 234-56-7890")
  expect_false(r@pass)
  expect_length(r@details$matches$ssn, 2L)
  expect_match(r@reason, "2")
})
