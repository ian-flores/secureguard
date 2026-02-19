test_that("pii_patterns returns named list with expected types", {
  pats <- pii_patterns()
  expect_type(pats, "list")
  expect_named(pats, c("ssn", "email", "phone", "credit_card", "ip_address"))
  for (p in pats) {
    expect_type(p, "character")
    expect_length(p, 1L)
  }
})

# -- SSN --
test_that("detect_pii finds SSNs", {
  expect_length(detect_pii("SSN: 123-45-6789")$ssn, 1L)
  expect_equal(detect_pii("123-45-6789")$ssn, "123-45-6789")
  expect_length(detect_pii("a 000-00-0000 b")$ssn, 1L)
  expect_length(detect_pii("SSN1 123-45-6789, SSN2 987-65-4321")$ssn, 2L)
  expect_equal(detect_pii("My SSN is 111-22-3333.")$ssn, "111-22-3333")
})

test_that("detect_pii rejects non-SSNs", {
  expect_length(detect_pii("123-456-789")$ssn, 0L)
  expect_length(detect_pii("12-34-5678")$ssn, 0L)
  expect_length(detect_pii("1234-56-7890")$ssn, 0L)
  expect_length(detect_pii("phone: 555-1234")$ssn, 0L)
  expect_length(detect_pii("no pii here")$ssn, 0L)
})

# -- Email --
test_that("detect_pii finds emails", {
  expect_equal(detect_pii("email: test@example.com")$email, "test@example.com")
  expect_length(detect_pii("user.name+tag@domain.co.uk")$email, 1L)
  expect_length(detect_pii("a@b.cc and c@d.ee")$email, 2L)
  expect_length(detect_pii("first.last@company.org")$email, 1L)
  expect_length(detect_pii("underscore_user@host.net")$email, 1L)
})

test_that("detect_pii rejects non-emails", {
  expect_length(detect_pii("not an email")$email, 0L)
  expect_length(detect_pii("@@invalid")$email, 0L)
  expect_length(detect_pii("user@")$email, 0L)
  expect_length(detect_pii("just words")$email, 0L)
  expect_length(detect_pii("@domain.com")$email, 0L)
})

# -- Phone --
test_that("detect_pii finds phone numbers", {
  expect_length(detect_pii("call 555-123-4567")$phone, 1L)
  expect_length(detect_pii("(555) 123-4567")$phone, 1L)
  expect_length(detect_pii("+1-555-123-4567")$phone, 1L)
  expect_length(detect_pii("1.555.123.4567")$phone, 1L)
  expect_length(detect_pii("555 123 4567")$phone, 1L)
})

test_that("detect_pii rejects non-phones", {
  expect_length(detect_pii("123")$phone, 0L)
  expect_length(detect_pii("no phone here")$phone, 0L)
  expect_length(detect_pii("12-34")$phone, 0L)
  expect_length(detect_pii("just text")$phone, 0L)
  expect_length(detect_pii("abc-def-ghij")$phone, 0L)
})

# -- Credit Card --
test_that("detect_pii finds credit card numbers", {
  expect_length(detect_pii("card: 4111111111111111")$credit_card, 1L)
  expect_length(detect_pii("4111-1111-1111-1111")$credit_card, 1L)
  expect_length(detect_pii("4111 1111 1111 1111")$credit_card, 1L)
  expect_length(detect_pii("5500-0000-0000-0004")$credit_card, 1L)
  expect_length(detect_pii("CC 3400 0000 0000 0009")$credit_card, 1L)
})

test_that("detect_pii rejects non-credit-cards", {
  expect_length(detect_pii("1234")$credit_card, 0L)
  expect_length(detect_pii("no card")$credit_card, 0L)
  expect_length(detect_pii("12345678")$credit_card, 0L)
  expect_length(detect_pii("not a number")$credit_card, 0L)
  expect_length(detect_pii("1234-5678")$credit_card, 0L)
})

# -- IP Address --
test_that("detect_pii finds IP addresses", {
  expect_equal(detect_pii("ip: 192.168.1.1")$ip_address, "192.168.1.1")
  expect_length(detect_pii("10.0.0.1 and 10.0.0.2")$ip_address, 2L)
  expect_length(detect_pii("server at 255.255.255.0")$ip_address, 1L)
  expect_length(detect_pii("0.0.0.0")$ip_address, 1L)
  expect_length(detect_pii("127.0.0.1")$ip_address, 1L)
})

test_that("detect_pii rejects non-IPs", {
  expect_length(detect_pii("999.999.999.999")$ip_address, 0L)
  expect_length(detect_pii("no ip")$ip_address, 0L)
  expect_length(detect_pii("1.2.3")$ip_address, 0L)
  expect_length(detect_pii("256.1.1.1")$ip_address, 0L)
  expect_length(detect_pii("just text")$ip_address, 0L)
})

# -- API / edge cases --
test_that("detect_pii validates text argument", {
  expect_error(detect_pii(42), "single character string")
  expect_error(detect_pii(c("a", "b")), "single character string")
})

test_that("detect_pii filters by types", {
  result <- detect_pii("test@example.com 123-45-6789", types = "email")
  expect_named(result, "email")
  expect_length(result$email, 1L)
})

test_that("detect_pii rejects unknown types", {
  expect_error(detect_pii("test", types = "passport"), "Unknown PII type")
})

test_that("detect_pii returns empty for clean text", {
  result <- detect_pii("This is a perfectly clean sentence with no PII.")
  for (nm in names(result)) {
    expect_length(result[[nm]], 0L)
  }
})
