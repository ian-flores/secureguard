test_that("pii_patterns returns named list with expected types", {
  pats <- pii_patterns()
  expect_type(pats, "list")
  expect_named(pats, c(
    "ssn", "email", "phone", "credit_card", "ip_address_v4",
    "ip_address_v6", "phone_intl", "iban", "dob", "mac_address",
    "us_passport", "drivers_license", "itin", "vin"
  ))
  for (p in pats) {
    expect_type(p, "character")
    expect_length(p, 1L)
  }
})

# -- SSN --
test_that("detect_pii finds SSNs", {
  expect_length(detect_pii("SSN: 123-45-6789")$ssn, 1L)
  expect_equal(detect_pii("123-45-6789")$ssn, "123-45-6789")
  expect_length(detect_pii("SSN1 123-45-6789, SSN2 234-56-7890")$ssn, 2L)
  expect_equal(detect_pii("My SSN is 111-22-3333.")$ssn, "111-22-3333")
  # No-dash format
  expect_length(detect_pii("SSN: 123456789")$ssn, 1L)
})

test_that("detect_pii rejects invalid SSNs", {
  # Area number 000 is invalid

  expect_length(detect_pii("a 000-00-0000 b")$ssn, 0L)
  # Area number 666 is invalid
  expect_length(detect_pii("666-12-3456")$ssn, 0L)
  # Area number 9XX is invalid (reserved for ITIN)
  expect_length(detect_pii("900-12-3456")$ssn, 0L)
  # Group number 00 is invalid
  expect_length(detect_pii("123-00-6789")$ssn, 0L)
  # Serial number 0000 is invalid
  expect_length(detect_pii("123-45-0000")$ssn, 0L)
  # Wrong formats
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
test_that("detect_pii finds Luhn-valid credit card numbers", {
  # Visa (Luhn valid)
  expect_length(detect_pii("card: 4111111111111111")$credit_card, 1L)
  expect_length(detect_pii("4111-1111-1111-1111")$credit_card, 1L)
  expect_length(detect_pii("4111 1111 1111 1111")$credit_card, 1L)
  # Mastercard (Luhn valid)
  expect_length(detect_pii("5500000000000004")$credit_card, 1L)
  # Amex (Luhn valid, 15 digit)
  expect_length(detect_pii("378282246310005")$credit_card, 1L)
  # Discover (Luhn valid)
  expect_length(detect_pii("6011111111111117")$credit_card, 1L)
})

test_that("detect_pii rejects Luhn-invalid credit card numbers", {
  # Visa prefix but bad checksum
  expect_length(detect_pii("4111111111111112")$credit_card, 0L)
  # Mastercard prefix but bad checksum
  expect_length(detect_pii("5500000000000005")$credit_card, 0L)
})

test_that("detect_pii rejects non-credit-cards", {
  expect_length(detect_pii("1234")$credit_card, 0L)
  expect_length(detect_pii("no card")$credit_card, 0L)
  expect_length(detect_pii("12345678")$credit_card, 0L)
  expect_length(detect_pii("not a number")$credit_card, 0L)
  expect_length(detect_pii("1234-5678")$credit_card, 0L)
})

# -- IP Address v4 --
test_that("detect_pii finds IPv4 addresses", {
  expect_equal(detect_pii("ip: 192.168.1.1")$ip_address_v4, "192.168.1.1")
  expect_length(detect_pii("10.0.0.1 and 10.0.0.2")$ip_address_v4, 2L)
  expect_length(detect_pii("server at 255.255.255.0")$ip_address_v4, 1L)
  expect_length(detect_pii("0.0.0.0")$ip_address_v4, 1L)
  expect_length(detect_pii("127.0.0.1")$ip_address_v4, 1L)
})

test_that("detect_pii rejects non-IPv4", {
  expect_length(detect_pii("999.999.999.999")$ip_address_v4, 0L)
  expect_length(detect_pii("no ip")$ip_address_v4, 0L)
  expect_length(detect_pii("1.2.3")$ip_address_v4, 0L)
  expect_length(detect_pii("256.1.1.1")$ip_address_v4, 0L)
  expect_length(detect_pii("just text")$ip_address_v4, 0L)
})

# -- IP Address v6 --
test_that("detect_pii finds IPv6 addresses", {
  expect_length(detect_pii("ipv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334")$ip_address_v6, 1L)
  expect_length(detect_pii("fe80:0000:0000:0000:0000:0000:0000:0001")$ip_address_v6, 1L)
  expect_length(detect_pii("::1")$ip_address_v6, 1L)
  expect_length(detect_pii("2001:db8::")$ip_address_v6, 1L)
  expect_length(detect_pii("::ffff:192.0.2.1")$ip_address_v6, 1L)
})

test_that("detect_pii rejects non-IPv6", {
  expect_length(detect_pii("not an ip")$ip_address_v6, 0L)
  expect_length(detect_pii("12345")$ip_address_v6, 0L)
  expect_length(detect_pii("just text here")$ip_address_v6, 0L)
  expect_length(detect_pii("192.168.1.1")$ip_address_v6, 0L)
  expect_length(detect_pii("hello world")$ip_address_v6, 0L)
})

# -- Phone International (E.164) --
test_that("detect_pii finds international phone numbers", {
  expect_length(detect_pii("call +14155552671")$phone_intl, 1L)
  expect_length(detect_pii("number: +442071234567")$phone_intl, 1L)
  expect_length(detect_pii("+61412345678")$phone_intl, 1L)
  expect_length(detect_pii("phone +81312345678")$phone_intl, 1L)
  expect_length(detect_pii("+5511987654321")$phone_intl, 1L)
})

test_that("detect_pii rejects non-international-phones", {
  expect_length(detect_pii("+12345")$phone_intl, 0L)
  expect_length(detect_pii("+0123456789")$phone_intl, 0L)
  expect_length(detect_pii("5551234567")$phone_intl, 0L)
  expect_length(detect_pii("no phone")$phone_intl, 0L)
  expect_length(detect_pii("+")$phone_intl, 0L)
})

# -- IBAN --
test_that("detect_pii finds IBANs", {
  expect_length(detect_pii("IBAN: GB29NWBK60161331926819")$iban, 1L)
  expect_length(detect_pii("DE89370400440532013000")$iban, 1L)
  expect_length(detect_pii("FR76 3000 6000 0112 3456 7890 189")$iban, 1L)
  expect_length(detect_pii("account: ES9121000418450200051332")$iban, 1L)
  expect_length(detect_pii("NL91ABNA0417164300")$iban, 1L)
})

test_that("detect_pii rejects non-IBANs", {
  expect_length(detect_pii("not an iban")$iban, 0L)
  expect_length(detect_pii("AB12")$iban, 0L)
  expect_length(detect_pii("12345678901234")$iban, 0L)
  expect_length(detect_pii("just text")$iban, 0L)
  expect_length(detect_pii("hello world")$iban, 0L)
})

# -- Date of Birth --
test_that("detect_pii finds dates of birth", {
  expect_length(detect_pii("date of birth: 01/15/1990")$dob, 1L)
  expect_length(detect_pii("DOB: 03-22-1985")$dob, 1L)
  expect_length(detect_pii("birthday: 12.25.2000")$dob, 1L)
  expect_length(detect_pii("born on: 7/4/76")$dob, 1L)
  expect_length(detect_pii("dob 11/30/1955")$dob, 1L)
})

test_that("detect_pii rejects non-DOBs", {
  expect_length(detect_pii("01/15/1990")$dob, 0L)
  expect_length(detect_pii("the date was 2023-01-01")$dob, 0L)
  expect_length(detect_pii("no date here")$dob, 0L)
  expect_length(detect_pii("12/25/2000")$dob, 0L)
  expect_length(detect_pii("just a date 03-22-1985")$dob, 0L)
})

# -- MAC Address --
test_that("detect_pii finds MAC addresses", {
  expect_length(detect_pii("mac: 00:1A:2B:3C:4D:5E")$mac_address, 1L)
  expect_length(detect_pii("AA:BB:CC:DD:EE:FF")$mac_address, 1L)
  expect_length(detect_pii("device 01-23-45-67-89-ab")$mac_address, 1L)
  expect_length(detect_pii("ff:ff:ff:ff:ff:ff")$mac_address, 1L)
  expect_length(detect_pii("MAC is 00:00:00:00:00:00")$mac_address, 1L)
})

test_that("detect_pii rejects non-MACs", {
  expect_length(detect_pii("not a mac")$mac_address, 0L)
  expect_length(detect_pii("00:1A:2B")$mac_address, 0L)
  expect_length(detect_pii("GG:HH:II:JJ:KK:LL")$mac_address, 0L)
  expect_length(detect_pii("12345678")$mac_address, 0L)
  expect_length(detect_pii("just text")$mac_address, 0L)
})

# -- US Passport --
test_that("detect_pii finds US passport numbers", {
  expect_length(detect_pii("passport: 123456789")$us_passport, 1L)
  expect_length(detect_pii("Passport Number: AB1234567")$us_passport, 1L)
  expect_length(detect_pii("passport no C12345")$us_passport, 1L)
  expect_length(detect_pii("PASSPORT#D23456")$us_passport, 1L)
  expect_length(detect_pii("passport num 987654")$us_passport, 1L)
})

test_that("detect_pii rejects non-passport numbers", {
  expect_length(detect_pii("123456789")$us_passport, 0L)
  expect_length(detect_pii("not a passport")$us_passport, 0L)
  expect_length(detect_pii("AB1234567")$us_passport, 0L)
  expect_length(detect_pii("just text")$us_passport, 0L)
  expect_length(detect_pii("pass 12345")$us_passport, 0L)
})

# -- Driver's License --
test_that("detect_pii finds driver's license numbers", {
  expect_length(detect_pii("driver's license: D1234567")$drivers_license, 1L)
  expect_length(detect_pii("DL: 12345678")$drivers_license, 1L)
  expect_length(detect_pii("drivers license number AB12345")$drivers_license, 1L)
  expect_length(detect_pii("Driver License # S12345678")$drivers_license, 1L)
  expect_length(detect_pii("DL num A1234")$drivers_license, 1L)
})

test_that("detect_pii rejects non-DL numbers", {
  expect_length(detect_pii("D1234567")$drivers_license, 0L)
  expect_length(detect_pii("not a license")$drivers_license, 0L)
  expect_length(detect_pii("12345678")$drivers_license, 0L)
  expect_length(detect_pii("just text")$drivers_license, 0L)
  expect_length(detect_pii("license to drive")$drivers_license, 0L)
})

# -- ITIN --
test_that("detect_pii finds ITINs", {
  # 9XX-7X group
  expect_length(detect_pii("ITIN: 912-70-1234")$itin, 1L)
  expect_length(detect_pii("tax id 999-78-5678")$itin, 1L)
  # 9XX-8X group
  expect_length(detect_pii("itin: 950-80-4321")$itin, 1L)
  expect_length(detect_pii("number 911-88-9999")$itin, 1L)
  # 9XX-9[0-2,4-9]X group
  expect_length(detect_pii("id: 900-90-1111")$itin, 1L)
})

test_that("detect_pii rejects non-ITINs", {
  # Not starting with 9
  expect_length(detect_pii("123-70-1234")$itin, 0L)
  # Middle group 93 is invalid for ITIN
  expect_length(detect_pii("900-93-1234")$itin, 0L)
  # Middle group not 7X or 8X
  expect_length(detect_pii("900-50-1234")$itin, 0L)
  # Regular SSN format (not 9XX start)
  expect_length(detect_pii("123-45-6789")$itin, 0L)
  expect_length(detect_pii("not an itin")$itin, 0L)
})

# -- VIN --
test_that("detect_pii finds VINs", {
  expect_length(detect_pii("VIN: 1HGBH41JXMN109186")$vin, 1L)
  expect_length(detect_pii("vin:1FTFW1EF1EKE12345")$vin, 1L)
  expect_length(detect_pii("VIN 5YJSA1E11HF000001")$vin, 1L)
  expect_length(detect_pii("vin WBA3A5C55CF256789")$vin, 1L)
  expect_length(detect_pii("VIN: WVWZZZ3CZWE123456")$vin, 1L)
})

test_that("detect_pii rejects non-VINs", {
  # VIN without keyword
  expect_length(detect_pii("1HGBH41JXMN109186")$vin, 0L)
  # Too short
  expect_length(detect_pii("VIN: 1HGBH41J")$vin, 0L)
  # Contains invalid chars (I, O, Q)
  expect_length(detect_pii("VIN: 1HGBH41IXMN109186")$vin, 0L)
  expect_length(detect_pii("not a vin")$vin, 0L)
  expect_length(detect_pii("VIN: short")$vin, 0L)
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
