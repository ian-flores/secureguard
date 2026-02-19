test_that("secret_patterns returns named list with expected types", {
  pats <- secret_patterns()
  expect_type(pats, "list")
  expect_named(
    pats,
    c("api_key", "aws_key", "password", "token", "private_key", "github_token")
  )
  for (p in pats) {
    expect_type(p, "character")
    expect_length(p, 1L)
  }
})

# -- API Key --
test_that("detect_secrets finds API keys", {
  expect_length(detect_secrets("api_key = 'sk_live_abc123def456ghi789jkl0'")$api_key, 1L)
  expect_length(detect_secrets("API-KEY: abcdefghijklmnopqrst1234")$api_key, 1L)
  expect_length(detect_secrets("apiKey=ABCDEFGHIJKLMNOPQRSTUVWXYZ")$api_key, 1L)
  expect_length(detect_secrets("my api_key = very_long_key_value_1234567890")$api_key, 1L)
  expect_length(detect_secrets("API_KEY='a1b2c3d4e5f6g7h8i9j0k1l2'")$api_key, 1L)
})

test_that("detect_secrets rejects non-API-keys", {
  expect_length(detect_secrets("no secrets here")$api_key, 0L)
  expect_length(detect_secrets("api_key = short")$api_key, 0L)
  expect_length(detect_secrets("just a regular sentence")$api_key, 0L)
  expect_length(detect_secrets("api documentation link")$api_key, 0L)
  expect_length(detect_secrets("key = 123")$api_key, 0L)
})

# -- AWS Key --
test_that("detect_secrets finds AWS keys", {
  expect_length(detect_secrets("AKIAIOSFODNN7EXAMPLE")$aws_key, 1L)
  expect_length(detect_secrets("key: ASIAIOSFODNN7EXAMPLE")$aws_key, 1L)
  expect_length(detect_secrets("aws AKIAI44QH8DHBEXAMPLE")$aws_key, 1L)
  expect_length(detect_secrets("AKIAEXAMPLEKEYID1234")$aws_key, 1L)
  expect_equal(
    detect_secrets("creds: AKIAIOSFODNN7EXAMPLE")$aws_key,
    "AKIAIOSFODNN7EXAMPLE"
  )
})

test_that("detect_secrets rejects non-AWS-keys", {
  expect_length(detect_secrets("AKIA")$aws_key, 0L)
  expect_length(detect_secrets("no aws here")$aws_key, 0L)
  expect_length(detect_secrets("AKIAlowercase1234567")$aws_key, 0L)
  expect_length(detect_secrets("ABCDEFGHIJKLMNOPQRST")$aws_key, 0L)
  expect_length(detect_secrets("random text")$aws_key, 0L)
})

# -- Password --
test_that("detect_secrets finds passwords", {
  expect_length(detect_secrets("password = mysecretpassword")$password, 1L)
  expect_length(detect_secrets("PASSWORD: longpassword123")$password, 1L)
  expect_length(detect_secrets("password='super_secret!'")$password, 1L)
  expect_length(detect_secrets("Password=Str0ngP@ss!")$password, 1L)
  expect_length(detect_secrets("password = \"verylongpassword\"")$password, 1L)
})

test_that("detect_secrets rejects non-passwords", {
  expect_length(detect_secrets("no password here")$password, 0L)
  expect_length(detect_secrets("password = short")$password, 0L)
  expect_length(detect_secrets("just words")$password, 0L)
  expect_length(detect_secrets("passw0rd mention")$password, 0L)
  expect_length(detect_secrets("enter your password")$password, 0L)
})

# -- Token --
test_that("detect_secrets finds tokens", {
  expect_length(detect_secrets("bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")$token, 1L)
  expect_length(detect_secrets("Authorization: Bearer abc123def456ghi789jkl0")$token, 1L)
  expect_length(detect_secrets("auth = 'very_long_auth_token_value_123'")$token, 1L)
  expect_length(detect_secrets("Bearer abcdefghijklmnopqrstu")$token, 1L)
  expect_length(detect_secrets("authorization=tok_1234567890abcdefgh")$token, 1L)
})

test_that("detect_secrets rejects non-tokens", {
  expect_length(detect_secrets("no token here")$token, 0L)
  expect_length(detect_secrets("bear with me")$token, 0L)
  expect_length(detect_secrets("authorize access")$token, 0L)
  expect_length(detect_secrets("random words")$token, 0L)
  expect_length(detect_secrets("bearer ab")$token, 0L)
})

# -- Private Key --
test_that("detect_secrets finds private key headers", {
  expect_length(
    detect_secrets("-----BEGIN RSA PRIVATE KEY-----")$private_key, 1L
  )
  expect_length(
    detect_secrets("-----BEGIN PRIVATE KEY-----")$private_key, 1L
  )
  expect_length(
    detect_secrets("-----BEGIN EC PRIVATE KEY-----")$private_key, 1L
  )
  expect_length(
    detect_secrets("-----BEGIN DSA PRIVATE KEY-----")$private_key, 1L
  )
  expect_length(
    detect_secrets("-----BEGIN OPENSSH PRIVATE KEY-----")$private_key, 1L
  )
})

test_that("detect_secrets rejects non-private-keys", {
  expect_length(detect_secrets("-----BEGIN PUBLIC KEY-----")$private_key, 0L)
  expect_length(detect_secrets("no key here")$private_key, 0L)
  expect_length(detect_secrets("BEGIN PRIVATE")$private_key, 0L)
  expect_length(detect_secrets("private key mentioned")$private_key, 0L)
  expect_length(
    detect_secrets("-----BEGIN CERTIFICATE-----")$private_key, 0L
  )
})

# -- GitHub Token --
test_that("detect_secrets finds GitHub tokens", {
  fake36 <- paste0(rep("a", 36), collapse = "")
  expect_length(detect_secrets(paste0("ghp_", fake36))$github_token, 1L)
  expect_length(detect_secrets(paste0("gho_", fake36))$github_token, 1L)
  expect_length(detect_secrets(paste0("ghu_", fake36))$github_token, 1L)
  expect_length(detect_secrets(paste0("ghs_", fake36))$github_token, 1L)
  expect_length(detect_secrets(paste0("ghr_", fake36))$github_token, 1L)
})

test_that("detect_secrets rejects non-GitHub-tokens", {
  expect_length(detect_secrets("ghp_short")$github_token, 0L)
  expect_length(detect_secrets("ghx_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")$github_token, 0L)
  expect_length(detect_secrets("no github token")$github_token, 0L)
  expect_length(detect_secrets("gh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")$github_token, 0L)
  expect_length(detect_secrets("just text")$github_token, 0L)
})

# -- API / edge cases --
test_that("detect_secrets validates text argument", {
  expect_error(detect_secrets(42), "single character string")
  expect_error(detect_secrets(c("a", "b")), "single character string")
})

test_that("detect_secrets filters by types", {
  result <- detect_secrets("AKIAIOSFODNN7EXAMPLE", types = "aws_key")
  expect_named(result, "aws_key")
  expect_length(result$aws_key, 1L)
})

test_that("detect_secrets rejects unknown types", {
  expect_error(detect_secrets("test", types = "ssh_key"), "Unknown secret type")
})

test_that("detect_secrets returns empty for clean text", {
  result <- detect_secrets("This is clean text with no secrets at all.")
  for (nm in names(result)) {
    expect_length(result[[nm]], 0L)
  }
})
