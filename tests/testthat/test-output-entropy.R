# -- shannon_entropy --

test_that("shannon_entropy returns 0 for empty string", {
  expect_equal(shannon_entropy(""), 0)
})

test_that("shannon_entropy returns 0 for single repeated char", {
  expect_equal(shannon_entropy("aaaaaa"), 0)
  expect_equal(shannon_entropy("BBBBBBBBB"), 0)
})

test_that("shannon_entropy returns positive for mixed chars", {
  e <- shannon_entropy("ab")
  expect_true(e > 0)
  # "ab" has entropy of exactly 1 bit (2 equally frequent chars)
  expect_equal(e, 1.0)
})

test_that("shannon_entropy increases with more unique chars", {
  e2 <- shannon_entropy("ab")        # 2 unique chars -> 1 bit
  e4 <- shannon_entropy("abcd")      # 4 unique chars -> 2 bits
  e8 <- shannon_entropy("abcdefgh")  # 8 unique chars -> 3 bits
  expect_true(e4 > e2)
  expect_true(e8 > e4)
  expect_equal(e2, 1.0)
  expect_equal(e4, 2.0)
  expect_equal(e8, 3.0)
})

test_that("shannon_entropy validates input", {
  expect_error(shannon_entropy(42), "single character string")
  expect_error(shannon_entropy(c("a", "b")), "single character string")
  expect_error(shannon_entropy(NULL), "single character string")
})

# -- is_high_entropy --

test_that("is_high_entropy rejects short strings", {
  # String shorter than min_length (default 20) always returns FALSE
  expect_false(is_high_entropy("aB3$xK9!"))
  expect_false(is_high_entropy("short"))
  expect_false(is_high_entropy(""))
})

test_that("is_high_entropy detects high entropy base64", {
  # A string with many unique chars over 20 chars -> high entropy
  # This random-looking base64 string should have entropy > 4.5
  token <- "aB3xK9pQ2mR7nL4wS8vDfG5hJ6k"
  expect_true(nchar(token) >= 20)
  expect_true(shannon_entropy(token) > 4.5)
  expect_true(is_high_entropy(token))
})

test_that("is_high_entropy detects high entropy hex", {
  # hex string with high entropy (> 3.0)
  # 20+ hex chars with good distribution
  hex_token <- "a1b2c3d4e5f6a7b8c9d0e1f2"
  expect_true(nchar(hex_token) >= 20)
  expect_true(grepl("^[0-9a-fA-F]+$", hex_token))
  expect_true(shannon_entropy(hex_token) > 3.0)
  expect_true(is_high_entropy(hex_token))
})

test_that("is_high_entropy rejects low entropy long strings", {
  # Repeated chars -- low entropy even if long
  expect_false(is_high_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaa"))
  # Alternating two chars -- entropy = 1.0, well below threshold

  expect_false(is_high_entropy("abababababababababababab"))
})

test_that("is_high_entropy respects custom thresholds", {
  # Use a base64-like token (NOT hex-only) with moderate entropy
  # "aBcDeFgH..." contains uppercase so it's NOT matched by hex regex
  token <- "aBcDeFgHaBcDeFgHaBcDeFgH"  # entropy ~3.0, base64-like
  expect_true(nchar(token) >= 20)
  expect_false(grepl("^[0-9a-fA-F]+$", token))  # not hex
  expect_false(is_high_entropy(token))  # default base64_threshold 4.5 -> FALSE
  expect_true(is_high_entropy(token, base64_threshold = 1.0))  # lowered -> TRUE
})

test_that("is_high_entropy respects custom hex threshold", {
  # hex string with moderate entropy (~2.58)
  hex_mod <- "aabb11223344aabb11223344"
  expect_true(grepl("^[0-9a-fA-F]+$", hex_mod))
  e <- shannon_entropy(hex_mod)
  # entropy ~2.58, default hex_threshold = 3.0, so should be FALSE
  expect_true(e > 2.0 && e < 3.0)
  expect_false(is_high_entropy(hex_mod))
  # Lower hex threshold to 2.0 -> TRUE
  expect_true(is_high_entropy(hex_mod, hex_threshold = 2.0))
})

test_that("is_high_entropy validates input", {
  expect_error(is_high_entropy(42), "single character string")
  expect_error(is_high_entropy(c("a", "b")), "single character string")
})

# -- guard_output_entropy: block mode --

test_that("guard_output_entropy blocks high entropy tokens", {
  g <- guard_output_entropy()
  # Embed a high-entropy token in a sentence
  high_ent <- "aB3xK9pQ2mR7nL4wS8vDfG5hJ6k"
  text <- paste("The token is", high_ent)
  result <- run_guardrail(g, text)
  expect_false(result@pass)
  expect_true(grepl("High-entropy", result@reason))
  expect_true(high_ent %in% result@details$flagged_tokens)
})

test_that("guard_output_entropy passes clean text", {
  g <- guard_output_entropy()
  result <- run_guardrail(g, "This is a normal sentence with no secrets.")
  expect_true(result@pass)
})

test_that("guard_output_entropy passes text with only short tokens", {
  g <- guard_output_entropy()
  result <- run_guardrail(g, "short words only here nothing long")
  expect_true(result@pass)
})

test_that("guard_output_entropy blocks multiple high entropy tokens", {
  g <- guard_output_entropy()
  tok1 <- "aB3xK9pQ2mR7nL4wS8vDfG5hJ6k"
  tok2 <- "Zp9Wq8Xr7Ys6Vt5Uw4Ex3Dy2Cz1"
  text <- paste("First:", tok1, "Second:", tok2)
  result <- run_guardrail(g, text)
  expect_false(result@pass)
  expect_true(grepl("2 tokens", result@reason))
})

# -- guard_output_entropy: redact mode --

test_that("guard_output_entropy redacts high entropy tokens", {
  g <- guard_output_entropy(action = "redact")
  high_ent <- "aB3xK9pQ2mR7nL4wS8vDfG5hJ6k"
  text <- paste("The token is", high_ent, "in context")
  result <- run_guardrail(g, text)
  expect_true(result@pass)
  expect_true(grepl("\\[HIGH_ENTROPY\\]", result@details$redacted_text))
  expect_false(grepl(high_ent, result@details$redacted_text, fixed = TRUE))
  expect_true(high_ent %in% result@details$flagged_tokens)
})

# -- guard_output_entropy: warn mode --

test_that("guard_output_entropy warns on high entropy tokens", {
  g <- guard_output_entropy(action = "warn")
  high_ent <- "aB3xK9pQ2mR7nL4wS8vDfG5hJ6k"
  text <- paste("The token is", high_ent)
  result <- run_guardrail(g, text)
  expect_true(result@pass)
  expect_true(length(result@warnings) > 0)
  expect_true(any(grepl("High-entropy", result@warnings)))
  expect_true(high_ent %in% result@details$flagged_tokens)
})

# -- guard_output_entropy: data frame input --

test_that("guard_output_entropy scans data frame output", {
  g <- guard_output_entropy()
  high_ent <- "aB3xK9pQ2mR7nL4wS8vDfG5hJ6k"
  df <- data.frame(key = high_ent)
  result <- run_guardrail(g, df)
  expect_false(result@pass)
})

# -- guard_output_entropy: structure --

test_that("guard_output_entropy is type output", {
  g <- guard_output_entropy()
  expect_equal(g@type, "output")
})

test_that("guard_output_entropy is secureguard class", {
  g <- guard_output_entropy()
  expect_true(S7::S7_inherits(g, secureguard_class))
})

test_that("guard_output_entropy has descriptive description", {
  g <- guard_output_entropy()
  expect_true(grepl("Entropy", g@description))
  expect_true(grepl("block", g@description))

  g2 <- guard_output_entropy(action = "redact")
  expect_true(grepl("redact", g2@description))
})

test_that("guard_output_entropy respects custom min_length", {
  # Use a shorter min_length AND lower threshold to catch shorter tokens
  # "aB3xK9pQ2mR7" is 12 chars, entropy ~3.58, base64-like (not hex)
  short_tok <- "aB3xK9pQ2mR7"
  expect_true(nchar(short_tok) >= 10)
  expect_true(nchar(short_tok) < 20)
  expect_true(shannon_entropy(short_tok) > 3.0)

  # With min_length=10 and base64_threshold=3.0, this should be flagged
  g <- guard_output_entropy(min_length = 10L, base64_threshold = 3.0)
  result <- run_guardrail(g, paste("key:", short_tok))
  expect_false(result@pass)

  # Same token with default min_length (20) should pass (too short)
  g_default <- guard_output_entropy()
  result2 <- run_guardrail(g_default, paste("key:", short_tok))
  expect_true(result2@pass)
})
