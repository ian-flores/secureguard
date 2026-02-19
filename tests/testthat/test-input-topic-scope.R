test_that("guard_topic_scope creates valid guardrail", {
  g <- guard_topic_scope(allowed_topics = "statistics")
  expect_s3_class(g, "secureguard")
  expect_equal(g$type, "input")
  expect_equal(g$name, "topic_scope")
})

# -- Allowed topics --
test_that("guard_topic_scope allows matching topics", {
  g <- guard_topic_scope(allowed_topics = c("statistics", "data analysis"))

  r <- run_guardrail(g, "How do I run a statistics test?")
  expect_true(r$pass)
  expect_true("statistics" %in% r$details$matched_topics)

  r2 <- run_guardrail(g, "Help with data analysis in R")
  expect_true(r2$pass)
})

test_that("guard_topic_scope blocks non-matching allowed topics", {
  g <- guard_topic_scope(allowed_topics = c("statistics", "data analysis"))

  r <- run_guardrail(g, "What is the weather today?")
  expect_false(r$pass)
  expect_match(r$reason, "does not match any allowed topic")

  r2 <- run_guardrail(g, "Tell me a joke")
  expect_false(r2$pass)
})

# -- Denied topics --
test_that("guard_topic_scope blocks denied topics", {
  g <- guard_topic_scope(denied_topics = c("politics", "religion"))

  r <- run_guardrail(g, "What are your views on politics?")
  expect_false(r$pass)
  expect_match(r$reason, "denied topic")

  r2 <- run_guardrail(g, "Discuss religion in detail")
  expect_false(r2$pass)
})

test_that("guard_topic_scope allows non-denied topics", {
  g <- guard_topic_scope(denied_topics = c("politics", "religion"))

  r <- run_guardrail(g, "How do I fit a linear model?")
  expect_true(r$pass)

  r2 <- run_guardrail(g, "Calculate mean and standard deviation")
  expect_true(r2$pass)
})

# -- Case sensitivity --
test_that("guard_topic_scope is case-insensitive by default", {
  g <- guard_topic_scope(allowed_topics = "statistics")

  r <- run_guardrail(g, "STATISTICS is fun")
  expect_true(r$pass)

  r2 <- run_guardrail(g, "Statistics test")
  expect_true(r2$pass)
})

test_that("guard_topic_scope respects case_sensitive = TRUE", {
  g <- guard_topic_scope(allowed_topics = "Statistics", case_sensitive = TRUE)

  r <- run_guardrail(g, "Statistics is fun")
  expect_true(r$pass)

  r2 <- run_guardrail(g, "STATISTICS is fun")
  expect_false(r2$pass)
})

# -- Validation --
test_that("guard_topic_scope rejects both allowed and denied", {
  expect_error(
    guard_topic_scope(allowed_topics = "a", denied_topics = "b"),
    "Cannot specify both"
  )
})

test_that("guard_topic_scope rejects neither allowed nor denied", {
  expect_error(
    guard_topic_scope(),
    "Must specify either"
  )
})

test_that("guard_topic_scope validates allowed_topics type", {
  expect_error(
    guard_topic_scope(allowed_topics = 42),
    "character vector"
  )
})

test_that("guard_topic_scope validates denied_topics type", {
  expect_error(
    guard_topic_scope(denied_topics = 42),
    "character vector"
  )
})

test_that("guard_topic_scope validates case_sensitive", {
  expect_error(
    guard_topic_scope(allowed_topics = "a", case_sensitive = "yes"),
    "case_sensitive"
  )
  expect_error(
    guard_topic_scope(allowed_topics = "a", case_sensitive = NA),
    "case_sensitive"
  )
})

test_that("guard_topic_scope rejects non-string input at runtime", {
  g <- guard_topic_scope(allowed_topics = "stats")
  expect_error(run_guardrail(g, 42), "single character string")
})

# -- Multiple patterns --
test_that("guard_topic_scope matches any allowed topic", {
  g <- guard_topic_scope(allowed_topics = c("^math", "^science"))

  r <- run_guardrail(g, "math homework help")
  expect_true(r$pass)

  r2 <- run_guardrail(g, "science experiment")
  expect_true(r2$pass)

  r3 <- run_guardrail(g, "cooking recipes")
  expect_false(r3$pass)
})

test_that("guard_topic_scope blocks any denied topic", {
  g <- guard_topic_scope(denied_topics = c("violence", "weapons"))

  r <- run_guardrail(g, "discussion about violence in media")
  expect_false(r$pass)

  r2 <- run_guardrail(g, "information about weapons")
  expect_false(r2$pass)

  r3 <- run_guardrail(g, "peaceful gardening")
  expect_true(r3$pass)
})

test_that("guard_topic_scope denied details include matched patterns", {
  g <- guard_topic_scope(denied_topics = c("politics", "religion"))
  r <- run_guardrail(g, "Let's discuss politics and religion")
  expect_false(r$pass)
  expect_length(r$details$matched_denied, 2L)
})
