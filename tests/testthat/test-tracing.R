# Helper: record spans emitted while evaluating `expr` using otelsdk's
# in-memory tracer provider. Returns list(value = <expr result>,
# spans = <list of recorded otel_span_data objects>).
local_otel_record <- function(expr) {
  rec <- otelsdk::with_otel_record(expr)
  list(value = rec$value, spans = rec$traces)
}

span_names <- function(rec) {
  vapply(rec$spans, function(s) s$name, character(1), USE.NAMES = FALSE)
}

test_that("run_guardrail emits span when tracing enabled", {
  skip_if_not_installed("otel")
  skip_if_not_installed("otelsdk")

  g <- guard_code_analysis()

  rec <- local_otel_record({
    run_guardrail(g, "x <- 1 + 2")
  })

  expect_true(rec$value@pass)
  expect_true(any(grepl("^guardrail\\.", span_names(rec))))
})

test_that("check_all emits spans when tracing enabled", {
  skip_if_not_installed("otel")
  skip_if_not_installed("otelsdk")

  guards <- list(
    guard_code_analysis(),
    guard_code_complexity()
  )

  rec <- local_otel_record({
    check_all(guards, "x <- 1 + 2")
  })

  expect_true(rec$value$pass)
  nms <- span_names(rec)
  expect_true("guardrails.check_all" %in% nms)
  # One child span per guardrail
  expect_length(grep("^guardrail\\.", nms), 2L)
})

test_that("run_guardrail works with tracing disabled", {
  # This tests the non-traced path (works even when otel is not installed)
  g <- guard_code_analysis()
  result <- run_guardrail(g, "x <- 1 + 2")
  expect_true(result@pass)
})

test_that("full pipeline works with tracing disabled", {
  pipeline <- secure_pipeline(
    input_guardrails = list(guard_prompt_injection()),
    code_guardrails = list(guard_code_analysis()),
    output_guardrails = list(guard_output_pii())
  )

  expect_true(pipeline$check_input("Hello world")$pass)
  expect_true(pipeline$check_code("x <- 1")$pass)
  expect_true(pipeline$check_output("Clean output")$pass)

  out <- guard_output("Hello world, nothing sensitive", guard_output_pii())
  expect_true(out$pass)
})

test_that("guard_output emits span when tracing enabled", {
  skip_if_not_installed("otel")
  skip_if_not_installed("otelsdk")

  rec <- local_otel_record({
    guard_output(
      "Hello world, nothing sensitive",
      guard_output_pii()
    )
  })

  expect_true(rec$value$pass)
  expect_true("guardrails.guard_output" %in% span_names(rec))
})

test_that("secure_pipeline emits spans when tracing enabled", {
  skip_if_not_installed("otel")
  skip_if_not_installed("otelsdk")

  pipeline <- secure_pipeline(
    input_guardrails = list(guard_prompt_injection()),
    code_guardrails = list(guard_code_analysis()),
    output_guardrails = list(guard_output_pii())
  )

  rec <- local_otel_record({
    input_result <- pipeline$check_input("Hello world")
    expect_true(input_result$pass)

    code_result <- pipeline$check_code("x <- 1")
    expect_true(code_result$pass)

    output_result <- pipeline$check_output("Clean output")
    expect_true(output_result$pass)
  })

  nms <- span_names(rec)
  expect_true(all(
    c(
      "pipeline.check_input",
      "pipeline.check_code",
      "pipeline.check_output"
    ) %in% nms
  ))
})
