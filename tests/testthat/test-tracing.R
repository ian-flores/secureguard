test_that("run_guardrail emits span when trace active", {
  skip_if_not_installed("securetrace")

  g <- guard_code_analysis()

  result <- securetrace::with_trace("test-guardrail", {
    run_guardrail(g, "x <- 1 + 2")
  })

  expect_true(result@pass)
})

test_that("check_all emits spans when trace active", {
  skip_if_not_installed("securetrace")

  guards <- list(
    guard_code_analysis(),
    guard_code_complexity()
  )

  result <- securetrace::with_trace("test-check-all", {
    check_all(guards, "x <- 1 + 2")
  }, exporter = securetrace::console_exporter(verbose = FALSE))

  expect_true(result$pass)
})

test_that("run_guardrail works without securetrace", {
  # This tests the non-traced path
  g <- guard_code_analysis()
  result <- run_guardrail(g, "x <- 1 + 2")
  expect_true(result@pass)
})

test_that("guard_output emits span when trace active", {
  skip_if_not_installed("securetrace")

  result <- securetrace::with_trace("test-output", {
    guard_output(
      "Hello world, nothing sensitive",
      guard_output_pii()
    )
  })

  expect_true(result$pass)
})

test_that("secure_pipeline emits spans when trace active", {
  skip_if_not_installed("securetrace")

  pipeline <- secure_pipeline(
    input_guardrails = list(guard_prompt_injection()),
    code_guardrails = list(guard_code_analysis()),
    output_guardrails = list(guard_output_pii())
  )

  securetrace::with_trace("test-pipeline", {
    input_result <- pipeline$check_input("Hello world")
    expect_true(input_result$pass)

    code_result <- pipeline$check_code("x <- 1")
    expect_true(code_result$pass)

    output_result <- pipeline$check_output("Clean output")
    expect_true(output_result$pass)
  })
})
