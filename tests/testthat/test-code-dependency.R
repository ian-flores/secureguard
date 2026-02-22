test_that("guard_code_dependencies creates secureguard object", {
  g <- guard_code_dependencies()
  expect_true(S7::S7_inherits(g, secureguard_class))
  expect_equal(g@type, "code")
  expect_equal(g@name, "code_dependencies")
})

test_that("no restrictions allows everything", {
  g <- guard_code_dependencies()
  result <- run_guardrail(g, "library(dplyr)\nggplot2::ggplot()")
  expect_true(result@pass)
  expect_true("dplyr" %in% result@details$detected_packages)
  expect_true("ggplot2" %in% result@details$detected_packages)
})

test_that("allowlist blocks non-listed packages", {
  g <- guard_code_dependencies(allowed_packages = c("dplyr", "ggplot2"))
  result <- run_guardrail(g, "library(dplyr)\nlibrary(data.table)")
  expect_false(result@pass)
  expect_true("data.table" %in% result@details$violations)
})

test_that("allowlist allows listed packages", {
  g <- guard_code_dependencies(allowed_packages = c("dplyr"))
  result <- run_guardrail(g, "library(dplyr)")
  expect_true(result@pass)
})

test_that("denylist blocks listed packages", {
  g <- guard_code_dependencies(denied_packages = c("data.table"))
  result <- run_guardrail(g, "library(data.table)")
  expect_false(result@pass)
  expect_true("data.table" %in% result@details$violations)
})

test_that("denylist allows non-listed packages", {
  g <- guard_code_dependencies(denied_packages = c("data.table"))
  result <- run_guardrail(g, "library(dplyr)")
  expect_true(result@pass)
})

test_that("allow_base permits base packages by default", {
  g <- guard_code_dependencies(allowed_packages = c("dplyr"))
  result <- run_guardrail(g, "library(stats)\nlibrary(dplyr)")
  expect_true(result@pass)
})

test_that("allow_base = FALSE checks base packages", {
  g <- guard_code_dependencies(
    allowed_packages = c("dplyr"),
    allow_base = FALSE
  )
  result <- run_guardrail(g, "library(stats)")
  expect_false(result@pass)
  expect_true("stats" %in% result@details$violations)
})

test_that("pkg::fn syntax is detected", {
  g <- guard_code_dependencies(denied_packages = "processx")
  result <- run_guardrail(g, "processx::run('ls')")
  expect_false(result@pass)
  expect_true("processx" %in% result@details$violations)
})

test_that("pkg:::fn syntax is detected", {
  g <- guard_code_dependencies(denied_packages = "processx")
  result <- run_guardrail(g, "processx:::internal_fn()")
  expect_false(result@pass)
})

test_that("require() is detected", {
  g <- guard_code_dependencies(denied_packages = "data.table")
  result <- run_guardrail(g, "require(data.table)")
  expect_false(result@pass)
})

test_that("loadNamespace() is detected", {
  g <- guard_code_dependencies(denied_packages = "data.table")
  result <- run_guardrail(g, 'loadNamespace("data.table")')
  expect_false(result@pass)
})

test_that("cannot specify both allowed and denied", {
  expect_error(
    guard_code_dependencies(
      allowed_packages = "dplyr",
      denied_packages = "data.table"
    )
  )
})

test_that("code with no packages passes", {
  g <- guard_code_dependencies(allowed_packages = "dplyr")
  result <- run_guardrail(g, "x <- 1 + 2")
  expect_true(result@pass)
})

test_that("invalid inputs are rejected", {
  expect_error(guard_code_dependencies(allowed_packages = 123))
  expect_error(guard_code_dependencies(denied_packages = 123))
  expect_error(guard_code_dependencies(allow_base = "yes"))
})
