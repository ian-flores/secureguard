# Common test helpers for secureguard

# Simple pass/fail guardrail for composition tests
make_pass_guardrail <- function(type = "code") {
  new_guardrail(
    name = "always_pass",
    type = type,
    check_fn = function(x) guardrail_result(pass = TRUE),
    description = "Always passes"
  )
}

make_fail_guardrail <- function(reason = "test failure", type = "code") {
  new_guardrail(
    name = "always_fail",
    type = type,
    check_fn = function(x) guardrail_result(pass = FALSE, reason = reason),
    description = "Always fails"
  )
}

make_warn_guardrail <- function(warning_msg = "test warning", type = "code") {
  new_guardrail(
    name = "always_warn",
    type = type,
    check_fn = function(x) {
      guardrail_result(pass = TRUE, warnings = warning_msg)
    },
    description = "Always warns"
  )
}
