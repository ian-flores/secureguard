#' Convert code guardrails to a securer pre-execute hook
#'
#' Takes one or more code guardrails and returns a function suitable for
#' securer's `pre_execute_hook` parameter. The hook returns `FALSE` to block
#' code that fails any guardrail, or `TRUE` to allow it.
#'
#' @param ... Guardrail objects with `type = "code"`.
#' @return A function with signature `function(code)` that returns `TRUE` if
#'   all guardrails pass, or `FALSE` (with warnings) if any fail.
#' @export
#' @examples
#' hook <- as_pre_execute_hook(
#'   guard_code_analysis(),
#'   guard_code_complexity(max_ast_depth = 10)
#' )
#' hook("x <- 1 + 2")
#' hook("system('ls')")
as_pre_execute_hook <- function(...) {
  guardrails <- list(...)

  if (length(guardrails) == 0L) {
    cli_abort("At least one guardrail is required.")
  }

  for (i in seq_along(guardrails)) {
    g <- guardrails[[i]]
    if (!S7_inherits(g, secureguard_class)) {
      cli_abort("Argument {i} is not a guardrail (class {.cls secureguard}).")
    }
    if (g@type != "code") {
      cli_abort(
        "Argument {i} ({.val {g@name}}) has type {.val {g@type}}, expected {.val code}."
      )
    }
  }

  function(code) {
    result <- check_all(guardrails, code)

    if (length(result$warnings) > 0L) {
      for (w in result$warnings) {
        cli_warn(w)
      }
    }

    if (!result$pass) {
      for (r in result$reasons) {
        cli_warn(r)
      }
      return(FALSE)
    }

    TRUE
  }
}

#' Run output guardrails on a result
#'
#' Checks an R object against one or more output guardrails. For guardrails
#' with `action = "redact"`, the redacted text is applied to the result.
#'
#' @param result An R object to check.
#' @param ... Guardrail objects with `type = "output"`.
#' @return A list with components:
#'   - `pass`: logical, `TRUE` if all guardrails pass.
#'   - `result`: the (possibly redacted) result.
#'   - `warnings`: character vector of advisory warnings.
#'   - `reasons`: character vector of failure reasons.
#' @export
#' @examples
#' out <- guard_output(
#'   "My SSN is 123-45-6789",
#'   guard_output_pii()
#' )
#' out$pass
guard_output <- function(result, ...) {
  guardrails <- list(...)

  if (length(guardrails) == 0L) {
    cli_abort("At least one guardrail is required.")
  }

  for (i in seq_along(guardrails)) {
    g <- guardrails[[i]]
    if (!S7_inherits(g, secureguard_class)) {
      cli_abort("Argument {i} is not a guardrail (class {.cls secureguard}).")
    }
    if (g@type != "output") {
      cli_abort(
        "Argument {i} ({.val {g@name}}) has type {.val {g@type}}, expected {.val output}."
      )
    }
  }

  all_warnings <- character(0)
  all_reasons <- character(0)
  pass <- TRUE
  current_result <- result

  for (g in guardrails) {
    res <- run_guardrail(g, current_result)

    if (length(res@warnings) > 0L) {
      all_warnings <- c(all_warnings, res@warnings)
    }

    if (!res@pass) {
      pass <- FALSE
      reason <- res@reason %||% "check failed"
      all_reasons <- c(all_reasons, reason)
    }

    # Apply redaction if present
    if (!is.null(res@details$redacted_text)) {
      current_result <- res@details$redacted_text
    }
  }

  list(
    pass = pass,
    result = current_result,
    warnings = all_warnings,
    reasons = all_reasons
  )
}

#' Create a complete guardrail pipeline
#'
#' Bundles input, code, and output guardrails into a single pipeline object
#' with convenience methods for each stage.
#'
#' @param input_guardrails List of guardrails with `type = "input"`.
#' @param code_guardrails List of guardrails with `type = "code"`.
#' @param output_guardrails List of guardrails with `type = "output"`.
#' @return A list with methods:
#'   - `$check_input(text)`: run input guardrails, returns `check_all()` result.
#'   - `$check_code(code)`: run code guardrails, returns `check_all()` result.
#'   - `$check_output(result)`: run output guardrails via `guard_output()`.
#'   - `$as_pre_execute_hook()`: convert code guardrails to a securer hook.
#' @export
#' @examples
#' pipeline <- secure_pipeline(
#'   input_guardrails = list(guard_prompt_injection()),
#'   code_guardrails = list(guard_code_analysis()),
#'   output_guardrails = list(guard_output_pii())
#' )
#' pipeline$check_input("Hello, world")
#' pipeline$check_code("x <- 1")
secure_pipeline <- function(input_guardrails = list(),
                            code_guardrails = list(),
                            output_guardrails = list()) {
  validate_guardrail_list <- function(guardrails, expected_type, arg_name) {
    if (!is.list(guardrails)) {
      cli_abort("{.arg {arg_name}} must be a list.")
    }
    for (i in seq_along(guardrails)) {
      g <- guardrails[[i]]
      if (!S7_inherits(g, secureguard_class)) {
        cli_abort(
          "Element {i} of {.arg {arg_name}} is not a guardrail (class {.cls secureguard})."
        )
      }
      if (g@type != expected_type) {
        cli_abort(
          "Element {i} of {.arg {arg_name}} has type {.val {g@type}}, expected {.val {expected_type}}."
        )
      }
    }
  }

  validate_guardrail_list(input_guardrails, "input", "input_guardrails")
  validate_guardrail_list(code_guardrails, "code", "code_guardrails")
  validate_guardrail_list(output_guardrails, "output", "output_guardrails")

  list(
    check_input = function(text) {
      if (length(input_guardrails) == 0L) {
        return(list(
          pass = TRUE, results = list(),
          warnings = character(0), reasons = character(0)
        ))
      }
      check_all(input_guardrails, text)
    },

    check_code = function(code) {
      if (length(code_guardrails) == 0L) {
        return(list(
          pass = TRUE, results = list(),
          warnings = character(0), reasons = character(0)
        ))
      }
      check_all(code_guardrails, code)
    },

    check_output = function(result) {
      if (length(output_guardrails) == 0L) {
        return(list(
          pass = TRUE, result = result,
          warnings = character(0), reasons = character(0)
        ))
      }
      do.call(guard_output, c(list(result), output_guardrails))
    },

    as_pre_execute_hook = function() {
      if (length(code_guardrails) == 0L) {
        cli_abort("No code guardrails in this pipeline.")
      }
      do.call(as_pre_execute_hook, code_guardrails)
    }
  )
}
