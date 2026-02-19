#' Code complexity guardrail
#'
#' Creates a guardrail that checks R code against complexity limits using
#' AST statistics. Prevents overly complex or deeply nested code from being
#' executed.
#'
#' @param max_ast_depth Integer(1). Maximum allowed AST nesting depth.
#'   Default `50`.
#' @param max_calls Integer(1). Maximum number of function calls allowed.
#'   Default `200`.
#' @param max_assignments Integer(1). Maximum number of assignment operations.
#'   Default `100`.
#' @param max_expressions Integer(1). Maximum number of top-level expressions.
#'   Default `50`.
#' @return A guardrail object of class `"secureguard"` with type `"code"`.
#' @export
#' @examples
#' g <- guard_code_complexity()
#' run_guardrail(g, "x <- 1 + 2")
guard_code_complexity <- function(max_ast_depth = 50L,
                                  max_calls = 200L,
                                  max_assignments = 100L,
                                  max_expressions = 50L) {
  max_ast_depth <- as.integer(max_ast_depth)
  max_calls <- as.integer(max_calls)
  max_assignments <- as.integer(max_assignments)
  max_expressions <- as.integer(max_expressions)

  if (is.na(max_ast_depth) || max_ast_depth < 1L) {
    cli_abort("{.arg max_ast_depth} must be a positive integer.")
  }
  if (is.na(max_calls) || max_calls < 1L) {
    cli_abort("{.arg max_calls} must be a positive integer.")
  }
  if (is.na(max_assignments) || max_assignments < 1L) {
    cli_abort("{.arg max_assignments} must be a positive integer.")
  }
  if (is.na(max_expressions) || max_expressions < 1L) {
    cli_abort("{.arg max_expressions} must be a positive integer.")
  }

  check_fn <- function(code) {
    if (!is_string(code)) {
      cli_abort("{.arg code} must be a single character string.")
    }

    stats <- ast_stats(code)
    violations <- character(0)

    if (stats$depth > max_ast_depth) {
      violations <- c(violations, paste0(
        "AST depth ", stats$depth, " exceeds limit ", max_ast_depth
      ))
    }
    if (stats$n_calls > max_calls) {
      violations <- c(violations, paste0(
        "Call count ", stats$n_calls, " exceeds limit ", max_calls
      ))
    }
    if (stats$n_assignments > max_assignments) {
      violations <- c(violations, paste0(
        "Assignment count ", stats$n_assignments, " exceeds limit ",
        max_assignments
      ))
    }
    if (stats$n_expressions > max_expressions) {
      violations <- c(violations, paste0(
        "Expression count ", stats$n_expressions, " exceeds limit ",
        max_expressions
      ))
    }

    if (length(violations) > 0L) {
      guardrail_result(
        pass = FALSE,
        reason = paste(violations, collapse = "; "),
        details = list(stats = stats, violations = violations)
      )
    } else {
      guardrail_result(
        pass = TRUE,
        details = list(stats = stats)
      )
    }
  }

  new_guardrail(
    name = "code_complexity",
    type = "code",
    check_fn = check_fn,
    description = paste0(
      "Complexity limits (depth=", max_ast_depth,
      ", calls=", max_calls,
      ", assignments=", max_assignments,
      ", expressions=", max_expressions, ")"
    )
  )
}
