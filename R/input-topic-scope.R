#' Topic scope guardrail
#'
#' Creates a guardrail that restricts input to specific topics using allowlist
#' or denylist regex patterns.
#'
#' @param allowed_topics Character vector of regex patterns. If non-`NULL`,
#'   input must match at least one pattern to pass. Cannot be used together
#'   with `denied_topics`.
#' @param denied_topics Character vector of regex patterns. Input must not
#'   match any of these patterns. Cannot be used together with
#'   `allowed_topics`.
#' @param case_sensitive Logical(1). Whether pattern matching is
#'   case-sensitive. Default: `FALSE`.
#' @return A guardrail object of class `"secureguard"` with type `"input"`.
#' @export
#' @examples
#' g <- guard_topic_scope(allowed_topics = c("statistics", "data analysis"))
#' run_guardrail(g, "How do I calculate a t-test in statistics?")
#' run_guardrail(g, "What is the weather today?")
guard_topic_scope <- function(allowed_topics = NULL,
                              denied_topics = NULL,
                              case_sensitive = FALSE) {
  if (!is.null(allowed_topics) && !is.null(denied_topics)) {
    cli_abort("Cannot specify both {.arg allowed_topics} and {.arg denied_topics}.")
  }

  if (is.null(allowed_topics) && is.null(denied_topics)) {
    cli_abort("Must specify either {.arg allowed_topics} or {.arg denied_topics}.")
  }

  if (!is.null(allowed_topics) && !is.character(allowed_topics)) {
    cli_abort("{.arg allowed_topics} must be a character vector.")
  }

  if (!is.null(denied_topics) && !is.character(denied_topics)) {
    cli_abort("{.arg denied_topics} must be a character vector.")
  }

  if (!is.logical(case_sensitive) || length(case_sensitive) != 1L ||
      is.na(case_sensitive)) {
    cli_abort("{.arg case_sensitive} must be TRUE or FALSE.")
  }

  check_fn <- function(x) {
    if (!is_string(x)) {
      cli_abort("{.arg x} must be a single character string.")
    }

    ignore_case <- !case_sensitive

    if (!is.null(allowed_topics)) {
      matched <- vapply(allowed_topics, function(pat) {
        grepl(pat, x, ignore.case = ignore_case, perl = TRUE)
      }, logical(1))

      if (any(matched)) {
        guardrail_result(
          pass = TRUE,
          details = list(matched_topics = allowed_topics[matched])
        )
      } else {
        guardrail_result(
          pass = FALSE,
          reason = "Input does not match any allowed topic.",
          details = list(allowed_topics = allowed_topics)
        )
      }
    } else {
      matched <- vapply(denied_topics, function(pat) {
        grepl(pat, x, ignore.case = ignore_case, perl = TRUE)
      }, logical(1))

      if (any(matched)) {
        guardrail_result(
          pass = FALSE,
          reason = paste0(
            "Input matches denied topic(s): ",
            paste(denied_topics[matched], collapse = ", ")
          ),
          details = list(matched_denied = denied_topics[matched])
        )
      } else {
        guardrail_result(pass = TRUE)
      }
    }
  }

  mode <- if (!is.null(allowed_topics)) "allowlist" else "denylist"

  new_guardrail(
    name = "topic_scope",
    type = "input",
    check_fn = check_fn,
    description = paste0("Topic scope restriction (", mode, ")")
  )
}
