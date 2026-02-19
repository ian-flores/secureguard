#' Input PII guardrail
#'
#' Creates a guardrail that detects personally identifiable information in
#' input text and either blocks or warns.
#'
#' @param detect Character vector of PII types to look for. Default:
#'   `c("ssn", "email", "phone", "credit_card")`. See [pii_patterns()] for
#'   valid types.
#' @param action Character(1). What to do when PII is found: `"block"`
#'   (default) fails the check, `"warn"` passes with advisory warnings.
#' @return A guardrail object of class `"secureguard"` with type `"input"`.
#' @export
#' @examples
#' g <- guard_input_pii()
#' run_guardrail(g, "My SSN is 123-45-6789")
#' run_guardrail(g, "Please help me with R code")
guard_input_pii <- function(detect = c("ssn", "email", "phone", "credit_card"),
                            action = c("block", "warn")) {
  action <- match.arg(action)

  all_types <- names(pii_patterns())
  unknown <- setdiff(detect, all_types)
  if (length(unknown) > 0L) {
    cli_abort("Unknown PII type{?s}: {.val {unknown}}.")
  }

  check_fn <- function(x) {
    if (!is_string(x)) {
      cli_abort("{.arg x} must be a single character string.")
    }

    matches <- detect_pii(x, types = detect)
    has_matches <- vapply(matches, function(m) length(m) > 0L, logical(1))

    if (any(has_matches)) {
      detected_types <- names(matches)[has_matches]
      match_counts <- vapply(
        matches[has_matches], length, integer(1)
      )
      detail_msg <- paste0(
        detected_types, " (", match_counts, ")",
        collapse = ", "
      )

      if (action == "block") {
        guardrail_result(
          pass = FALSE,
          reason = paste0("PII detected in input: ", detail_msg),
          details = list(matches = matches[has_matches])
        )
      } else {
        # action == "warn"
        warning_msgs <- paste0("PII found: ", detected_types, " (", match_counts, ")")
        guardrail_result(
          pass = TRUE,
          warnings = warning_msgs,
          details = list(matches = matches[has_matches])
        )
      }
    } else {
      guardrail_result(pass = TRUE)
    }
  }

  new_guardrail(
    name = "input_pii",
    type = "input",
    check_fn = check_fn,
    description = paste0(
      "Input PII detection (action=", action,
      ", types=", paste(detect, collapse = ","), ")"
    )
  )
}
