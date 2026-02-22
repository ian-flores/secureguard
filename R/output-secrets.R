#' Secret output guardrail
#'
#' Creates a guardrail that scans output for secrets and credentials.
#'
#' @param detect Character vector of secret types to detect. Defaults to all
#'   types from [secret_patterns()]: `"api_key"`, `"aws_key"`, `"password"`,
#'   `"token"`, `"private_key"`, `"github_token"`.
#' @param action Character(1). What to do when secrets are found:
#'   - `"block"` (default): fail the check.
#'   - `"redact"`: pass but replace secrets with `[REDACTED_API_KEY]` etc.
#'   - `"warn"`: pass with advisory warnings.
#' @return A guardrail object of class `"secureguard"` with type `"output"`.
#' @export
#' @examples
#' g <- guard_output_secrets()
#' run_guardrail(g, "AKIAIOSFODNN7EXAMPLE")
#'
#' g_redact <- guard_output_secrets(action = "redact")
#' result <- run_guardrail(g_redact, "AKIAIOSFODNN7EXAMPLE")
#' result@details$redacted_text
guard_output_secrets <- function(detect = NULL,
                                 action = c("block", "redact", "warn")) {
  action <- match.arg(action)
  all_types <- names(secret_patterns())

  if (is.null(detect)) {
    detect <- all_types
  } else {
    if (!is.character(detect)) {
      cli_abort("{.arg detect} must be a character vector.")
    }
    unknown <- setdiff(detect, all_types)
    if (length(unknown) > 0L) {
      cli_abort("Unknown secret type{?s}: {.val {unknown}}.")
    }
  }

  check_fn <- function(x) {
    text <- output_to_text(x)
    matches <- detect_secrets(text, types = detect)
    has_matches <- vapply(matches, function(m) length(m) > 0L, logical(1))

    if (!any(has_matches)) {
      return(guardrail_result(pass = TRUE))
    }

    detected_types <- names(matches)[has_matches]
    detected_str <- paste(detected_types, collapse = ", ")

    if (action == "block") {
      guardrail_result(
        pass = FALSE,
        reason = paste0("Secrets detected in output: ", detected_str),
        details = list(matches = matches[has_matches])
      )
    } else if (action == "redact") {
      redacted <- text
      patterns <- secret_patterns()[detected_types]
      for (type_name in detected_types) {
        label <- paste0("[REDACTED_", toupper(type_name), "]")
        redacted <- gsub(patterns[[type_name]], label, redacted, perl = TRUE)
      }
      guardrail_result(
        pass = TRUE,
        details = list(
          matches = matches[has_matches],
          redacted_text = redacted
        )
      )
    } else {
      # warn
      warn_msgs <- vapply(detected_types, function(tp) {
        n <- length(matches[[tp]])
        paste0(
          "Secret detected: ", tp,
          " (", n, " occurrence", if (n > 1L) "s", ")"
        )
      }, character(1))
      guardrail_result(
        pass = TRUE,
        warnings = warn_msgs,
        details = list(matches = matches[has_matches])
      )
    }
  }

  new_guardrail(
    name = "output_secrets",
    type = "output",
    check_fn = check_fn,
    description = paste0(
      "Secret output detection (action=", action,
      ", types=", paste(detect, collapse = ","), ")"
    )
  )
}
