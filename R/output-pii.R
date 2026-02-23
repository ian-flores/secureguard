#' Convert an R object to scannable text
#'
#' Converts arbitrary R objects to a single character string for pattern
#' scanning by output guardrails.
#'
#' @param x An arbitrary R object.
#' @return Character(1). A text representation of `x`.
#' @keywords internal
#' @export
#' @examples
#' output_to_text("hello")
#' output_to_text(data.frame(a = 1:3, b = letters[1:3]))
#' output_to_text(list(x = 1, y = "two"))
output_to_text <- function(x) {
  if (is.character(x)) {
    return(paste(x, collapse = "\n"))
  }
  if (is.data.frame(x)) {
    return(paste(utils::capture.output(print(x)), collapse = "\n"))
  }
  if (is.list(x)) {
    return(paste(utils::capture.output(utils::str(x)), collapse = "\n"))
  }
  paste(utils::capture.output(print(x)), collapse = "\n")
}

#' PII output guardrail
#'
#' Creates a guardrail that scans output for personally identifiable
#' information (PII).
#'
#' @param detect Character vector of PII types to detect. Defaults to all types
#'   from [pii_patterns()]: `"ssn"`, `"email"`, `"phone"`, `"credit_card"`,
#'   `"ip_address_v4"`, `"ip_address_v6"`, `"phone_intl"`, `"iban"`, `"dob"`,
#'   `"mac_address"`, `"us_passport"`, `"drivers_license"`, `"itin"`, `"vin"`.
#' @param action Character(1). What to do when PII is found:
#'   - `"block"` (default): fail the check.
#'   - `"redact"`: pass but replace PII with `[REDACTED_SSN]` etc.
#'   - `"warn"`: pass with advisory warnings.
#' @return A guardrail object of class `"secureguard"` with type `"output"`.
#' @export
#' @examples
#' g <- guard_output_pii()
#' run_guardrail(g, "My SSN is 123-45-6789")
#'
#' g_redact <- guard_output_pii(action = "redact")
#' result <- run_guardrail(g_redact, "My SSN is 123-45-6789")
#' result@details$redacted_text
guard_output_pii <- function(detect = NULL,
                             action = c("block", "redact", "warn")) {
  action <- match.arg(action)
  all_types <- names(pii_patterns())

  if (is.null(detect)) {
    detect <- all_types
  } else {
    if (!is.character(detect)) {
      cli_abort("{.arg detect} must be a character vector.")
    }
    unknown <- setdiff(detect, all_types)
    if (length(unknown) > 0L) {
      cli_abort("Unknown PII type{?s}: {.val {unknown}}.")
    }
  }

  check_fn <- function(x) {
    text <- output_to_text(x)
    matches <- detect_pii(text, types = detect)
    has_matches <- vapply(matches, function(m) length(m) > 0L, logical(1))

    if (!any(has_matches)) {
      return(guardrail_result(pass = TRUE))
    }

    detected_types <- names(matches)[has_matches]
    detected_str <- paste(detected_types, collapse = ", ")

    if (action == "block") {
      guardrail_result(
        pass = FALSE,
        reason = paste0("PII detected in output: ", detected_str),
        details = list(matches = matches[has_matches])
      )
    } else if (action == "redact") {
      redacted <- text
      patterns <- pii_patterns()[detected_types]
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
        paste0("PII detected: ", tp, " (", n, " occurrence", if (n > 1L) "s", ")")
      }, character(1))
      guardrail_result(
        pass = TRUE,
        warnings = warn_msgs,
        details = list(matches = matches[has_matches])
      )
    }
  }

  new_guardrail(
    name = "output_pii",
    type = "output",
    check_fn = check_fn,
    description = paste0(
      "PII output detection (action=", action,
      ", types=", paste(detect, collapse = ","), ")"
    )
  )
}
