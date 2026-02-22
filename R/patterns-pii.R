#' PII detection patterns
#'
#' Returns a named list of regex patterns for detecting personally identifiable
#' information (PII) in text.
#'
#' @return A named list of character(1) regex patterns. Names: `ssn`, `email`,
#'   `phone`, `credit_card`, `ip_address`.
#' @keywords internal
#' @export
#' @examples
#' pats <- pii_patterns()
#' names(pats)
#' grepl(pats$ssn, "123-45-6789")
pii_patterns <- function() {
  list(
    ssn = "\\b\\d{3}-\\d{2}-\\d{4}\\b",
    email = "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
    phone = "\\b(?:\\+?1[-.\\s]?)?(?:\\(?\\d{3}\\)?[-.\\s]?)\\d{3}[-.\\s]?\\d{4}\\b",
    credit_card = "\\b(?:\\d{4}[- ]?){3}\\d{4}\\b",
    ip_address = "\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b"
  )
}

#' Detect PII in text
#'
#' Scans text for personally identifiable information using regex patterns.
#'
#' @param text Character(1). The text to scan.
#' @param types Character vector of PII types to check. Defaults to all
#'   available types from [pii_patterns()]. Valid values: `"ssn"`, `"email"`,
#'   `"phone"`, `"credit_card"`, `"ip_address"`.
#' @return A named list where each element is a character vector of matches
#'   found for that PII type. Empty character vectors indicate no matches.
#' @export
#' @examples
#' detect_pii("Call me at 555-123-4567 or email me at test@example.com")
#' detect_pii("SSN: 123-45-6789", types = "ssn")
detect_pii <- function(text, types = NULL) {
  if (!is_string(text)) {
    cli_abort("{.arg text} must be a single character string.")
  }

  all_patterns <- pii_patterns()

  if (is.null(types)) {
    types <- names(all_patterns)
  } else {
    if (!is.character(types)) {
      cli_abort("{.arg types} must be a character vector.")
    }
    unknown <- setdiff(types, names(all_patterns))
    if (length(unknown) > 0L) {
      cli_abort("Unknown PII type{?s}: {.val {unknown}}.")
    }
  }

  patterns <- all_patterns[types]
  results <- lapply(patterns, function(pat) {
    m <- gregexpr(pat, text, perl = TRUE)
    regmatches(text, m)[[1L]]
  })

  results
}
