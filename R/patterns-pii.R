#' PII detection patterns
#'
#' Returns a named list of regex patterns for detecting personally identifiable
#' information (PII) in text.
#'
#' @return A named list of character(1) regex patterns. Names: `ssn`, `email`,
#'   `phone`, `credit_card`, `ip_address_v4`, `ip_address_v6`, `phone_intl`,
#'   `iban`, `dob`, `mac_address`, `us_passport`, `drivers_license`, `itin`,
#'   `vin`.
#' @keywords internal
#' @export
#' @examples
#' pats <- pii_patterns()
#' names(pats)
#' grepl(pats$ssn, "123-45-6789", perl = TRUE)
pii_patterns <- function() {
  list(
    ssn = "\\b(?!000|666|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b|\\b(?!000|666|9\\d{2})\\d{3}(?!00)\\d{2}(?!0000)\\d{4}\\b",
    email = "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
    phone = "\\b(?:\\+?1[-.\\s]?)?(?:\\(?\\d{3}\\)?[-.\\s]?)\\d{3}[-.\\s]?\\d{4}\\b",
    credit_card = "\\b(?:4\\d{3}|5[1-5]\\d{2}|2[2-7]\\d{2}|3[47]\\d{2}|6(?:011|5\\d{2}))[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b|\\b3[47]\\d{2}[- ]?\\d{6}[- ]?\\d{5}\\b",
    ip_address_v4 = "\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b",
    ip_address_v6 = "(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}",
    phone_intl = "\\+[1-9]\\d{6,14}\\b",
    iban = "\\b[A-Z]{2}\\d{2}[- ]?[A-Z0-9]{4}[- ]?(?:[A-Z0-9]{4}[- ]?){1,7}[A-Z0-9]{1,4}\\b",
    dob = "(?i)(?:date of birth|\\bdob\\b|birthday|born on)[:\\s]*\\d{1,2}[/\\-.]\\d{1,2}[/\\-.]\\d{2,4}",
    mac_address = "\\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\\b",
    us_passport = "(?i)(?:passport(?:\\s*(?:number|no|#|num))?)[:\\s]*[A-Z0-9]{6,9}\\b",
    drivers_license = "(?i)(?:driver'?s?\\s*licen[sc]e|\\bDL\\b)(?:\\s*(?:number|no|#|num))?[:\\s]*[A-Z0-9]{4,13}\\b",
    itin = "\\b9\\d{2}-[78]\\d-\\d{4}\\b|\\b9\\d{2}-9[0-24-9]-\\d{4}\\b",
    vin = "(?i)\\bvin[:\\s]*[A-HJ-NPR-Z0-9]{17}\\b"
  )
}

# Luhn algorithm check for credit card validation (not exported)
luhn_check <- function(number) {
  digits <- as.integer(strsplit(gsub("[^0-9]", "", number), "")[[1L]])
  n <- length(digits)
  if (n < 13L || n > 19L) return(FALSE)
  # Double every second digit from right
  idx <- seq(n - 1L, 1L, by = -2L)
  digits[idx] <- digits[idx] * 2L
  digits[idx][digits[idx] > 9L] <- digits[idx][digits[idx] > 9L] - 9L
  (sum(digits) %% 10L) == 0L
}

#' Detect PII in text
#'
#' Scans text for personally identifiable information using regex patterns.
#'
#' @param text Character(1). The text to scan.
#' @param types Character vector of PII types to check. Defaults to all
#'   available types from [pii_patterns()]. Valid values: `"ssn"`, `"email"`,
#'   `"phone"`, `"credit_card"`, `"ip_address_v4"`, `"ip_address_v6"`,
#'   `"phone_intl"`, `"iban"`, `"dob"`, `"mac_address"`, `"us_passport"`,
#'   `"drivers_license"`, `"itin"`, `"vin"`.
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

  # Post-filter credit cards through Luhn check
  if ("credit_card" %in% names(results) && length(results$credit_card) > 0L) {
    results$credit_card <- results$credit_card[
      vapply(results$credit_card, luhn_check, logical(1))
    ]
  }

  results
}
