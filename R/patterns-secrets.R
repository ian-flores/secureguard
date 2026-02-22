#' Secret detection patterns
#'
#' Returns a named list of regex patterns for detecting secrets and credentials
#' in text.
#'
#' @return A named list of character(1) regex patterns. Names: `api_key`,
#'   `aws_key`, `password`, `token`, `private_key`, `github_token`.
#' @keywords internal
#' @export
#' @examples
#' pats <- secret_patterns()
#' names(pats)
#' grepl(pats$aws_key, "AKIAIOSFODNN7EXAMPLE")
secret_patterns <- function() {
  list(
    api_key = "(?i)api[_-]?key\\s*[:=]\\s*['\"]?[A-Za-z0-9_\\-]{20,}",
    aws_key = "(?:AKIA|ASIA)[A-Z0-9]{16}",
    password = "(?i)password\\s*[:=]\\s*['\"]?[^\\s'\"]{8,}",
    token = "(?i)(?:bearer|auth(?:orization)?)\\s*[:=]?\\s*['\"]?[A-Za-z0-9_\\-.]{20,}",
    private_key = "-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    github_token = "gh[pousr]_[A-Za-z0-9_]{36,}"
  )
}

#' Detect secrets in text
#'
#' Scans text for secrets and credentials using regex patterns.
#'
#' @param text Character(1). The text to scan.
#' @param types Character vector of secret types to check. Defaults to all
#'   available types from [secret_patterns()]. Valid values: `"api_key"`,
#'   `"aws_key"`, `"password"`, `"token"`, `"private_key"`, `"github_token"`.
#' @return A named list where each element is a character vector of matches
#'   found for that secret type. Empty character vectors indicate no matches.
#' @export
#' @examples
#' detect_secrets("API_KEY = 'sk_live_abc123def456ghi789jkl0'")
#' detect_secrets("AKIAIOSFODNN7EXAMPLE", types = "aws_key")
detect_secrets <- function(text, types = NULL) {
  if (!is_string(text)) {
    cli_abort("{.arg text} must be a single character string.")
  }

  all_patterns <- secret_patterns()

  if (is.null(types)) {
    types <- names(all_patterns)
  } else {
    if (!is.character(types)) {
      cli_abort("{.arg types} must be a character vector.")
    }
    unknown <- setdiff(types, names(all_patterns))
    if (length(unknown) > 0L) {
      cli_abort("Unknown secret type{?s}: {.val {unknown}}.")
    }
  }

  patterns <- all_patterns[types]
  results <- lapply(patterns, function(pat) {
    m <- gregexpr(pat, text, perl = TRUE)
    regmatches(text, m)[[1L]]
  })

  results
}
