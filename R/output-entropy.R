#' Shannon entropy of a string
#'
#' Calculates the Shannon entropy (in bits) of a character string based on
#' character frequency.
#'
#' @param s Character(1). The string to measure.
#' @return Numeric(1). The Shannon entropy in bits. Returns 0 for empty strings
#'   or single-character strings.
#' @export
#' @seealso [is_high_entropy()], [guard_output_entropy()]
#' @examples
#' shannon_entropy("aaaaaa")    # low entropy (0)
#' shannon_entropy("abcdefgh")  # higher entropy
#' shannon_entropy("aB3$xK9!")  # high entropy
shannon_entropy <- function(s) {
  if (!is_string(s)) {
    cli_abort("{.arg s} must be a single character string.")
  }
  if (nchar(s) == 0L) return(0)
  chars <- strsplit(s, "")[[1L]]
  freq <- table(chars) / length(chars)
  -sum(freq * log2(freq))
}

#' Check if a string has high entropy
#'
#' Determines whether a string has suspiciously high Shannon entropy,
#' suggesting it may be a secret, key, or random token.
#'
#' @param s Character(1). The string to check.
#' @param base64_threshold Numeric(1). Entropy threshold for base64-like
#'   strings (default 4.5).
#' @param hex_threshold Numeric(1). Entropy threshold for hex-like strings
#'   (default 3.0).
#' @param min_length Integer(1). Minimum string length to consider
#'   (default 20). Shorter strings always return `FALSE`.
#' @return Logical(1).
#' @export
#' @seealso [shannon_entropy()], [guard_output_entropy()]
#' @examples
#' is_high_entropy("aaaaaaaaaaaaaaaaaaaaa")  # FALSE (low entropy)
#' is_high_entropy("aB3xK9pQ2mR7nL4wS8vD")  # likely TRUE
is_high_entropy <- function(s,
                            base64_threshold = 4.5,
                            hex_threshold = 3.0,
                            min_length = 20L) {
  if (!is_string(s)) {
    cli_abort("{.arg s} must be a single character string.")
  }
  if (nchar(s) < min_length) return(FALSE)

  entropy <- shannon_entropy(s)

  # Determine character class
  if (grepl("^[0-9a-fA-F]+$", s)) {
    threshold <- hex_threshold
  } else if (grepl("^[A-Za-z0-9+/=_-]+$", s)) {
    threshold <- base64_threshold
  } else {
    threshold <- base64_threshold
  }

  entropy > threshold
}

#' Entropy output guardrail
#'
#' Creates a guardrail that scans output for high-entropy substrings that
#' may indicate leaked secrets, tokens, or keys.
#'
#' @param min_length Integer(1). Minimum token length to check (default 20).
#' @param base64_threshold Numeric(1). Entropy threshold for base64-like
#'   strings (default 4.5).
#' @param hex_threshold Numeric(1). Entropy threshold for hex-like strings
#'   (default 3.0).
#' @param action Character(1). What to do when high-entropy strings are found:
#'   - `"block"` (default): fail the check.
#'   - `"redact"`: pass but replace high-entropy tokens with `[HIGH_ENTROPY]`.
#'   - `"warn"`: pass with advisory warnings.
#' @return A guardrail object of class `"secureguard"` with type `"output"`.
#' @export
#' @seealso [shannon_entropy()], [is_high_entropy()]
#' @examples
#' g <- guard_output_entropy()
#' run_guardrail(g, "Nothing suspicious here")
#' run_guardrail(g, "token=aB3xK9pQ2mR7nL4wS8vDfG5hJ6kT0yU")
guard_output_entropy <- function(min_length = 20L,
                                  base64_threshold = 4.5,
                                  hex_threshold = 3.0,
                                  action = c("block", "redact", "warn")) {
  action <- match.arg(action)

  check_fn <- function(x) {
    text <- output_to_text(x)
    # Tokenize: split on whitespace and common delimiters
    tokens <- unlist(strsplit(text, "[\\s,;:='\"\\(\\)\\[\\]\\{\\}]+", perl = TRUE))
    tokens <- tokens[nchar(tokens) >= min_length]

    if (length(tokens) == 0L) {
      return(guardrail_result(pass = TRUE))
    }

    high_entropy <- vapply(tokens, function(tok) {
      is_high_entropy(tok,
                      base64_threshold = base64_threshold,
                      hex_threshold = hex_threshold,
                      min_length = min_length)
    }, logical(1))

    flagged <- tokens[high_entropy]

    if (length(flagged) == 0L) {
      return(guardrail_result(pass = TRUE))
    }

    if (action == "block") {
      guardrail_result(
        pass = FALSE,
        reason = paste0(
          "High-entropy strings detected (",
          length(flagged), " token", if (length(flagged) > 1L) "s", ")"
        ),
        details = list(flagged_tokens = flagged)
      )
    } else if (action == "redact") {
      redacted <- text
      for (tok in flagged) {
        redacted <- gsub(tok, "[HIGH_ENTROPY]", redacted, fixed = TRUE)
      }
      guardrail_result(
        pass = TRUE,
        details = list(
          flagged_tokens = flagged,
          redacted_text = redacted
        )
      )
    } else {
      # warn
      guardrail_result(
        pass = TRUE,
        warnings = paste0(
          "High-entropy string detected: ",
          substr(flagged, 1, 8), "..."
        ),
        details = list(flagged_tokens = flagged)
      )
    }
  }

  new_guardrail(
    name = "output_entropy",
    type = "output",
    check_fn = check_fn,
    description = paste0(
      "Entropy output detection (action=", action,
      ", min_length=", min_length, ")"
    )
  )
}
