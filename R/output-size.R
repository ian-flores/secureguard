#' Output size guardrail
#'
#' Creates a guardrail that checks whether output exceeds size limits.
#'
#' @param max_chars Integer(1). Maximum number of characters in the text
#'   representation. Default `100000`.
#' @param max_lines Integer(1). Maximum number of lines in the text
#'   representation. Default `5000`.
#' @param max_elements Integer(1). Maximum number of elements. For vectors and
#'   lists this is `length()`. For data frames this is `nrow() * ncol()`.
#'   Default `10000`.
#' @return A guardrail object of class `"secureguard"` with type `"output"`.
#' @export
#' @examples
#' g <- guard_output_size(max_chars = 100, max_lines = 5)
#' run_guardrail(g, strrep("x", 200))
#' run_guardrail(g, "short")
guard_output_size <- function(max_chars = 100000L,
                              max_lines = 5000L,
                              max_elements = 10000L) {
  if (!is.numeric(max_chars) || length(max_chars) != 1L || max_chars <= 0) {
    cli_abort("{.arg max_chars} must be a positive number.")
  }
  if (!is.numeric(max_lines) || length(max_lines) != 1L || max_lines <= 0) {
    cli_abort("{.arg max_lines} must be a positive number.")
  }
  if (!is.numeric(max_elements) || length(max_elements) != 1L ||
      max_elements <= 0) {
    cli_abort("{.arg max_elements} must be a positive number.")
  }

  max_chars <- as.integer(max_chars)
  max_lines <- as.integer(max_lines)
  max_elements <- as.integer(max_elements)

  check_fn <- function(x) {
    violations <- character(0)
    details <- list()

    # Element count check (on raw object, before text conversion)
    if (is.data.frame(x)) {
      n_elements <- nrow(x) * ncol(x)
    } else if (is.atomic(x) || is.list(x)) {
      n_elements <- length(x)
    } else {
      n_elements <- 1L
    }
    details$elements <- n_elements
    if (n_elements > max_elements) {
      violations <- c(violations, paste0(
        "elements: ", n_elements, " > ", max_elements
      ))
    }

    # Text-based checks
    text <- output_to_text(x)
    n_chars <- nchar(text)
    n_lines <- length(strsplit(text, "\n", fixed = TRUE)[[1L]])

    details$chars <- n_chars
    details$lines <- n_lines

    if (n_chars > max_chars) {
      violations <- c(violations, paste0(
        "chars: ", n_chars, " > ", max_chars
      ))
    }
    if (n_lines > max_lines) {
      violations <- c(violations, paste0(
        "lines: ", n_lines, " > ", max_lines
      ))
    }

    if (length(violations) > 0L) {
      guardrail_result(
        pass = FALSE,
        reason = paste0(
          "Output exceeds size limits: ",
          paste(violations, collapse = "; ")
        ),
        details = details
      )
    } else {
      guardrail_result(pass = TRUE, details = details)
    }
  }

  new_guardrail(
    name = "output_size",
    type = "output",
    check_fn = check_fn,
    description = paste0(
      "Output size limits (chars=", max_chars,
      ", lines=", max_lines,
      ", elements=", max_elements, ")"
    )
  )
}
