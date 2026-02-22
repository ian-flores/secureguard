#' S7 class: secureguard
#'
#' An S7 value type representing a guardrail. Prefer the `guard_*()` factory
#' functions for end-user guardrails.
#'
#' @param name Character(1). Short identifier for the guardrail.
#' @param type Character(1). One of `"input"`, `"code"`, or `"output"`.
#' @param check_fn A function taking a single argument and returning a
#'   [guardrail_result()].
#' @param description Character(1). Human-readable description.
#' @export
#' @examples
#' # Prefer new_guardrail() or guard_*() factories over direct construction
#' g <- secureguard_class(
#'   name = "my_guard",
#'   type = "input",
#'   check_fn = function(x) guardrail_result(pass = TRUE),
#'   description = "A simple guardrail"
#' )
#' g@name
#' g@type
secureguard_class <- new_class("secureguard", properties = list(
  name = class_character,
  type = class_character,
  check_fn = class_function,
  description = class_character
))

#' Create a new guardrail
#'
#' Low-level constructor for guardrail objects. Prefer the `guard_*()` factory
#' functions for end-user guardrails.
#'
#' @param name Character(1). Short identifier for the guardrail.
#' @param type Character(1). One of `"input"`, `"code"`, or `"output"`.
#' @param check_fn A function taking a single argument and returning a
#'   [guardrail_result()].
#' @param description Character(1). Human-readable description.
#' @return An S7 object of class `secureguard`.
#' @export
#' @examples
#' g <- new_guardrail(
#'   name = "no_eval",
#'   type = "code",
#'   check_fn = function(code) {
#'     if (grepl("\\beval\\b", code)) {
#'       guardrail_result(pass = FALSE, reason = "eval() detected")
#'     } else {
#'       guardrail_result(pass = TRUE)
#'     }
#'   },
#'   description = "Blocks eval() calls"
#' )
#' g@name
#' run_guardrail(g, "x <- 1")
new_guardrail <- function(name, type, check_fn, description = "") {
  stopifnot(
    is_string(name),
    is_string(type),
    type %in% c("input", "code", "output"),
    is_function(check_fn),
    is_string(description)
  )
  secureguard_class(
    name = name,
    type = type,
    check_fn = check_fn,
    description = description
  )
}

#' S7 class: guardrail_result
#'
#' An S7 value type representing a structured return value from guardrail checks.
#'
#' @param pass Logical(1). Did the check pass?
#' @param reason Character(1) or `NULL`. Why the check failed.
#' @param warnings Character vector of advisory warnings.
#' @param details Named list of additional information (e.g. matched patterns,
#'   redacted text).
#' @export
#' @examples
#' # Prefer guardrail_result() constructor over direct construction
#' r <- guardrail_result_class(pass = TRUE)
#' r@pass
#'
#' r2 <- guardrail_result_class(
#'   pass = FALSE,
#'   reason = "blocked",
#'   warnings = "advisory note"
#' )
#' r2@reason
guardrail_result_class <- new_class("guardrail_result", properties = list(
  pass = class_logical,
  reason = new_property(class_any, default = NULL),
  warnings = new_property(class_character, default = character(0)),
  details = new_property(class_list, default = list())
))

#' Create a guardrail result
#'
#' Structured return value from guardrail checks.
#'
#' @param pass Logical(1). Did the check pass?
#' @param reason Character(1) or `NULL`. Why the check failed.
#' @param warnings Character vector of advisory warnings.
#' @param details Named list of additional information (e.g. matched patterns,
#'   redacted text).
#' @return An S7 object of class `guardrail_result`.
#' @export
#' @examples
#' # A passing result
#' r <- guardrail_result(pass = TRUE)
#' r@pass
#'
#' # A failing result with details
#' r <- guardrail_result(
#'   pass = FALSE,
#'   reason = "Blocked function detected",
#'   details = list(blocked_calls = "system")
#' )
#' r@reason
#' r@details
guardrail_result <- function(pass, reason = NULL, warnings = character(0),
                             details = list()) {
  stopifnot(
    is.logical(pass), length(pass) == 1L, !is.na(pass),
    is.null(reason) || is_string(reason),
    is.character(warnings),
    is.list(details)
  )
  guardrail_result_class(
    pass = pass,
    reason = reason,
    warnings = warnings,
    details = details
  )
}

#' Compose guardrails
#'
#' Combine multiple guardrails into a single composite guardrail.
#'
#' @param ... Guardrail objects to compose.
#' @param mode Character(1). `"all"` requires every guardrail to pass (default).
#'   `"any"` passes if at least one guardrail passes.
#' @return A composite guardrail of class `secureguard`.
#' @export
#' @examples
#' # Compose two code guardrails (both must pass)
#' g <- compose_guardrails(
#'   guard_code_analysis(),
#'   guard_code_complexity()
#' )
#' run_guardrail(g, "x <- 1 + 2")
#'
#' # Use "any" mode (at least one must pass)
#' g2 <- compose_guardrails(
#'   guard_code_analysis(),
#'   guard_code_complexity(),
#'   mode = "any"
#' )
#' run_guardrail(g2, "x <- 1")
compose_guardrails <- function(..., mode = c("all", "any")) {

  guardrails <- list(...)
  mode <- match.arg(mode)

  # Validate all are guardrails

  for (i in seq_along(guardrails)) {
    if (!S7_inherits(guardrails[[i]], secureguard_class)) {
      cli_abort("Argument {i} is not a guardrail (class {.cls secureguard}).")
    }
  }

  if (length(guardrails) == 0L) {
    cli_abort("At least one guardrail is required.")
  }

  # Infer type from children (must be same type)
  types <- vapply(guardrails, function(g) g@type, character(1))
  unique_types <- unique(types)
  if (length(unique_types) > 1L) {
    cli_abort(
      "Cannot compose guardrails of different types: {.val {unique_types}}."
    )
  }

  check_fn <- function(x) {
    results <- lapply(guardrails, function(g) run_guardrail(g, x))
    passes <- vapply(results, function(r) r@pass, logical(1))
    all_warnings <- unlist(
      lapply(results, function(r) r@warnings),
      use.names = FALSE
    )
    if (is.null(all_warnings)) all_warnings <- character(0)
    all_reasons <- vapply(
      results[!passes],
      function(r) r@reason %||% "check failed",
      character(1)
    )

    if (mode == "all") {
      pass <- all(passes)
      reason <- if (!pass) paste(all_reasons, collapse = "; ") else NULL
    } else {
      pass <- any(passes)
      reason <- if (!pass) paste(all_reasons, collapse = "; ") else NULL
    }

    guardrail_result(
      pass = pass,
      reason = reason,
      warnings = all_warnings,
      details = list(results = results)
    )
  }

  names_str <- paste(
    vapply(guardrails, function(g) g@name, character(1)),
    collapse = " + "
  )

  new_guardrail(
    name = paste0("composed(", names_str, ")"),
    type = unique_types,
    check_fn = check_fn,
    description = paste0(
      "Composite guardrail (mode=", mode, "): ", names_str
    )
  )
}

#' Run a single guardrail
#'
#' @param guardrail A guardrail object.
#' @param x The input to check (string for input/code, any R object for output).
#' @return A [guardrail_result()].
#' @export
#' @examples
#' g <- guard_code_analysis()
#' result <- run_guardrail(g, "x <- 1 + 2")
#' result@pass
#'
#' result2 <- run_guardrail(g, "system('ls')")
#' result2@pass
#' result2@reason
run_guardrail <- function(guardrail, x) {
  if (!S7_inherits(guardrail, secureguard_class)) {
    cli_abort("{.arg guardrail} must be a {.cls secureguard} object.")
  }
  guardrail@check_fn(x)
}

#' Run all guardrails and collect results
#'
#' @param guardrails A list of guardrail objects.
#' @param x The input to check.
#' @return A list with components `pass` (logical), `results` (list of
#'   individual results), `warnings` (character vector), and `reasons`
#'   (character vector of failure reasons).
#' @export
#' @examples
#' guards <- list(
#'   guard_code_analysis(),
#'   guard_code_complexity()
#' )
#' result <- check_all(guards, "x <- 1 + 2")
#' result$pass
#'
#' result2 <- check_all(guards, "system('ls')")
#' result2$pass
#' result2$reasons
check_all <- function(guardrails, x) {
  if (!is.list(guardrails)) {
    cli_abort("{.arg guardrails} must be a list of guardrail objects.")
  }
  results <- lapply(guardrails, function(g) run_guardrail(g, x))
  passes <- vapply(results, function(r) r@pass, logical(1))
  all_warnings <- unlist(
    lapply(results, function(r) r@warnings),
    use.names = FALSE
  )
  if (is.null(all_warnings)) all_warnings <- character(0)
  reasons <- vapply(
    results[!passes],
    function(r) r@reason %||% "check failed",
    character(1)
  )

  list(
    pass = all(passes),
    results = results,
    warnings = all_warnings,
    reasons = reasons
  )
}

#' @export
method(print, secureguard_class) <- function(x, ...) {
  cli_text("<secureguard> {.strong {x@name}} ({x@type})")
  if (nzchar(x@description)) {
    cli_text("  {x@description}")
  }
  invisible(x)
}

#' @export
method(print, guardrail_result_class) <- function(x, ...) {
  status <- if (x@pass) "PASS" else "FAIL"
  cli_text("<guardrail_result> {status}")
  if (!is.null(x@reason)) {
    cli_text("  Reason: {x@reason}")
  }
  if (length(x@warnings) > 0L) {
    cli_text("  Warnings: {length(x@warnings)}")
  }
  invisible(x)
}
