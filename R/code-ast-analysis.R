#' Default blocked functions
#'
#' Returns the default character vector of function names considered dangerous
#' for LLM-generated code. These include system-level calls, dynamic evaluation,
#' and file/network operations.
#'
#' @return Character vector of blocked function names.
#' @export
default_blocked_functions <- function() {
  c(
    "system", "system2", "shell",
    ".Internal", ".Primitive", ".Call", ".C", ".Fortran", ".External",
    "dyn.load",
    "pipe",
    "processx::run", "callr::r",
    "socketConnection",
    "download.file",
    "eval", "evalq",
    "get", "match.fun",
    "Sys.setenv",
    "unlink", "file.remove"
  )
}

#' Code AST analysis guardrail
#'
#' Creates a guardrail that inspects R code for calls to blocked functions.
#' Uses AST walking to detect direct calls and optionally indirect invocation
#' via `do.call()`.
#'
#' @param blocked_functions Character vector of function names to block.
#'   Defaults to [default_blocked_functions()]. Names can include namespace
#'   prefixes (e.g. `"processx::run"`).
#' @param allow_namespaces Character vector of package prefixes to allow even
#'   if a function from that package appears in `blocked_functions`. For
#'   example, `allow_namespaces = "dplyr"` would allow `dplyr::filter`.
#' @param detect_indirect Logical(1). If `TRUE` (default), also detect indirect
#'   calls via `do.call("system", ...)` where the first argument is a string
#'   literal matching a blocked function.
#' @return A guardrail object of class `"secureguard"` with type `"code"`.
#' @export
#' @examples
#' g <- guard_code_analysis()
#' run_guardrail(g, "x <- 1 + 2")
#' run_guardrail(g, "system('ls')")
guard_code_analysis <- function(blocked_functions = default_blocked_functions(),
                                allow_namespaces = NULL,
                                detect_indirect = TRUE) {
  if (!is.character(blocked_functions) || length(blocked_functions) == 0L) {
    cli_abort("{.arg blocked_functions} must be a non-empty character vector.")
  }
  if (!is.null(allow_namespaces) && !is.character(allow_namespaces)) {
    cli_abort("{.arg allow_namespaces} must be a character vector or NULL.")
  }
  if (!is.logical(detect_indirect) || length(detect_indirect) != 1L) {
    cli_abort("{.arg detect_indirect} must be TRUE or FALSE.")
  }

  check_fn <- function(code) {
    if (!is_string(code)) {
      cli_abort("{.arg code} must be a single character string.")
    }

    visitor <- list(
      on_call = function(expr, fn_name, depth) {
        if (is.na(fn_name)) return(NULL)

        # Check if fn_name is in an allowed namespace
        if (!is.null(allow_namespaces)) {
          for (ns in allow_namespaces) {
            prefix <- paste0(ns, "::")
            prefix3 <- paste0(ns, ":::")
            if (startsWith(fn_name, prefix) || startsWith(fn_name, prefix3)) {
              return(NULL)
            }
          }
        }

        # Direct match
        if (fn_name %in% blocked_functions) {
          return(fn_name)
        }

        # Indirect via do.call
        if (detect_indirect && fn_name == "do.call" && length(expr) >= 2L) {
          # Already resolved by call_fn_name -- but we need the raw first arg
          # call_fn_name returns the string literal for do.call, so fn_name
          # would already be the resolved name. However, walk_ast visits the
          # do.call node itself, and call_fn_name resolves do.call("system",...)
          # to "system". So fn_name here is the resolved target. Already
          # handled above by the direct match.
          NULL
        } else {
          NULL
        }
      }
    )

    findings <- walk_code(code, visitor)
    blocked <- unique(unlist(findings))

    if (length(blocked) > 0L) {
      guardrail_result(
        pass = FALSE,
        reason = paste0(
          "Blocked function(s) detected: ",
          paste(blocked, collapse = ", ")
        ),
        details = list(blocked_calls = blocked)
      )
    } else {
      guardrail_result(pass = TRUE)
    }
  }

  new_guardrail(
    name = "code_analysis",
    type = "code",
    check_fn = check_fn,
    description = paste0(
      "AST-based function blocking (",
      length(blocked_functions), " blocked functions)"
    )
  )
}
