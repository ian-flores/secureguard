#' Default blocked functions
#'
#' The functions [guard_code_analysis()] blocks unless you give it your own
#' list. They run shell commands, evaluate code built at run time, call
#' compiled code, delete files, or open network connections.
#'
#' @return Character vector of blocked function names.
#' @export
#' @examples
#' fns <- default_blocked_functions()
#' "system" %in% fns
#' "eval" %in% fns
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
#' Parses R code and fails if it calls a blocked function. Because it reads
#' the parsed code rather than the text, it also finds calls made through
#' `do.call("system", ...)` or `do.call(system, ...)` and namespaced calls
#' like `base::system()`. It does not resolve names computed at run time,
#' such as `fn <- "system"; do.call(fn, ...)`; the defaults block `get()`
#' and `match.fun()` outright instead.
#'
#' @param blocked_functions Character vector of function names to block.
#'   Defaults to [default_blocked_functions()]. A bare name like `"system"`
#'   also blocks `base::system()`. A name with a package prefix, like
#'   `"processx::run"`, blocks only that package's function.
#' @param allow_namespaces Character vector of package names. Namespaced calls
#'   into these packages are allowed even if the function is in
#'   `blocked_functions`. For example, `allow_namespaces = "processx"` lets
#'   `processx::run()` through.
#' @param detect_indirect Logical(1). If `TRUE` (default), also catch calls
#'   like `do.call("system", ...)`, where the first argument is a string
#'   naming a blocked function. A bare or namespaced name works too:
#'   `do.call(system, ...)`, `do.call(base::system, ...)`, and the same
#'   through `base::do.call()`. If `FALSE`, such a call counts only as a
#'   call to `do.call()` itself.
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

    is_blocked <- function(fn_name) {
      if (is.na(fn_name)) return(FALSE)

      # Check if fn_name is in an allowed namespace
      if (!is.null(allow_namespaces)) {
        for (ns in allow_namespaces) {
          prefix <- paste0(ns, "::")
          prefix3 <- paste0(ns, ":::")
          if (startsWith(fn_name, prefix) || startsWith(fn_name, prefix3)) {
            return(FALSE)
          }
        }
      }

      # Direct match, on the full name ("processx::run") or the bare name,
      # so that `base::system()` can't slip past a block on "system".
      bare_name <- sub("^[^:]+:::?", "", fn_name)
      fn_name %in% blocked_functions || bare_name %in% blocked_functions
    }

    visitor <- list(
      on_call = function(expr, fn_name, depth) {
        # call_fn_name() resolves do.call("system", ...) to "system". The
        # do.call itself is always checked; its target only with
        # detect_indirect.
        if (is_do_call(expr)) {
          head_name <- fn_ref_name(expr[[1L]])
          fn_name <- if (detect_indirect) {
            unique(c(head_name, fn_name))
          } else {
            head_name
          }
        }

        hits <- fn_name[vapply(fn_name, is_blocked, logical(1))]
        if (length(hits) == 0L) NULL else hits
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
