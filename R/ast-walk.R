#' Parse code string into expressions
#'
#' Parses an R code string into a list of expressions, with clear
#' error messages on failure.
#'
#' @param code Character(1). R code to parse.
#' @return A parsed expression object (from [base::parse()]).
#' @export
parse_code <- function(code) {
  if (!is_string(code)) {
    cli_abort("{.arg code} must be a single character string.")
  }
  tryCatch(
    parse(text = code, keep.source = FALSE),
    error = function(e) {
      cli_abort(c(
        "Failed to parse code.",
        "x" = e$message
      ))
    }
  )
}

#' Walk an AST node recursively
#'
#' Visits every node in a parsed R expression, calling visitor callbacks
#' for calls, symbols, and literals. Findings from callbacks are accumulated
#' and returned.
#'
#' @param expr A language object (from [parse_code()] or [base::parse()]).
#' @param visitor A list with optional callback functions:
#'   \describe{
#'     \item{`on_call`}{`function(expr, fn_name, depth)` -- called for
#'       function calls. `fn_name` is extracted via [call_fn_name()].}
#'     \item{`on_symbol`}{`function(expr, name, depth)` -- called for
#'       symbols (names).}
#'     \item{`on_literal`}{`function(expr, depth)` -- called for literal
#'       values (numeric, character, logical, NULL, etc.).}
#'   }
#'   Each callback should return `NULL` to continue without accumulating,
#'   or any other value to add it to the findings list.
#' @param depth Integer. Current nesting depth (used internally for
#'   recursion). Defaults to 0.
#' @return A list of findings accumulated from visitor callbacks
#'   (excluding `NULL` returns).
#' @export
walk_ast <- function(expr, visitor, depth = 0L) {
  if (!is.list(visitor)) {
    cli_abort("{.arg visitor} must be a list of callback functions.")
  }

  findings <- list()

  if (is.call(expr)) {
    fn_name <- call_fn_name(expr)

    if (is.function(visitor$on_call)) {
      result <- visitor$on_call(expr, fn_name, depth)
      if (!is.null(result)) {
        findings <- c(findings, list(result))
      }
    }

    # Recurse into all children (including the function position)
    for (i in seq_along(expr)) {
      child <- expr[[i]]
      if (!is.null(child)) {
        findings <- c(findings, walk_ast(child, visitor, depth + 1L))
      }
    }
  } else if (is.symbol(expr) && nzchar(as.character(expr))) {
    # Symbols (names) -- exclude empty symbols (from missing args)
    if (is.function(visitor$on_symbol)) {
      name <- as.character(expr)
      result <- visitor$on_symbol(expr, name, depth)
      if (!is.null(result)) {
        findings <- c(findings, list(result))
      }
    }
  } else if (is.pairlist(expr)) {
    # Function formals -- recurse into default values
    for (i in seq_along(expr)) {
      child <- expr[[i]]
      if (!is.null(child) && !is.symbol(child)) {
        findings <- c(findings, walk_ast(child, visitor, depth + 1L))
      } else if (is.symbol(child) && nzchar(as.character(child))) {
        findings <- c(findings, walk_ast(child, visitor, depth + 1L))
      }
    }
  } else {
    # Literals: numeric, character, logical, complex, NULL, NA, etc.
    if (is.function(visitor$on_literal)) {
      result <- visitor$on_literal(expr, depth)
      if (!is.null(result)) {
        findings <- c(findings, list(result))
      }
    }
  }

  findings
}

#' Walk all expressions in a code string
#'
#' Parses the code and walks each top-level expression with the visitor.
#'
#' @param code Character(1). R code to parse and walk.
#' @param visitor A visitor list (see [walk_ast()]).
#' @return A list of accumulated findings from all top-level expressions.
#' @export
walk_code <- function(code, visitor) {
  parsed <- parse_code(code)
  findings <- list()
  for (i in seq_along(parsed)) {
    findings <- c(findings, walk_ast(parsed[[i]], visitor, depth = 0L))
  }
  findings
}

#' Extract function name from a call expression
#'
#' Returns the function name for simple calls (`fn(x)`), namespaced calls
#' (`pkg::fn(x)`, `pkg:::fn(x)`), and `do.call()` with a string literal
#' first argument (`do.call("fn", list(x))`).
#'
#' @param expr A call expression.
#' @return Character(1). The function name, or `NA_character_` if it cannot
#'   be determined (e.g., anonymous function calls).
#' @export
call_fn_name <- function(expr) {
  if (!is.call(expr)) {
    cli_abort("{.arg expr} must be a call expression.")
  }

  head <- expr[[1L]]

  # Namespaced calls: pkg::fn or pkg:::fn
  if (is.call(head)) {
    op <- as.character(head[[1L]])
    if (op %in% c("::", ":::") && length(head) == 3L) {
      pkg <- as.character(head[[2L]])
      fn <- as.character(head[[3L]])
      return(paste0(pkg, op, fn))
    }
    # Other call-head patterns (e.g., (function(x) x)(1)) -- not named
    return(NA_character_)
  }

  # Simple calls: fn(x)
  if (is.symbol(head)) {
    fn_name <- as.character(head)

    # do.call with string literal first arg
    if (fn_name == "do.call" && length(expr) >= 2L) {
      first_arg <- expr[[2L]]
      if (is.character(first_arg) && length(first_arg) == 1L) {
        return(first_arg)
      }
    }

    return(fn_name)
  }

  NA_character_
}

#' Compute maximum AST nesting depth
#'
#' @param expr A language object.
#' @param depth Integer. Current depth (internal).
#' @return Integer. Maximum nesting depth.
#' @export
ast_depth <- function(expr, depth = 0L) {
  if (is.call(expr)) {
    child_depths <- vapply(
      seq_along(expr),
      function(i) {
        child <- expr[[i]]
        if (!is.null(child)) {
          ast_depth(child, depth + 1L)
        } else {
          depth
        }
      },
      integer(1)
    )
    return(max(child_depths, depth))
  }

  if (is.pairlist(expr)) {
    child_depths <- vapply(
      seq_along(expr),
      function(i) {
        child <- expr[[i]]
        if (!is.null(child)) {
          ast_depth(child, depth + 1L)
        } else {
          depth
        }
      },
      integer(1)
    )
    return(max(child_depths, depth))
  }

  # Leaf node (symbol, literal)
  depth
}

#' Compute summary statistics for R code AST
#'
#' Parses the code and returns counts of calls, assignments, symbols,
#' expressions, and maximum nesting depth.
#'
#' @param code Character(1). R code to analyse.
#' @return A named list with components:
#'   \describe{
#'     \item{`n_calls`}{Number of function calls.}
#'     \item{`n_assignments`}{Number of assignment operations (including
#'       `<-`, `=`, `->`, `<<-`, `->>`, and `assign()`).}
#'     \item{`n_symbols`}{Number of symbol (name) references.}
#'     \item{`depth`}{Maximum AST nesting depth.}
#'     \item{`n_expressions`}{Number of top-level expressions.}
#'   }
#' @export
ast_stats <- function(code) {
  parsed <- parse_code(code)

  assignment_ops <- c("<-", "=", "<<-", "->", "->>")

  n_calls <- 0L
  n_assignments <- 0L
  n_symbols <- 0L

  visitor <- list(
    on_call = function(expr, fn_name, depth) {
      n_calls <<- n_calls + 1L

      # Count assignments
      if (!is.na(fn_name) && fn_name %in% assignment_ops) {
        n_assignments <<- n_assignments + 1L
      }
      # assign() function call
      if (!is.na(fn_name) && fn_name == "assign") {
        n_assignments <<- n_assignments + 1L
      }
      NULL
    },
    on_symbol = function(expr, name, depth) {
      n_symbols <<- n_symbols + 1L
      NULL
    }
  )

  max_depth <- 0L
  for (i in seq_along(parsed)) {
    walk_ast(parsed[[i]], visitor, depth = 0L)
    d <- ast_depth(parsed[[i]])
    if (d > max_depth) max_depth <- d
  }

  list(
    n_calls = n_calls,
    n_assignments = n_assignments,
    n_symbols = n_symbols,
    depth = max_depth,
    n_expressions = length(parsed)
  )
}
