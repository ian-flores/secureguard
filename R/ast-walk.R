#' Parse code string into expressions
#'
#' Parses a string of R code. If the code doesn't parse, the error says
#' why.
#'
#' @param code Character(1). R code to parse.
#' @return A parsed expression object (from [base::parse()]).
#' @export
#' @examples
#' expr <- parse_code("x <- 1 + 2")
#' length(expr)
#'
#' expr2 <- parse_code("f <- function(x) x + 1\nf(10)")
#' length(expr2)
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
#' Visits every node in a parsed R expression and calls your callbacks on
#' function calls, symbols, and literals. Anything a callback returns, other
#' than `NULL`, is collected and returned.
#'
#' @param expr A language object (from [parse_code()] or [base::parse()]).
#' @param visitor A list with optional callback functions:
#'   \describe{
#'     \item{`on_call`}{`function(expr, fn_name, depth)`, called for
#'       function calls. `fn_name` comes from [call_fn_name()].}
#'     \item{`on_symbol`}{`function(expr, name, depth)`, called for
#'       symbols (names).}
#'     \item{`on_literal`}{`function(expr, depth)`, called for literal
#'       values (numbers, strings, logicals, `NULL`, and so on).}
#'   }
#'   A callback returns `NULL` to record nothing, or any other value to add
#'   it to the results.
#' @param depth Integer. Current nesting depth (used internally for
#'   recursion). Defaults to 0.
#' @return A list of the non-`NULL` values the callbacks returned.
#' @export
#' @examples
#' # Collect all function call names from an expression
#' expr <- parse_code("mean(x) + sum(y)")[[1]]
#' visitor <- list(
#'   on_call = function(expr, fn_name, depth) fn_name
#' )
#' walk_ast(expr, visitor)
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
#' @return A list of the non-`NULL` values the callbacks returned, across
#'   all top-level expressions.
#' @export
#' @examples
#' # Find all function calls in a code string
#' visitor <- list(
#'   on_call = function(expr, fn_name, depth) fn_name
#' )
#' walk_code("x <- mean(1:10)\ny <- sum(x)", visitor)
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
#' (`pkg::fn(x)`, `pkg:::fn(x)`), and `do.call()` calls that name their
#' target directly: `do.call("fn", ...)`, `do.call(fn, ...)`, or
#' `do.call(pkg::fn, ...)`. `base::do.call()` and `base:::do.call()` are
#' resolved the same way. A `do.call()` whose target is computed, such as
#' `do.call(get_fn(), ...)`, returns its own name.
#'
#' A symbol target is taken at face value: `do.call(fn, ...)` returns
#' `"fn"` even if `fn` is a variable holding some other function's name.
#'
#' @param expr A call expression.
#' @return Character(1). The function name, or `NA_character_` if it cannot
#'   be determined (e.g., anonymous function calls).
#' @export
#' @examples
#' expr <- parse_code("mean(x)")[[1]]
#' call_fn_name(expr)
#'
#' expr2 <- parse_code("stats::median(x)")[[1]]
#' call_fn_name(expr2)
#'
#' expr3 <- parse_code("do.call(rbind, list(a, b))")[[1]]
#' call_fn_name(expr3)
call_fn_name <- function(expr) {
  if (!is.call(expr)) {
    cli_abort("{.arg expr} must be a call expression.")
  }

  if (is_do_call(expr)) {
    target <- fn_ref_name(do_call_arg(expr, "what"))
    if (!is.na(target)) {
      return(target)
    }
  }

  fn_ref_name(expr[[1L]])
}

# Name of a function reference: "fn", `fn`, a "fn" string, or pkg::fn /
# pkg:::fn. NA_character_ for anything else, such as (function(x) x) or
# f(1) in f(1)(2).
fn_ref_name <- function(ref) {
  if (is.character(ref) && length(ref) == 1L && !is.na(ref)) {
    return(ref)
  }
  if (is.symbol(ref) && nzchar(as.character(ref))) {
    return(as.character(ref))
  }
  if (is.call(ref) && length(ref) == 3L && is.symbol(ref[[1L]]) &&
      as.character(ref[[1L]]) %in% c("::", ":::") &&
      is.symbol(ref[[2L]]) && is.symbol(ref[[3L]])) {
    return(paste0(
      as.character(ref[[2L]]), as.character(ref[[1L]]), as.character(ref[[3L]])
    ))
  }
  NA_character_
}

# Is `expr` a call to do.call(), base::do.call(), or base:::do.call()?
is_do_call <- function(expr) {
  fn_ref_name(expr[[1L]]) %in% c("do.call", "base::do.call", "base:::do.call")
}

# An argument of a do.call() call ("what", "args", ...), matched the way R
# matches it: by exact name, else by position among the unnamed arguments.
# NULL if it isn't supplied.
do_call_arg <- function(expr, arg) {
  args <- as.list(expr)[-1L]
  arg_names <- names(args)
  if (is.null(arg_names)) {
    arg_names <- character(length(args))
  }
  if (arg %in% arg_names) {
    return(args[[match(arg, arg_names)]])
  }
  open <- setdiff(c("what", "args", "quote", "envir"), arg_names)
  unnamed <- which(arg_names == "")
  i <- match(arg, open)
  if (is.na(i) || i > length(unnamed)) {
    return(NULL)
  }
  args[[unnamed[[i]]]]
}

#' Compute maximum AST nesting depth
#'
#' @param expr A language object.
#' @param depth Integer. Current depth (internal).
#' @return Integer. Maximum nesting depth.
#' @export
#' @examples
#' expr <- parse_code("f(g(h(1)))")[[1]]
#' ast_depth(expr)
#'
#' expr2 <- parse_code("x <- 1")[[1]]
#' ast_depth(expr2)
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

#' Count calls, assignments, and nesting in R code
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
#' @examples
#' stats <- ast_stats("x <- mean(1:10)\ny <- x + 1")
#' stats$n_calls
#' stats$n_assignments
#' stats$depth
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
