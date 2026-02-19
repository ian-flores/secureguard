#' Code data flow guardrail
#'
#' Creates a guardrail that detects data flow patterns in R code using AST
#' analysis. Can block environment access, network operations, file writes,
#' and file reads.
#'
#' @param block_env_access Logical(1). Block environment variable access
#'   (`Sys.getenv`, `Sys.setenv`, `Sys.unsetenv`, `.GlobalEnv`,
#'   `globalenv()`, `parent.env()`). Default `TRUE`.
#' @param block_network Logical(1). Block network operations (`url()`,
#'   `download.file`, `curl::*`, `httr::*`, `httr2::*`,
#'   `socketConnection`). Default `TRUE`.
#' @param block_file_write Logical(1). Block file write operations
#'   (`writeLines`, `write.csv`, `write.table`, `saveRDS`, `save`,
#'   `cat(..., file=)`, `sink`, `file.create`, `file.copy`, `file.rename`,
#'   `unlink`, `file.remove`). Default `TRUE`.
#' @param block_file_read Logical(1). Block file read operations
#'   (`readLines`, `read.csv`, `read.table`, `readRDS`, `load`, `scan`,
#'   `source`, `file`). Default `FALSE`.
#' @return A guardrail object of class `"secureguard"` with type `"code"`.
#' @export
#' @examples
#' g <- guard_code_dataflow()
#' run_guardrail(g, "x <- 1 + 2")
#' run_guardrail(g, "Sys.getenv('SECRET_KEY')")
guard_code_dataflow <- function(block_env_access = TRUE,
                                block_network = TRUE,
                                block_file_write = TRUE,
                                block_file_read = FALSE) {
  if (!is.logical(block_env_access) || length(block_env_access) != 1L) {
    cli_abort("{.arg block_env_access} must be TRUE or FALSE.")
  }
  if (!is.logical(block_network) || length(block_network) != 1L) {
    cli_abort("{.arg block_network} must be TRUE or FALSE.")
  }
  if (!is.logical(block_file_write) || length(block_file_write) != 1L) {
    cli_abort("{.arg block_file_write} must be TRUE or FALSE.")
  }
  if (!is.logical(block_file_read) || length(block_file_read) != 1L) {
    cli_abort("{.arg block_file_read} must be TRUE or FALSE.")
  }

  # Define category function lists
  env_fns <- c("Sys.getenv", "Sys.setenv", "Sys.unsetenv")
  env_symbols <- c(".GlobalEnv")
  env_calls <- c("globalenv", "parent.env")

  network_fns <- c("url", "download.file", "socketConnection")
  network_ns <- c("curl", "httr", "httr2")

  file_write_fns <- c(
    "writeLines", "write.csv", "write.table",
    "saveRDS", "save",
    "sink", "file.create", "file.copy", "file.rename",
    "unlink", "file.remove"
  )
  # cat() is only a write when it has a file= argument
  cat_fn <- "cat"

  file_read_fns <- c(
    "readLines", "read.csv", "read.table",
    "readRDS", "load", "scan", "source", "file"
  )

  check_fn <- function(code) {
    if (!is_string(code)) {
      cli_abort("{.arg code} must be a single character string.")
    }

    violations <- list()

    visitor <- list(
      on_call = function(expr, fn_name, depth) {
        if (is.na(fn_name)) return(NULL)

        # Environment access
        if (block_env_access) {
          if (fn_name %in% env_fns || fn_name %in% env_calls) {
            violations[[length(violations) + 1L]] <<- list(
              category = "env_access", fn = fn_name
            )
            return(NULL)
          }
        }

        # Network access
        if (block_network) {
          if (fn_name %in% network_fns) {
            violations[[length(violations) + 1L]] <<- list(
              category = "network", fn = fn_name
            )
            return(NULL)
          }
          # Check namespace prefixes
          for (ns in network_ns) {
            prefix <- paste0(ns, "::")
            prefix3 <- paste0(ns, ":::")
            if (startsWith(fn_name, prefix) || startsWith(fn_name, prefix3)) {
              violations[[length(violations) + 1L]] <<- list(
                category = "network", fn = fn_name
              )
              return(NULL)
            }
          }
        }

        # File write
        if (block_file_write) {
          if (fn_name %in% file_write_fns) {
            violations[[length(violations) + 1L]] <<- list(
              category = "file_write", fn = fn_name
            )
            return(NULL)
          }
          # cat() with file= argument
          if (fn_name == cat_fn && length(expr) >= 2L) {
            arg_names <- names(expr)
            if (!is.null(arg_names) && "file" %in% arg_names) {
              violations[[length(violations) + 1L]] <<- list(
                category = "file_write", fn = "cat(file=)"
              )
              return(NULL)
            }
          }
        }

        # File read
        if (block_file_read) {
          if (fn_name %in% file_read_fns) {
            violations[[length(violations) + 1L]] <<- list(
              category = "file_read", fn = fn_name
            )
            return(NULL)
          }
        }

        NULL
      },
      on_symbol = function(expr, name, depth) {
        # .GlobalEnv is a symbol
        if (block_env_access && name %in% env_symbols) {
          violations[[length(violations) + 1L]] <<- list(
            category = "env_access", fn = name
          )
        }
        NULL
      }
    )

    walk_code(code, visitor)

    if (length(violations) > 0L) {
      categories <- unique(vapply(violations, function(v) v$category,
                                  character(1)))
      fns <- unique(vapply(violations, function(v) v$fn, character(1)))

      guardrail_result(
        pass = FALSE,
        reason = paste0(
          "Data flow violation(s): ",
          paste(fns, collapse = ", ")
        ),
        details = list(
          violations = violations,
          categories = categories
        )
      )
    } else {
      guardrail_result(pass = TRUE)
    }
  }

  active <- character(0)
  if (block_env_access) active <- c(active, "env_access")
  if (block_network) active <- c(active, "network")
  if (block_file_write) active <- c(active, "file_write")
  if (block_file_read) active <- c(active, "file_read")

  new_guardrail(
    name = "code_dataflow",
    type = "code",
    check_fn = check_fn,
    description = paste0(
      "Data flow restrictions (",
      paste(active, collapse = ", "), ")"
    )
  )
}
