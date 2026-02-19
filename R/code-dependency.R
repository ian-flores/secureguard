#' Code dependency guardrail
#'
#' Creates a guardrail that controls which packages can be used in R code.
#' Detects package usage via `library()`, `require()`, `pkg::fn`,
#' `pkg:::fn`, and `loadNamespace()` calls.
#'
#' @param allowed_packages Character vector of permitted package names
#'   (allowlist mode). If non-`NULL`, only these packages (plus base packages
#'   if `allow_base = TRUE`) are permitted. Cannot be used together with
#'   `denied_packages`.
#' @param denied_packages Character vector of denied package names (denylist
#'   mode). If non-`NULL`, these packages are blocked. Cannot be used together
#'   with `allowed_packages`.
#' @param allow_base Logical(1). If `TRUE` (default), base R packages
#'   (`base`, `utils`, `stats`, `methods`, `grDevices`, `graphics`,
#'   `datasets`) are always permitted regardless of allowlist/denylist.
#' @return A guardrail object of class `"secureguard"` with type `"code"`.
#' @export
#' @examples
#' g <- guard_code_dependencies(denied_packages = "processx")
#' run_guardrail(g, "library(dplyr)")
#' run_guardrail(g, "processx::run('ls')")
guard_code_dependencies <- function(allowed_packages = NULL,
                                    denied_packages = NULL,
                                    allow_base = TRUE) {
  if (!is.null(allowed_packages) && !is.null(denied_packages)) {
    cli_abort(
      "Cannot specify both {.arg allowed_packages} and {.arg denied_packages}."
    )
  }
  if (!is.null(allowed_packages) && !is.character(allowed_packages)) {
    cli_abort("{.arg allowed_packages} must be a character vector or NULL.")
  }
  if (!is.null(denied_packages) && !is.character(denied_packages)) {
    cli_abort("{.arg denied_packages} must be a character vector or NULL.")
  }
  if (!is.logical(allow_base) || length(allow_base) != 1L) {
    cli_abort("{.arg allow_base} must be TRUE or FALSE.")
  }

  base_packages <- c(
    "base", "utils", "stats", "methods",
    "grDevices", "graphics", "datasets"
  )

  check_fn <- function(code) {
    if (!is_string(code)) {
      cli_abort("{.arg code} must be a single character string.")
    }

    detected_packages <- character(0)

    visitor <- list(
      on_call = function(expr, fn_name, depth) {
        if (is.na(fn_name)) return(NULL)

        # library(x), require(x)
        if (fn_name %in% c("library", "require") && length(expr) >= 2L) {
          pkg_arg <- expr[[2L]]
          if (is.symbol(pkg_arg)) {
            detected_packages[length(detected_packages) + 1L] <<-
              as.character(pkg_arg)
          } else if (is.character(pkg_arg) && length(pkg_arg) == 1L) {
            detected_packages[length(detected_packages) + 1L] <<- pkg_arg
          }
          return(NULL)
        }

        # loadNamespace(x)
        if (fn_name == "loadNamespace" && length(expr) >= 2L) {
          pkg_arg <- expr[[2L]]
          if (is.character(pkg_arg) && length(pkg_arg) == 1L) {
            detected_packages[length(detected_packages) + 1L] <<- pkg_arg
          }
          return(NULL)
        }

        # pkg::fn or pkg:::fn
        head <- expr[[1L]]
        if (is.call(head)) {
          op <- as.character(head[[1L]])
          if (op %in% c("::", ":::") && length(head) == 3L) {
            pkg <- as.character(head[[2L]])
            detected_packages[length(detected_packages) + 1L] <<- pkg
          }
        }

        NULL
      }
    )

    walk_code(code, visitor)
    detected_packages <- unique(detected_packages)

    # Filter base packages if allowed
    if (allow_base) {
      check_packages <- setdiff(detected_packages, base_packages)
    } else {
      check_packages <- detected_packages
    }

    # Determine violations
    violations <- character(0)

    if (!is.null(allowed_packages)) {
      # Allowlist mode: anything not in allowed_packages is blocked
      violations <- setdiff(check_packages, allowed_packages)
    } else if (!is.null(denied_packages)) {
      # Denylist mode: anything in denied_packages is blocked
      violations <- intersect(check_packages, denied_packages)
    }
    # If neither is set, everything is allowed

    if (length(violations) > 0L) {
      guardrail_result(
        pass = FALSE,
        reason = paste0(
          "Disallowed package(s): ",
          paste(sort(violations), collapse = ", ")
        ),
        details = list(
          detected_packages = sort(detected_packages),
          violations = sort(violations)
        )
      )
    } else {
      guardrail_result(
        pass = TRUE,
        details = list(detected_packages = sort(detected_packages))
      )
    }
  }

  mode_desc <- if (!is.null(allowed_packages)) {
    paste0("allowlist: ", paste(allowed_packages, collapse = ", "))
  } else if (!is.null(denied_packages)) {
    paste0("denylist: ", paste(denied_packages, collapse = ", "))
  } else {
    "no restrictions"
  }

  new_guardrail(
    name = "code_dependencies",
    type = "code",
    check_fn = check_fn,
    description = paste0("Package dependency control (", mode_desc, ")")
  )
}
