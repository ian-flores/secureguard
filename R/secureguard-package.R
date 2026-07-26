#' @keywords internal
"_PACKAGE"

# Tracer name used by the otel package for OpenTelemetry tracing.
# otel discovers this automatically when otel calls are made from
# within this package's namespace.
otel_tracer_name <- "com.github.ian-flores.secureguard"

## usethis namespace: start
#' @import S7
#' @importFrom rlang abort warn inform is_function is_string is_character
#' @importFrom cli cli_abort cli_warn cli_inform cli_text
## usethis namespace: end
NULL
