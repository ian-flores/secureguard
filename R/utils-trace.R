# Internal tracing helpers -- not exported
# otel is a soft dependency (Suggests only)

#' Check if OpenTelemetry tracing is active
#' @return Logical scalar.
#' @noRd
.trace_active <- function() {
  requireNamespace("otel", quietly = TRUE) &&
    otel::is_tracing_enabled()
}

#' Add an event to the currently active span (if tracing)
#' @param name Event name.
#' @param data Named list of event data.
#' @return Invisible `NULL`.
#' @noRd
.span_event <- function(name, data = list()) {
  if (.trace_active()) {
    span <- otel::get_active_span()
    if (!is.null(span)) {
      data <- data[!vapply(data, is.null, logical(1))]
      span$add_event(name, attributes = otel::as_attributes(data))
    }
  }
  invisible(NULL)
}

#' Evaluate an expression inside an active span (if tracing)
#'
#' When tracing is enabled, a span is started and stays active while
#' `expr` is evaluated; it ends automatically when this function
#' returns. When
#' tracing is disabled (or otel is not installed), `expr` is simply
#' evaluated.
#'
#' @param name Span name.
#' @param expr Expression to evaluate.
#' @param type Span type, recorded as the `secureguard.type` attribute.
#' @return The value of `expr`.
#' @noRd
.with_span <- function(name, expr, type = "guardrail") {
  if (.trace_active()) {
    otel::start_local_active_span(
      name,
      attributes = otel::as_attributes(list(secureguard.type = type))
    )
  }
  expr
}
