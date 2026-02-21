# Topic scope guardrail

Creates a guardrail that restricts input to specific topics using
allowlist or denylist regex patterns.

## Usage

``` r
guard_topic_scope(
  allowed_topics = NULL,
  denied_topics = NULL,
  case_sensitive = FALSE
)
```

## Arguments

- allowed_topics:

  Character vector of regex patterns. If non-`NULL`, input must match at
  least one pattern to pass. Cannot be used together with
  `denied_topics`.

- denied_topics:

  Character vector of regex patterns. Input must not match any of these
  patterns. Cannot be used together with `allowed_topics`.

- case_sensitive:

  Logical(1). Whether pattern matching is case-sensitive. Default:
  `FALSE`.

## Value

A guardrail object of class `"secureguard"` with type `"input"`.

## Examples

``` r
g <- guard_topic_scope(allowed_topics = c("statistics", "data analysis"))
run_guardrail(g, "How do I calculate a t-test in statistics?")
#> <guardrail_result> PASS
run_guardrail(g, "What is the weather today?")
#> <guardrail_result> FAIL
#> Reason: Input does not match any allowed topic.
```
