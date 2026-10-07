# Advanced guardrail patterns

## What’s here

[`vignette("secureguard")`](https://ian-flores.github.io/secureguard/articles/secureguard.md)
introduces the three kinds of guardrail and the built-in checks. This
one shows how to write your own guardrails, combine them, build a
pipeline, and connect it to securer.

## How a pipeline works

This is what happens to one agent turn inside a
[`secure_pipeline()`](https://ian-flores.github.io/secureguard/reference/secure_pipeline.md),
which is the easiest way to put guardrails into an agent loop:

![](data:image/svg+xml;base64,PHN2ZyByb2xlPSJpbWciIGFyaWEtbGFiZWw9IlRoZSBwcm9tcHQgaXMgY2hlY2tlZCwgdGhlIG1vZGVsIHdyaXRlcyBjb2RlLCB0aGUgY29kZSBpcyBjaGVja2VkLCBpdCBydW5zIGluIHRoZSBzYW5kYm94LCB0aGUgb3V0cHV0IGlzIGNoZWNrZWQ7IGEgZmFpbGVkIGNoZWNrIHN0b3BzIHRoZSB0dXJuIGF0IHRoYXQgc3RhZ2UiIHZpZXdib3g9IjAgMCAxMDAwIDIwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZGVmcz48bWFya2VyIGlkPSJwbC1hcnJvdyIgdmlld2JveD0iMCAwIDEwIDEwIiByZWZ4PSI5IiByZWZ5PSI1IiBtYXJrZXJ3aWR0aD0iNyIgbWFya2VyaGVpZ2h0PSI3IiBvcmllbnQ9ImF1dG8tc3RhcnQtcmV2ZXJzZSI+PHBhdGggZD0iTTEgMUw5IDVMMSA5IiBmaWxsPSJub25lIiBzdHJva2U9IiMyYjFmMTIiIHN0cm9rZS13aWR0aD0iMSIgLz48L21hcmtlcj48cGF0dGVybiBpZD0icGwtaGF0Y2giIHdpZHRoPSI2IiBoZWlnaHQ9IjYiIHBhdHRlcm51bml0cz0idXNlclNwYWNlT25Vc2UiIHBhdHRlcm50cmFuc2Zvcm09InJvdGF0ZSg0NSkiPjxsaW5lIHgxPSIwIiB5MT0iMCIgeDI9IjAiIHkyPSI2IiBzdHJva2U9IiNiZjVhMzYiIHN0cm9rZS13aWR0aD0iMC42IiBvcGFjaXR5PSIwLjU1Ij48L2xpbmU+PC9wYXR0ZXJuPjwvZGVmcz48dGV4dCB4PSI2Ni4wIiB5PSI3NC4zMjUiIGZvbnQtZmFtaWx5PSJTcGFjZSBNb25vLCB1aS1tb25vc3BhY2UsIG1vbm9zcGFjZSIgZm9udC1zaXplPSI5LjUiIGZpbGw9IiM2YjU2MzgiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtd2VpZ2h0PSI0MDAiIGxldHRlci1zcGFjaW5nPSIxLjIiPlVTRVI8L3RleHQ+PHRleHQgeD0iNjYuMCIgeT0iODguMzI1IiBmb250LWZhbWlseT0iU3BhY2UgTW9ubywgdWktbW9ub3NwYWNlLCBtb25vc3BhY2UiIGZvbnQtc2l6ZT0iOS41IiBmaWxsPSIjNmI1NjM4IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXdlaWdodD0iNDAwIiBsZXR0ZXItc3BhY2luZz0iMS4yIj5QUk9NUFQ8L3RleHQ+PHBhdGggZD0iTTExMiA3OC4wSDEzMCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjMmIxZjEyIiBzdHJva2Utd2lkdGg9IjAuNzUiIG1hcmtlci1lbmQ9InVybCgjcGwtYXJyb3cpIiAvPjxyZWN0IHg9IjEzMiIgeT0iNDAiIHdpZHRoPSIxNDAiIGhlaWdodD0iNzYiIGZpbGw9Im5vbmUiIHN0cm9rZT0iIzJiMWYxMiIgc3Ryb2tlLXdpZHRoPSIwLjc1IiAvPjx0ZXh0IHg9IjIwMi4wIiB5PSI2OC4wIiBmb250LWZhbWlseT0iU3BhY2UgTW9ubywgdWktbW9ub3NwYWNlLCBtb25vc3BhY2UiIGZvbnQtc2l6ZT0iMTAuNSIgZmlsbD0iIzJiMWYxMiIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC13ZWlnaHQ9IjcwMCIgbGV0dGVyLXNwYWNpbmc9IjEuMiI+Y2hlY2tfaW5wdXQoKTwvdGV4dD48dGV4dCB4PSIyMDIuMCIgeT0iODIuMCIgZm9udC1mYW1pbHk9IlNwYWNlIE1vbm8sIHVpLW1vbm9zcGFjZSwgbW9ub3NwYWNlIiBmb250LXNpemU9IjkiIGZpbGw9IiM2YjU2MzgiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtd2VpZ2h0PSI0MDAiIGxldHRlci1zcGFjaW5nPSIwLjQiPmluamVjdGlvbiwgdG9waWMsPC90ZXh0Pjx0ZXh0IHg9IjIwMi4wIiB5PSI5NS4wIiBmb250LWZhbWlseT0iU3BhY2UgTW9ubywgdWktbW9ub3NwYWNlLCBtb25vc3BhY2UiIGZvbnQtc2l6ZT0iOSIgZmlsbD0iIzZiNTYzOCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC13ZWlnaHQ9IjQwMCIgbGV0dGVyLXNwYWNpbmc9IjAuNCI+cGVyc29uYWwgZGF0YTwvdGV4dD48cGF0aCBkPSJNMjAyLjAgMTE2VjE2MCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjMmIxZjEyIiBzdHJva2Utd2lkdGg9IjAuNzUiIG1hcmtlci1lbmQ9InVybCgjcGwtYXJyb3cpIiBzdHJva2UtZGFzaGFycmF5PSIzIDMiIC8+PHRleHQgeD0iMjA4LjAiIHk9IjEzOCIgZm9udC1mYW1pbHk9IlNwYWNlIE1vbm8sIHVpLW1vbm9zcGFjZSwgbW9ub3NwYWNlIiBmb250LXNpemU9IjkiIGZpbGw9IiM2YjU2MzgiIHRleHQtYW5jaG9yPSJzdGFydCIgZm9udC13ZWlnaHQ9IjQwMCIgbGV0dGVyLXNwYWNpbmc9IjAuNCI+ZmFpbDwvdGV4dD48dGV4dCB4PSIyMDIuMCIgeT0iMTc4IiBmb250LWZhbWlseT0iU3BhY2UgTW9ubywgdWktbW9ub3NwYWNlLCBtb25vc3BhY2UiIGZvbnQtc2l6ZT0iOC41IiBmaWxsPSIjYmY1YTM2IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXdlaWdodD0iNDAwIiBsZXR0ZXItc3BhY2luZz0iMS40Ij5TVE9QIMK3IFNUQUdFOiBJTlBVVDwvdGV4dD48cGF0aCBkPSJNMjcyIDc4LjBIMzAwIiBmaWxsPSJub25lIiBzdHJva2U9IiMyYjFmMTIiIHN0cm9rZS13aWR0aD0iMC43NSIgbWFya2VyLWVuZD0idXJsKCNwbC1hcnJvdykiIC8+PHRleHQgeD0iMzQ4LjAiIHk9Ijc0LjMyNSIgZm9udC1mYW1pbHk9IlNwYWNlIE1vbm8sIHVpLW1vbm9zcGFjZSwgbW9ub3NwYWNlIiBmb250LXNpemU9IjkuNSIgZmlsbD0iIzZiNTYzOCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC13ZWlnaHQ9IjQwMCIgbGV0dGVyLXNwYWNpbmc9IjEuMiI+TU9ERUw8L3RleHQ+PHRleHQgeD0iMzQ4LjAiIHk9Ijg4LjMyNSIgZm9udC1mYW1pbHk9IlNwYWNlIE1vbm8sIHVpLW1vbm9zcGFjZSwgbW9ub3NwYWNlIiBmb250LXNpemU9IjkuNSIgZmlsbD0iIzZiNTYzOCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC13ZWlnaHQ9IjQwMCIgbGV0dGVyLXNwYWNpbmc9IjEuMiI+V1JJVEVTIENPREU8L3RleHQ+PHBhdGggZD0iTTM5NCA3OC4wSDQxMiIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjMmIxZjEyIiBzdHJva2Utd2lkdGg9IjAuNzUiIG1hcmtlci1lbmQ9InVybCgjcGwtYXJyb3cpIiAvPjxyZWN0IHg9IjQxNCIgeT0iNDAiIHdpZHRoPSIxNDAiIGhlaWdodD0iNzYiIGZpbGw9Im5vbmUiIHN0cm9rZT0iIzJiMWYxMiIgc3Ryb2tlLXdpZHRoPSIwLjc1IiAvPjx0ZXh0IHg9IjQ4NC4wIiB5PSI2OC4wIiBmb250LWZhbWlseT0iU3BhY2UgTW9ubywgdWktbW9ub3NwYWNlLCBtb25vc3BhY2UiIGZvbnQtc2l6ZT0iMTAuNSIgZmlsbD0iIzJiMWYxMiIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC13ZWlnaHQ9IjcwMCIgbGV0dGVyLXNwYWNpbmc9IjEuMiI+Y2hlY2tfY29kZSgpPC90ZXh0Pjx0ZXh0IHg9IjQ4NC4wIiB5PSI4Mi4wIiBmb250LWZhbWlseT0iU3BhY2UgTW9ubywgdWktbW9ub3NwYWNlLCBtb25vc3BhY2UiIGZvbnQtc2l6ZT0iOSIgZmlsbD0iIzZiNTYzOCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC13ZWlnaHQ9IjQwMCIgbGV0dGVyLXNwYWNpbmc9IjAuNCI+ZnVuY3Rpb25zLCBjb21wbGV4aXR5LDwvdGV4dD48dGV4dCB4PSI0ODQuMCIgeT0iOTUuMCIgZm9udC1mYW1pbHk9IlNwYWNlIE1vbm8sIHVpLW1vbm9zcGFjZSwgbW9ub3NwYWNlIiBmb250LXNpemU9IjkiIGZpbGw9IiM2YjU2MzgiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtd2VpZ2h0PSI0MDAiIGxldHRlci1zcGFjaW5nPSIwLjQiPnBhY2thZ2VzLCBkYXRhIGZsb3c8L3RleHQ+PHBhdGggZD0iTTQ4NC4wIDExNlYxNjAiIGZpbGw9Im5vbmUiIHN0cm9rZT0iIzJiMWYxMiIgc3Ryb2tlLXdpZHRoPSIwLjc1IiBtYXJrZXItZW5kPSJ1cmwoI3BsLWFycm93KSIgc3Ryb2tlLWRhc2hhcnJheT0iMyAzIiAvPjx0ZXh0IHg9IjQ5MC4wIiB5PSIxMzgiIGZvbnQtZmFtaWx5PSJTcGFjZSBNb25vLCB1aS1tb25vc3BhY2UsIG1vbm9zcGFjZSIgZm9udC1zaXplPSI5IiBmaWxsPSIjNmI1NjM4IiB0ZXh0LWFuY2hvcj0ic3RhcnQiIGZvbnQtd2VpZ2h0PSI0MDAiIGxldHRlci1zcGFjaW5nPSIwLjQiPmZhaWw8L3RleHQ+PHRleHQgeD0iNDg0LjAiIHk9IjE3OCIgZm9udC1mYW1pbHk9IlNwYWNlIE1vbm8sIHVpLW1vbm9zcGFjZSwgbW9ub3NwYWNlIiBmb250LXNpemU9IjguNSIgZmlsbD0iI2JmNWEzNiIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC13ZWlnaHQ9IjQwMCIgbGV0dGVyLXNwYWNpbmc9IjEuNCI+U1RPUCDCtyBTVEFHRTogQ09ERTwvdGV4dD48cGF0aCBkPSJNNTU0IDc4LjBINTgyIiBmaWxsPSJub25lIiBzdHJva2U9IiMyYjFmMTIiIHN0cm9rZS13aWR0aD0iMC43NSIgbWFya2VyLWVuZD0idXJsKCNwbC1hcnJvdykiIC8+PHRleHQgeD0iNjMwLjAiIHk9Ijc0LjMyNSIgZm9udC1mYW1pbHk9IlNwYWNlIE1vbm8sIHVpLW1vbm9zcGFjZSwgbW9ub3NwYWNlIiBmb250LXNpemU9IjkuNSIgZmlsbD0iIzZiNTYzOCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC13ZWlnaHQ9IjQwMCIgbGV0dGVyLXNwYWNpbmc9IjEuMiI+UlVOIElOIFRIRTwvdGV4dD48dGV4dCB4PSI2MzAuMCIgeT0iODguMzI1IiBmb250LWZhbWlseT0iU3BhY2UgTW9ubywgdWktbW9ub3NwYWNlLCBtb25vc3BhY2UiIGZvbnQtc2l6ZT0iOS41IiBmaWxsPSIjNmI1NjM4IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXdlaWdodD0iNDAwIiBsZXR0ZXItc3BhY2luZz0iMS4yIj5TQU5EQk9YPC90ZXh0PjxwYXRoIGQ9Ik02NzYgNzguMEg2OTQiIGZpbGw9Im5vbmUiIHN0cm9rZT0iIzJiMWYxMiIgc3Ryb2tlLXdpZHRoPSIwLjc1IiBtYXJrZXItZW5kPSJ1cmwoI3BsLWFycm93KSIgLz48cmVjdCB4PSI2OTYiIHk9IjQwIiB3aWR0aD0iMTQwIiBoZWlnaHQ9Ijc2IiBmaWxsPSJub25lIiBzdHJva2U9IiMyYjFmMTIiIHN0cm9rZS13aWR0aD0iMC43NSIgLz48dGV4dCB4PSI3NjYuMCIgeT0iNjguMCIgZm9udC1mYW1pbHk9IlNwYWNlIE1vbm8sIHVpLW1vbm9zcGFjZSwgbW9ub3NwYWNlIiBmb250LXNpemU9IjEwLjUiIGZpbGw9IiMyYjFmMTIiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtd2VpZ2h0PSI3MDAiIGxldHRlci1zcGFjaW5nPSIxLjIiPmNoZWNrX291dHB1dCgpPC90ZXh0Pjx0ZXh0IHg9Ijc2Ni4wIiB5PSI4Mi4wIiBmb250LWZhbWlseT0iU3BhY2UgTW9ubywgdWktbW9ub3NwYWNlLCBtb25vc3BhY2UiIGZvbnQtc2l6ZT0iOSIgZmlsbD0iIzZiNTYzOCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC13ZWlnaHQ9IjQwMCIgbGV0dGVyLXNwYWNpbmc9IjAuNCI+cGVyc29uYWwgZGF0YSw8L3RleHQ+PHRleHQgeD0iNzY2LjAiIHk9Ijk1LjAiIGZvbnQtZmFtaWx5PSJTcGFjZSBNb25vLCB1aS1tb25vc3BhY2UsIG1vbm9zcGFjZSIgZm9udC1zaXplPSI5IiBmaWxsPSIjNmI1NjM4IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXdlaWdodD0iNDAwIiBsZXR0ZXItc3BhY2luZz0iMC40Ij5zZWNyZXRzLCBzaXplPC90ZXh0PjxwYXRoIGQ9Ik03NjYuMCAxMTZWMTYwIiBmaWxsPSJub25lIiBzdHJva2U9IiMyYjFmMTIiIHN0cm9rZS13aWR0aD0iMC43NSIgbWFya2VyLWVuZD0idXJsKCNwbC1hcnJvdykiIHN0cm9rZS1kYXNoYXJyYXk9IjMgMyIgLz48dGV4dCB4PSI3NzIuMCIgeT0iMTM4IiBmb250LWZhbWlseT0iU3BhY2UgTW9ubywgdWktbW9ub3NwYWNlLCBtb25vc3BhY2UiIGZvbnQtc2l6ZT0iOSIgZmlsbD0iIzZiNTYzOCIgdGV4dC1hbmNob3I9InN0YXJ0IiBmb250LXdlaWdodD0iNDAwIiBsZXR0ZXItc3BhY2luZz0iMC40Ij5mYWlsPC90ZXh0Pjx0ZXh0IHg9Ijc2Ni4wIiB5PSIxNzgiIGZvbnQtZmFtaWx5PSJTcGFjZSBNb25vLCB1aS1tb25vc3BhY2UsIG1vbm9zcGFjZSIgZm9udC1zaXplPSI4LjUiIGZpbGw9IiNiZjVhMzYiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtd2VpZ2h0PSI0MDAiIGxldHRlci1zcGFjaW5nPSIxLjQiPlNUT1AgwrcgU1RBR0U6IE9VVFBVVDwvdGV4dD48cGF0aCBkPSJNODM2IDc4LjBIODY2IiBmaWxsPSJub25lIiBzdHJva2U9IiMyYjFmMTIiIHN0cm9rZS13aWR0aD0iMC43NSIgbWFya2VyLWVuZD0idXJsKCNwbC1hcnJvdykiIC8+PHJlY3QgeD0iODY4IiB5PSI0OCIgd2lkdGg9IjEyMCIgaGVpZ2h0PSI2MCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjYmY1YTM2IiBzdHJva2Utd2lkdGg9IjAuNzUiIC8+PHRleHQgeD0iOTI4LjAiIHk9Ijc1LjAiIGZvbnQtZmFtaWx5PSJTcGFjZSBNb25vLCB1aS1tb25vc3BhY2UsIG1vbm9zcGFjZSIgZm9udC1zaXplPSIxMC41IiBmaWxsPSIjYmY1YTM2IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXdlaWdodD0iNzAwIiBsZXR0ZXItc3BhY2luZz0iMS4yIj5SRVNVTFQ8L3RleHQ+PHRleHQgeD0iOTI4LjAiIHk9Ijg5LjAiIGZvbnQtZmFtaWx5PSJTcGFjZSBNb25vLCB1aS1tb25vc3BhY2UsIG1vbm9zcGFjZSIgZm9udC1zaXplPSI5IiBmaWxsPSIjNmI1NjM4IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXdlaWdodD0iNDAwIiBsZXR0ZXItc3BhY2luZz0iMC40Ij5tYXliZSByZWRhY3RlZDwvdGV4dD48L3N2Zz4=)

Fig. 1 · secure_pipeline(): each check can stop the turn

A failure stops the turn. If the input check fails, the model never sees
the prompt. If the code check fails, the code never runs. You skip the
risky step and the work that would have followed it.

## Writing your own guardrails

The built-in guardrails handle the common cases: prompt injection,
dangerous function calls, personal data, and secrets. Your application
probably has risks of its own. An agent that writes SQL should be
checked for SQL injection. A health app may need extra patterns for
patient data. A finance tool may need to spot account and routing
numbers.

Every guardrail, built-in or yours, is an S3 object of class
`secureguard` with four fields: `name`, `type`, `check_fn`, and
`description`.
[`new_guardrail()`](https://ian-flores.github.io/secureguard/reference/new_guardrail.md)
checks these fields and returns a guardrail that works with
[`run_guardrail()`](https://ian-flores.github.io/secureguard/reference/run_guardrail.md),
[`compose_guardrails()`](https://ian-flores.github.io/secureguard/reference/compose_guardrails.md),
and
[`secure_pipeline()`](https://ian-flores.github.io/secureguard/reference/secure_pipeline.md),
just like the built-in ones.

### A SQL injection detector

An LLM can write SQL that is valid and still dangerous, especially when
the prompt was written to trick it. This guardrail looks for the usual
patterns before a query gets near a database.

``` r

library(secureguard)

guard_sql_injection <- function() {
  sql_patterns <- c(
    "(?i)\\b(?:UNION\\s+SELECT|DROP\\s+TABLE|DELETE\\s+FROM)\\b",
    "(?i)\\b(?:INSERT\\s+INTO|UPDATE\\s+.+\\s+SET)\\b.*?;\\s*--",
    "(?i)'\\s*(?:OR|AND)\\s+['\"]?\\d['\"]?\\s*=\\s*['\"]?\\d",
    "(?i)(?:--|#|/\\*).*(?:SELECT|DROP|INSERT|UPDATE|DELETE)"
  )

  check_fn <- function(x) {
    hits <- vapply(sql_patterns, function(pat) {
      grepl(pat, x, perl = TRUE)
    }, logical(1))

    if (any(hits)) {
      guardrail_result(
        pass = FALSE,
        reason = "Potential SQL injection detected",
        details = list(
          matched_patterns = which(hits)
        )
      )
    } else {
      guardrail_result(pass = TRUE)
    }
  }

  new_guardrail(
    name = "sql_injection",
    type = "input",
    check_fn = check_fn,
    description = "Detects common SQL injection patterns"
  )
}
```

Now use it like any built-in guardrail:

``` r

g <- guard_sql_injection()
g
#> <secureguard> sql_injection (input)
#> Detects common SQL injection patterns

# Safe query
run_guardrail(g, "SELECT name FROM users WHERE id = 42")
#> <guardrail_result> PASS

# Injection attempt
run_guardrail(g, "SELECT * FROM users WHERE id = 1; DROP TABLE users; --")
#> <guardrail_result> FAIL
#> Reason: Potential SQL injection detected
```

### A code length limit

A guardrail of type `"code"` is built the same way. This one limits how
many lines the generated code can have:

``` r

guard_code_length <- function(max_lines = 100L) {
  check_fn <- function(code) {
    n_lines <- length(strsplit(code, "\n", fixed = TRUE)[[1L]])
    if (n_lines > max_lines) {
      guardrail_result(
        pass = FALSE,
        reason = sprintf("Code has %d lines (max %d)", n_lines, max_lines),
        details = list(n_lines = n_lines, max_lines = max_lines)
      )
    } else {
      guardrail_result(pass = TRUE, details = list(n_lines = n_lines))
    }
  }

  new_guardrail(
    name = "code_length",
    type = "code",
    check_fn = check_fn,
    description = sprintf("Limits code to %d lines", max_lines)
  )
}

g_len <- guard_code_length(max_lines = 5)
run_guardrail(g_len, "x <- 1\ny <- 2\nz <- x + y")
#> <guardrail_result> PASS

long_code <- paste(sprintf("x%d <- %d", 1:10, 1:10), collapse = "\n")
run_guardrail(g_len, long_code)
#> <guardrail_result> FAIL
#> Reason: Code has 10 lines (max 5)
```

### What a check_fn needs

A `check_fn` takes one argument, the text or object to check. It returns
a
[`guardrail_result()`](https://ian-flores.github.io/secureguard/reference/guardrail_result.md)
with `pass = TRUE` or `pass = FALSE`. It can also set `reason` to say
why it failed, `warnings` for things worth flagging that shouldn’t fail
the check, and `details`, a named list of anything else.

Use `@` to read fields from the result:

``` r

result <- run_guardrail(guard_code_analysis(), "system('ls')")
result@pass
#> [1] FALSE
result@reason
#> [1] "Blocked function(s) detected: system"
result@details
#> $blocked_calls
#> [1] "system"
```

## Combining guardrails

You’ll usually want more than one check at a time, for example dangerous
functions and complexity, or injection and topic. There are two ways to
combine them.

### compose_guardrails()

[`compose_guardrails()`](https://ian-flores.github.io/secureguard/reference/compose_guardrails.md)
merges guardrails of the same type into one. The result is a guardrail
too, so you can run it with
[`run_guardrail()`](https://ian-flores.github.io/secureguard/reference/run_guardrail.md),
put it inside another composition, or use it in a pipeline. Here, three
code checks become one “strict code” guardrail:

``` r

# Compose three code guardrails; all must pass (the default)
strict_code <- compose_guardrails(
  guard_code_analysis(),
  guard_code_complexity(max_ast_depth = 10, max_calls = 50),
  guard_code_dependencies(allowed_packages = c("dplyr", "ggplot2"))
)

strict_code
#> <secureguard> composed(code_analysis + code_complexity + code_dependencies)
#> (code)
#> Composite guardrail (mode=all): code_analysis + code_complexity +
#> code_dependencies

# Clean code passes all three
run_guardrail(strict_code, "dplyr::filter(mtcars, cyl == 4)")
#> <guardrail_result> PASS

# system() fails code analysis
run_guardrail(strict_code, "system('whoami')")
#> <guardrail_result> FAIL
#> Reason: Blocked function(s) detected: system

# processx fails dependency check
run_guardrail(strict_code, "processx::run('ls')")
#> <guardrail_result> FAIL
#> Reason: Blocked function(s) detected: processx::run; Disallowed package(s):
#> processx
```

### mode = “any”

The default, `mode = "all"`, is what you want for security checks. Every
check has to pass. Sometimes you want the reverse: input is fine if it
matches any one of several categories. With `mode = "any"`, the
composite passes when at least one of its guardrails passes:

``` r

# Accept prompts about either statistics OR machine learning
topic_guard <- compose_guardrails(
  guard_topic_scope(allowed_topics = c("statistics", "regression", "t-test")),
  guard_topic_scope(allowed_topics = c("machine learning", "neural network")),
  mode = "any"
)

run_guardrail(topic_guard, "How do I run a t-test in R?")
#> <guardrail_result> PASS
run_guardrail(topic_guard, "Explain neural network backpropagation")
#> <guardrail_result> PASS
run_guardrail(topic_guard, "What is the weather today?")
#> <guardrail_result> FAIL
#> Reason: Input does not match any allowed topic.; Input does not match any
#> allowed topic.
```

### check_all()

[`check_all()`](https://ian-flores.github.io/secureguard/reference/check_all.md)
runs each guardrail in a list and keeps every result, so you can see how
each one did:

``` r

guards <- list(
  guard_code_analysis(),
  guard_code_complexity(max_ast_depth = 10),
  guard_code_dataflow()
)

result <- check_all(guards, "x <- mean(1:10)")
result$pass
#> [1] TRUE
length(result$results)  # one per guardrail
#> [1] 3

# Inspect individual results
vapply(result$results, function(r) r@pass, logical(1))
#> [1] TRUE TRUE TRUE
```

When something fails, `result$reasons` has the reason from each failing
check:

``` r

result <- check_all(guards, "Sys.getenv('SECRET_KEY')")
result$pass
#> [1] FALSE
result$reasons
#> [1] "Data flow violation(s): Sys.getenv"
```

### Which one to use

[`compose_guardrails()`](https://ian-flores.github.io/secureguard/reference/compose_guardrails.md)
gives you a guardrail. You get one pass or fail, and you can reuse the
object anywhere a guardrail is accepted. It suits a fixed set of checks
you want to treat as one, like the “strict code” example.

[`check_all()`](https://ian-flores.github.io/secureguard/reference/check_all.md)
gives you a list of results. Use it when you need to say which check
failed and why, in logs or in an error message. “Code guardrail failed”
doesn’t help anyone. “code_analysis blocked
[`system()`](https://rdrr.io/r/base/system.html)” does.

Plenty of applications use both:
[`compose_guardrails()`](https://ian-flores.github.io/secureguard/reference/compose_guardrails.md)
to build groups, and
[`check_all()`](https://ian-flores.github.io/secureguard/reference/check_all.md)
on top to see which group failed.

## Pipelines

A real agent needs input, code, and output checks together.
[`secure_pipeline()`](https://ian-flores.github.io/secureguard/reference/secure_pipeline.md)
holds all three in one object, with a method for each stage. You write
the rules once and use them on every turn.

### Defining a pipeline

``` r

pipeline <- secure_pipeline(
  input_guardrails = list(
    guard_prompt_injection(sensitivity = "high"),
    guard_input_pii(),
    guard_topic_scope(allowed_topics = c("statistics", "data analysis", "R"))
  ),
  code_guardrails = list(
    guard_code_analysis(),
    guard_code_complexity(max_ast_depth = 15, max_calls = 100),
    guard_code_dependencies(allowed_packages = c("dplyr", "ggplot2", "tidyr")),
    guard_code_dataflow(block_network = TRUE, block_file_write = TRUE)
  ),
  output_guardrails = list(
    guard_output_pii(),
    guard_output_secrets(action = "redact"),
    guard_output_size(max_chars = 10000, max_lines = 200)
  )
)
```

### Running each stage

``` r

# Stage 1: validate user input
input_result <- pipeline$check_input("Calculate the mean and sd of mtcars$mpg")
input_result$pass
#> [1] TRUE
```

``` r

# Stage 2: validate LLM-generated code
code_result <- pipeline$check_code("
  library(dplyr)
  mtcars %>%
    summarise(mean_mpg = mean(mpg), sd_mpg = sd(mpg))
")
code_result$pass
#> [1] TRUE
```

``` r

# Stage 3: filter execution output
output_result <- pipeline$check_output("mean_mpg = 20.09, sd_mpg = 6.03")
output_result$pass
#> [1] TRUE
output_result$result  # possibly redacted text
#> [1] "mean_mpg = 20.09, sd_mpg = 6.03"
```

### A pipeline in an agent loop

Call the three `check_*` methods in order. Stop as soon as one fails. If
`check_input()` fails, don’t call the model. If `check_code()` fails,
don’t run the code. The whole turn looks like this:

``` r

process_turn <- function(pipeline, user_prompt, llm_fn, execute_fn) {
  # 1. Input guardrails

  input_check <- pipeline$check_input(user_prompt)
  if (!input_check$pass) {
    return(list(
      success = FALSE,
      stage = "input",
      reasons = input_check$reasons
    ))
  }

  # 2. LLM generates code
  code <- llm_fn(user_prompt)

  # 3. Code guardrails
  code_check <- pipeline$check_code(code)
  if (!code_check$pass) {
    return(list(
      success = FALSE,
      stage = "code",
      reasons = code_check$reasons
    ))
  }

  # 4. Execute in sandbox
  result <- execute_fn(code)

  # 5. Output guardrails
  output_check <- pipeline$check_output(result)
  if (!output_check$pass) {
    return(list(
      success = FALSE,
      stage = "output",
      reasons = output_check$reasons
    ))
  }

  list(success = TRUE, result = output_check$result)
}
```

## Mixing your guardrails with the built-in ones

Your guardrails and the built-in ones are the same kind of object, so
you can mix them in
[`compose_guardrails()`](https://ian-flores.github.io/secureguard/reference/compose_guardrails.md),
[`check_all()`](https://ian-flores.github.io/secureguard/reference/check_all.md),
and
[`secure_pipeline()`](https://ian-flores.github.io/secureguard/reference/secure_pipeline.md).
There’s nothing to register:

``` r

# The SQL injection guard from earlier alongside built-in input guards
input_guards <- compose_guardrails(
  guard_prompt_injection(),
  guard_input_pii(),
  guard_sql_injection()
)

run_guardrail(input_guards, "Please help me write a SELECT query")
#> <guardrail_result> PASS
run_guardrail(input_guards, "' OR 1=1 --")
#> <guardrail_result> FAIL
#> Reason: Potential SQL injection detected
```

The same goes for code guardrails:

``` r

# Custom length guard composed with built-in code guards
code_guards <- compose_guardrails(
  guard_code_analysis(),
  guard_code_complexity(max_ast_depth = 10),
  guard_code_length(max_lines = 50)
)

run_guardrail(code_guards, "x <- mean(1:10)")
#> <guardrail_result> PASS
```

## Using secureguard with securer

secureguard looks at code and output and decides whether they’re safe.
[securer](https://github.com/ian-flores/securer) runs the code in an
operating system sandbox that limits what it can do, whatever it tries.
secureguard stops patterns it knows are dangerous. securer contains the
ones it doesn’t know about.

securer is only suggested, not required. Everything above works without
it. With it, you get a hook that checks code before securer runs it, and
you can check the output afterwards.

### Checking code before it runs

[`as_pre_execute_hook()`](https://ian-flores.github.io/secureguard/reference/as_pre_execute_hook.md)
turns code guardrails into a function that securer calls before running
each piece of code. It returns `TRUE` to let the code run and `FALSE` to
block it.

``` r

library(securer)
library(secureguard)

hook <- as_pre_execute_hook(
  guard_code_analysis(),
  guard_code_complexity(max_ast_depth = 15),
  guard_code_dataflow()
)

sess <- SecureSession$new(pre_execute_hook = hook)
sess$execute("mean(1:10)")        # allowed
sess$execute("system('whoami')")  # blocked by code_analysis
sess$execute("Sys.getenv('KEY')") # blocked by dataflow
sess$close()
```

### Checking the output

[`guard_output()`](https://ian-flores.github.io/secureguard/reference/guard_output.md)
runs output guardrails on what the code returned. Guardrails with
`action = "redact"` replace the sensitive parts instead of blocking the
whole result:

``` r

result <- sess$execute("paste('My API key is', 'AKIAIOSFODNN7EXAMPLE')")

checked <- guard_output(
  result,
  guard_output_pii(),
  guard_output_secrets(action = "redact")
)

if (checked$pass) {
  # Return the (possibly redacted) result to the user
  checked$result
} else {
  paste("Blocked:", paste(checked$reasons, collapse = "; "))
}
```

### A hook from a pipeline

A pipeline can turn its code guardrails into a hook:

``` r

pipeline <- secure_pipeline(
  input_guardrails = list(guard_prompt_injection()),
  code_guardrails = list(
    guard_code_analysis(),
    guard_code_dataflow()
  ),
  output_guardrails = list(
    guard_output_secrets(action = "redact")
  )
)

sess <- SecureSession$new(
  pre_execute_hook = pipeline$as_pre_execute_hook()
)

# The session now has code guardrails enforced automatically.
# Input and output guardrails are checked manually:
input_check <- pipeline$check_input(user_prompt)
# ... LLM generates code, session executes it ...
output_check <- pipeline$check_output(execution_result)

sess$close()
```

## Stricter and looser settings

So far every request gets the same checks. Often you want to be stricter
with some users than others, depending on who they are and where the
request came from.

### Injection sensitivity

A public chatbot will meet people trying to break it, so it needs high
injection sensitivity and a narrow list of topics. An internal tool for
your own analysts can use low sensitivity, so ordinary prompts don’t get
flagged by mistake:

``` r

# Public-facing: high sensitivity, strict topic scoping
public_guards <- compose_guardrails(
  guard_prompt_injection(sensitivity = "high"),
  guard_input_pii(),
  guard_topic_scope(allowed_topics = c("data analysis", "statistics"))
)

# Internal tool: lower sensitivity, broader topics
internal_guards <- compose_guardrails(
  guard_prompt_injection(sensitivity = "low"),
  guard_input_pii()
)

run_guardrail(
  public_guards,
  "Continue from where we left off with the regression"
)
#> <guardrail_result> FAIL
#> Reason: Prompt injection detected: continuation_attack; Input does not match
#> any allowed topic.

run_guardrail(
  internal_guards,
  "Continue from where we left off with the regression"
)
#> <guardrail_result> PASS
```

### Code restrictions

The same idea works for code. A trusted colleague running reviewed
scripts needs fewer limits than an outside user whose prompts can
produce any code at all:

``` r

# Trusted context: only block the most dangerous operations
trusted_code <- compose_guardrails(
  guard_code_analysis(blocked_functions = c("system", "system2", "shell")),
  guard_code_dataflow(
    block_env_access = TRUE,
    block_network = FALSE,
    block_file_write = FALSE,
    block_file_read = FALSE
  )
)

# Untrusted context: strict lockdown
untrusted_code <- compose_guardrails(
  guard_code_analysis(),
  guard_code_complexity(max_ast_depth = 10, max_calls = 30),
  guard_code_dependencies(allowed_packages = c("dplyr", "ggplot2")),
  guard_code_dataflow(
    block_env_access = TRUE,
    block_network = TRUE,
    block_file_write = TRUE,
    block_file_read = TRUE
  )
)

# Reading a file passes in the trusted setup but fails in the untrusted one
code <- "readLines('data.csv')"
run_guardrail(trusted_code, code)
#> <guardrail_result> PASS
run_guardrail(untrusted_code, code)
#> <guardrail_result> FAIL
#> Reason: Data flow violation(s): readLines
```

### Redact or block

Social security numbers and patient records should block the whole
response. Showing part of a record is still a privacy breach. API keys
and tokens can usually be redacted, which keeps the useful part of the
answer and hides the value. Output guardrails take an `action` of
`"block"`, `"redact"`, or `"warn"`:

``` r

# PII blocks the output entirely
# Secrets get redacted so the response is still useful
pipeline <- secure_pipeline(
  output_guardrails = list(
    guard_output_pii(),                         # blocks on PII
    guard_output_secrets(action = "redact"),     # redacts secrets
    guard_output_size(max_chars = 5000)          # blocks oversized output
  )
)

# Secrets are redacted, not blocked
result <- pipeline$check_output("API key: AKIAIOSFODNN7EXAMPLE, data looks good")
result$pass
#> [1] TRUE
result$result
#> [1] "API key: [REDACTED_AWS_KEY], data looks good"

# PII causes a block
result <- pipeline$check_output("Patient SSN: 123-45-6789")
result$pass
#> [1] FALSE
result$reasons
#> [1] "PII detected in output: ssn"
```

## Summary

| To do this | Use |
|----|----|
| Write your own check | [`new_guardrail()`](https://ian-flores.github.io/secureguard/reference/new_guardrail.md) |
| Merge checks of one type into one guardrail | [`compose_guardrails()`](https://ian-flores.github.io/secureguard/reference/compose_guardrails.md) |
| Run a list of checks and see each result | [`check_all()`](https://ian-flores.github.io/secureguard/reference/check_all.md) |
| Check input, code, and output in one object | [`secure_pipeline()`](https://ian-flores.github.io/secureguard/reference/secure_pipeline.md) |
| Check code before securer runs it | [`as_pre_execute_hook()`](https://ian-flores.github.io/secureguard/reference/as_pre_execute_hook.md) |
| Check or redact a result after it runs | [`guard_output()`](https://ian-flores.github.io/secureguard/reference/guard_output.md) |

Keep each guardrail small, aimed at one problem. Combine them with
[`compose_guardrails()`](https://ian-flores.github.io/secureguard/reference/compose_guardrails.md)
or
[`check_all()`](https://ian-flores.github.io/secureguard/reference/check_all.md),
and put them in a pipeline that checks every stage of the turn. If the
built-in checks don’t fit your case, write one with
[`new_guardrail()`](https://ian-flores.github.io/secureguard/reference/new_guardrail.md).
It will work anywhere the built-in ones do.
