# secureguard

secureguard checks what goes into an LLM agent, the R code it writes,
and what comes back out. It catches things like prompt injection, calls
to [`system()`](https://rdrr.io/r/base/system.html), and API keys or
social security numbers in the output.

Everything runs on your machine. The checks are regular expressions and
R’s own parser, so no text is sent to another service to be judged.

The package is experimental, and function names may still change.

## Installation

``` r

# install.packages("pak")
pak::pak("ian-flores/secureguard")
```

## A quick look

Stop dangerous code before it runs:

``` r

library(secureguard)

hook <- as_pre_execute_hook(
  guard_code_analysis(),
  guard_code_complexity(max_ast_depth = 15)
)

hook("mean(1:10)")    # TRUE: fine to run
hook("system('ls')")  # FALSE, with a warning naming `system`
```

Catch sensitive data in a result:

``` r

out <- guard_output(
  "User SSN: 123-45-6789",
  guard_output_pii(),
  guard_output_secrets()
)
out$pass     # FALSE
out$reasons  # "PII detected in output: ssn"
```

Or keep the result and hide the sensitive parts:

``` r

out <- guard_output(
  "Key: AKIAIOSFODNN7EXAMPLE, mail me at jo@example.com",
  guard_output_pii(action = "redact"),
  guard_output_secrets(action = "redact")
)
out$result  # "Key: [REDACTED_AWS_KEY], mail me at [REDACTED_EMAIL]"
```

## What it checks

There are three kinds of guardrail, one for each point where things can
go wrong.

**Input**, before the prompt reaches the model:

| Function | What it does |
|----|----|
| [`guard_prompt_injection()`](https://ian-flores.github.io/secureguard/reference/guard_prompt_injection.md) | Flags text that tries to override the agent’s instructions |
| [`guard_topic_scope()`](https://ian-flores.github.io/secureguard/reference/guard_topic_scope.md) | Keeps the conversation to topics you allow |
| [`guard_input_pii()`](https://ian-flores.github.io/secureguard/reference/guard_input_pii.md) | Flags personal data in the prompt |

**Code**, after the model writes R code and before it runs:

| Function | What it does |
|----|----|
| [`guard_code_analysis()`](https://ian-flores.github.io/secureguard/reference/guard_code_analysis.md) | Blocks calls like [`system()`](https://rdrr.io/r/base/system.html) or [`eval()`](https://rdrr.io/r/base/eval.html), even when they’re hidden behind [`do.call()`](https://rdrr.io/r/base/do.call.html) |
| [`guard_code_complexity()`](https://ian-flores.github.io/secureguard/reference/guard_code_complexity.md) | Limits how deep, long, or busy the code can be |
| [`guard_code_dependencies()`](https://ian-flores.github.io/secureguard/reference/guard_code_dependencies.md) | Allows or blocks specific packages |
| [`guard_code_dataflow()`](https://ian-flores.github.io/secureguard/reference/guard_code_dataflow.md) | Blocks reading environment variables, files, or the network |

**Output**, before the result goes back to the model or the user:

| Function | What it does |
|----|----|
| [`guard_output_pii()`](https://ian-flores.github.io/secureguard/reference/guard_output_pii.md) | Finds personal data, then blocks, redacts, or warns |
| [`guard_output_secrets()`](https://ian-flores.github.io/secureguard/reference/guard_output_secrets.md) | Finds API keys and passwords, then blocks, redacts, or warns |
| [`guard_output_entropy()`](https://ian-flores.github.io/secureguard/reference/guard_output_entropy.md) | Flags long random-looking strings, which are often keys |
| [`guard_output_size()`](https://ian-flores.github.io/secureguard/reference/guard_output_size.md) | Caps the number of characters, lines, or elements |

To run several guardrails together, use
[`guard_output()`](https://ian-flores.github.io/secureguard/reference/guard_output.md)
for outputs,
[`as_pre_execute_hook()`](https://ian-flores.github.io/secureguard/reference/as_pre_execute_hook.md)
to turn code checks into a hook for
[securer](https://github.com/ian-flores/securer), or
[`secure_pipeline()`](https://ian-flores.github.io/secureguard/reference/secure_pipeline.md)
to bundle all three kinds.

## With securer

secureguard works on its own, but it pairs well with securer, which runs
the agent’s code in a sandbox. The guardrails reject bad code before it
ever reaches the sandbox:

``` r

library(securer)
library(secureguard)

pipeline <- secure_pipeline(
  input_guardrails  = list(guard_prompt_injection()),
  code_guardrails   = list(guard_code_analysis()),
  output_guardrails = list(guard_output_pii(), guard_output_secrets(action = "redact"))
)

sess <- SecureSession$new(pre_execute_hook = pipeline$as_pre_execute_hook())

result <- sess$execute("mean(1:10)")  # runs
sess$execute("system('ls')")          # error: blocked by the guardrail

pipeline$check_output(result)
sess$close()
```

## Related packages

secureguard is part of a small set of packages for running LLM agents in
R more safely:

- [securer](https://github.com/ian-flores/securer) runs agent code in a
  sandbox.
- [securetools](https://github.com/ian-flores/securetools) has
  ready-made tools (file access, SQL, web requests) with limits built
  in.
- [securebench](https://github.com/ian-flores/securebench) measures how
  well your guardrails work. It complements
  [vitals](https://vitals.tidyverse.org/).

They build on Posit’s tools rather than replacing them. For tracing, use
[ellmer](https://ellmer.tidyverse.org/)’s OpenTelemetry support through
the [otel](https://otel.r-lib.org/) package. For retrieval (RAG), use
[ragnar](https://github.com/tidyverse/ragnar).

## Learn more

- [Getting
  started](https://ian-flores.github.io/secureguard/articles/secureguard.html)
- [Advanced
  patterns](https://ian-flores.github.io/secureguard/articles/advanced-patterns.html)
- [Function
  reference](https://ian-flores.github.io/secureguard/reference/)

Found a bug or have an idea? [Open an
issue](https://github.com/ian-flores/secureguard/issues).

## License

MIT
