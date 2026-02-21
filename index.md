# secureguard

> \[!CAUTION\] **Alpha software.** This package is part of a broader
> effort by [Ian Flores Siaca](https://github.com/ian-flores) to develop
> proper AI infrastructure for the R ecosystem. It is under active
> development and should **not** be used in production until an official
> release is published. APIs may change without notice.

Composable guardrails for LLM agent workflows in R. Three defense layers
– input validation, code analysis, and output filtering – all running
locally with zero external API calls.

## Installation

``` r
# install.packages("pak")
pak::pak("ian-flores/secureguard")
```

## Quick Example

``` r
library(secureguard)

# Block dangerous code before it runs
hook <- as_pre_execute_hook(
  guard_code_analysis(),
  guard_code_complexity(max_ast_depth = 15)
)
hook("mean(1:10)")    # TRUE -- safe
hook("system('ls')")  # FALSE -- blocked

# Check output for sensitive data
out <- guard_output(
  "User SSN: 123-45-6789",
  guard_output_pii(),
  guard_output_secrets()
)
out$pass     # FALSE
out$reasons  # "PII detected in output: ssn"
```

## Features

### Input Guardrails

| Function                                                                                                   | Description                         |
|------------------------------------------------------------------------------------------------------------|-------------------------------------|
| [`guard_prompt_injection()`](https://ian-flores.github.io/secureguard/reference/guard_prompt_injection.md) | Detect prompt injection attempts    |
| [`guard_topic_scope()`](https://ian-flores.github.io/secureguard/reference/guard_topic_scope.md)           | Enforce allowed/blocked topic lists |
| [`guard_input_pii()`](https://ian-flores.github.io/secureguard/reference/guard_input_pii.md)               | Filter PII from user prompts        |

### Code Guardrails

| Function                                                                                                     | Description                                 |
|--------------------------------------------------------------------------------------------------------------|---------------------------------------------|
| [`guard_code_analysis()`](https://ian-flores.github.io/secureguard/reference/guard_code_analysis.md)         | AST-based blocked function detection        |
| [`guard_code_complexity()`](https://ian-flores.github.io/secureguard/reference/guard_code_complexity.md)     | Depth, call count, expression limits        |
| [`guard_code_dependencies()`](https://ian-flores.github.io/secureguard/reference/guard_code_dependencies.md) | Namespace allow/block lists                 |
| [`guard_code_dataflow()`](https://ian-flores.github.io/secureguard/reference/guard_code_dataflow.md)         | Assignment and global variable restrictions |

### Output Guardrails

| Function                                                                                               | Description                                     |
|--------------------------------------------------------------------------------------------------------|-------------------------------------------------|
| [`guard_output_pii()`](https://ian-flores.github.io/secureguard/reference/guard_output_pii.md)         | PII detection with block/redact/warn actions    |
| [`guard_output_secrets()`](https://ian-flores.github.io/secureguard/reference/guard_output_secrets.md) | Secret detection with block/redact/warn actions |
| [`guard_output_size()`](https://ian-flores.github.io/secureguard/reference/guard_output_size.md)       | Character, line, and element limits             |

### Integration

| Function                                                                                             | Description                                  |
|------------------------------------------------------------------------------------------------------|----------------------------------------------|
| [`as_pre_execute_hook()`](https://ian-flores.github.io/secureguard/reference/as_pre_execute_hook.md) | Convert code guardrails to a securer hook    |
| [`guard_output()`](https://ian-flores.github.io/secureguard/reference/guard_output.md)               | Run output guardrails with redaction support |
| [`secure_pipeline()`](https://ian-flores.github.io/secureguard/reference/secure_pipeline.md)         | Bundle input + code + output guardrails      |

## securer Integration

secureguard integrates with
[securer](https://github.com/ian-flores/securer) for sandboxed R
execution:

``` r
library(securer)
library(secureguard)

pipeline <- secure_pipeline(
  input_guardrails = list(guard_prompt_injection()),
  code_guardrails = list(guard_code_analysis()),
  output_guardrails = list(guard_output_pii(), guard_output_secrets(action = "redact"))
)

sess <- SecureSession$new(
  pre_execute_hook = pipeline$as_pre_execute_hook()
)

# Safe code executes normally
result <- sess$execute("mean(1:10)")

# Dangerous code is blocked before reaching the sandbox
sess$execute("system('ls')")  # Error: blocked by guardrail

# Check output
out <- pipeline$check_output(result)
sess$close()
```

## License

MIT
