# secureguard

<!-- badges: start -->
[![R-CMD-check](https://github.com/ian-flores/secureguard/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/ian-flores/secureguard/actions/workflows/R-CMD-check.yaml)
[![Codecov test coverage](https://codecov.io/gh/ian-flores/secureguard/graph/badge.svg)](https://app.codecov.io/gh/ian-flores/secureguard)
[![Lifecycle: experimental](https://img.shields.io/badge/lifecycle-experimental-orange.svg)](https://lifecycle.r-lib.org/articles/stages.html#experimental)
[![pkgdown](https://github.com/ian-flores/secureguard/actions/workflows/pkgdown.yaml/badge.svg)](https://ian-flores.github.io/secureguard/)
<!-- badges: end -->

> [!CAUTION]
> **Alpha software.** This package is part of a broader effort by [Ian Flores Siaca](https://github.com/ian-flores) to develop proper AI infrastructure for the R ecosystem. It is under active development and should **not** be used in production until an official release is published. APIs may change without notice.

Composable guardrails for LLM agent workflows in R. Three defense layers -- input validation, code analysis, and output filtering -- all running locally with zero external API calls.

## Why secureguard?

Most guardrail solutions require external API calls or cloud services. secureguard runs entirely locally -- regex-based prompt injection detection, R AST analysis for dangerous code patterns, and PII/secret scanning -- all without sending your data anywhere.

## Part of the secure-r-dev Ecosystem

secureguard is part of a 7-package ecosystem for building governed AI agents in R:

```
                    ┌─────────────┐
                    │   securer    │
                    └──────┬──────┘
          ┌────────────────┼──────────────────┐
          │                │                   │
   ┌──────▼──────┐  ┌─────▼───────────┐  ┌───▼──────────────┐
   │ securetools  │  │>>> secureguard<<<│  │  securecontext   │
   └──────┬───────┘  └─────┬───────────┘  └───┬──────────────┘
          └────────────────┼──────────────────┘
                    ┌──────▼───────┐
                    │   orchestr   │
                    └──────┬───────┘
          ┌────────────────┼─────────────────┐
          │                                  │
   ┌──────▼──────┐                    ┌──────▼──────┐
   │ securetrace  │                   │ securebench  │
   └─────────────┘                    └─────────────┘
```

secureguard provides the guardrail layer -- input validation, code analysis, and output filtering that can run standalone or integrate with securer's pre-execute hooks. securebench at the bottom of the stack benchmarks guardrail accuracy with precision/recall/F1 metrics.

| Package | Role |
|---------|------|
| [securer](https://github.com/ian-flores/securer) | Sandboxed R execution with tool-call IPC |
| [securetools](https://github.com/ian-flores/securetools) | Pre-built security-hardened tool definitions |
| [secureguard](https://github.com/ian-flores/secureguard) | Input/code/output guardrails (injection, PII, secrets) |
| [orchestr](https://github.com/ian-flores/orchestr) | Graph-based agent orchestration |
| [securecontext](https://github.com/ian-flores/securecontext) | Document chunking, embeddings, RAG retrieval |
| [securetrace](https://github.com/ian-flores/securetrace) | Structured tracing, token/cost accounting, JSONL export |
| [securebench](https://github.com/ian-flores/securebench) | Guardrail benchmarking with precision/recall/F1 metrics |

## Installation

```r
# install.packages("pak")
pak::pak("ian-flores/secureguard")
```

## Quick Example

```r
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

| Function | Description |
|---|---|
| `guard_prompt_injection()` | Detect prompt injection attempts |
| `guard_topic_scope()` | Enforce allowed/blocked topic lists |
| `guard_input_pii()` | Filter PII from user prompts |

### Code Guardrails

| Function | Description |
|---|---|
| `guard_code_analysis()` | AST-based blocked function detection |
| `guard_code_complexity()` | Depth, call count, expression limits |
| `guard_code_dependencies()` | Namespace allow/block lists |
| `guard_code_dataflow()` | Assignment and global variable restrictions |

### Output Guardrails

| Function | Description |
|---|---|
| `guard_output_pii()` | PII detection with block/redact/warn actions |
| `guard_output_secrets()` | Secret detection with block/redact/warn actions |
| `guard_output_size()` | Character, line, and element limits |

### Integration

| Function | Description |
|---|---|
| `as_pre_execute_hook()` | Convert code guardrails to a securer hook |
| `guard_output()` | Run output guardrails with redaction support |
| `secure_pipeline()` | Bundle input + code + output guardrails |

## securer Integration

secureguard integrates with [securer](https://github.com/ian-flores/securer) for sandboxed R execution:

```r
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

## Documentation

- [Getting Started with secureguard](https://ian-flores.github.io/secureguard/articles/secureguard.html)
- [Advanced Guardrail Patterns](https://ian-flores.github.io/secureguard/articles/advanced-patterns.html)
- [Full reference documentation](https://ian-flores.github.io/secureguard/)

## Contributing

Contributions are welcome! Please file issues on GitHub and submit pull requests.

## License

MIT
