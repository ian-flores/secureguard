# secureguard – Development Guide

## What This Is

An R package providing composable guardrails for LLM agent workflows.
Three defense layers – input validation, code analysis, and output
filtering – all running locally with zero external API calls. Integrates
with securer for sandboxed execution.

## Architecture

    secureguard
    ├── Core (guardrail.R)
    │   ├── new_guardrail() -- S3 constructor for "secureguard" class
    │   ├── guardrail_result() -- structured check results
    │   ├── compose_guardrails() -- combine same-type guardrails
    │   ├── run_guardrail() -- execute a single guardrail
    │   └── check_all() -- run a list of guardrails, collect results
    ├── Input Guardrails
    │   ├── guard_prompt_injection() -- regex-based injection detection
    │   ├── guard_topic_scope() -- keyword topic allow/block
    │   └── guard_input_pii() -- PII detection in prompts
    ├── Code Guardrails
    │   ├── guard_code_analysis() -- AST-based blocked function detection
    │   ├── guard_code_complexity() -- depth/call/expression limits
    │   ├── guard_code_dependencies() -- namespace allow/block lists
    │   └── guard_code_dataflow() -- assignment/global variable restrictions
    ├── Output Guardrails
    │   ├── guard_output_pii() -- PII detection/redaction in results
    │   ├── guard_output_secrets() -- secret/credential detection/redaction
    │   └── guard_output_size() -- character/line/element limits
    ├── AST Utilities (ast-walk.R)
    │   ├── parse_code(), walk_ast(), walk_code()
    │   ├── call_fn_name(), ast_depth(), ast_stats()
    ├── Pattern Libraries
    │   ├── pii_patterns(), detect_pii()
    │   ├── secret_patterns(), detect_secrets()
    │   └── injection_patterns(), detect_injection()
    └── Integration (integration.R)
        ├── as_pre_execute_hook() -- code guardrails -> securer hook
        ├── guard_output() -- run output guardrails with redaction
        └── secure_pipeline() -- bundle all three layers

## Key Design Decisions

- All guardrails are S3 objects of class “secureguard” with a `type`
  field (“input”, “code”, “output”)
- `guardrail_result` is the universal return type: `$pass`, `$reason`,
  `$warnings`, `$details`
- Output guardrails with `action = "redact"` put cleaned text in
  `$details$redacted_text`
- [`output_to_text()`](https://ian-flores.github.io/secureguard/reference/output_to_text.md)
  converts arbitrary R objects to scannable strings
- AST walking uses a visitor pattern: `on_call(expr, fn_name, depth)`
- [`call_fn_name()`](https://ian-flores.github.io/secureguard/reference/call_fn_name.md)
  resolves `do.call("fn", ...)` and `pkg::fn()` to string names
- securer is a soft dependency (Suggests only)

## Development Commands

``` bash
# Run tests
Rscript -e "devtools::test('.')"

# Run R CMD check
Rscript -e "devtools::check('.')"

# Regenerate docs
Rscript -e "devtools::document('.')"

# Load for interactive testing
Rscript -e "devtools::load_all('.')"
```

## Test Structure

- `test-guardrail.R` – Core: new_guardrail, guardrail_result, compose,
  run, check_all
- `test-input-prompt-injection.R` – Injection detection
- `test-input-topic-scope.R` – Topic scoping
- `test-input-pii.R` – Input PII filtering
- `test-code-ast-analysis.R` – AST-based function blocking
- `test-code-complexity.R` – Complexity limits
- `test-code-dependency.R` – Dependency restrictions
- `test-code-dataflow.R` – Data flow analysis
- `test-output-pii.R` – Output PII detection/redaction
- `test-output-secrets.R` – Secret detection/redaction
- `test-output-size.R` – Size limits
- `test-ast-walk.R` – AST parser and walker
- `test-patterns-pii.R` – PII pattern library
- `test-patterns-secrets.R` – Secret pattern library
- `test-patterns-injection.R` – Injection pattern library
- `test-integration.R` – Integration: hooks, guard_output,
  secure_pipeline

## Dependencies

- **cli** – user-facing messages and errors
- **rlang** – type checking utilities, %\|\|% operator
- **securer** (Suggests) – sandboxed R execution sessions
- **testthat** (Suggests) – testing
