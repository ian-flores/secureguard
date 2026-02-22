# Package index

## Core

Guardrail creation, composition, and execution

- [`new_guardrail()`](https://ian-flores.github.io/secureguard/reference/new_guardrail.md)
  : Create a new guardrail
- [`secureguard_class()`](https://ian-flores.github.io/secureguard/reference/secureguard_class.md)
  : S7 class: secureguard
- [`guardrail_result()`](https://ian-flores.github.io/secureguard/reference/guardrail_result.md)
  : Create a guardrail result
- [`guardrail_result_class()`](https://ian-flores.github.io/secureguard/reference/guardrail_result_class.md)
  : S7 class: guardrail_result
- [`compose_guardrails()`](https://ian-flores.github.io/secureguard/reference/compose_guardrails.md)
  : Compose guardrails
- [`run_guardrail()`](https://ian-flores.github.io/secureguard/reference/run_guardrail.md)
  : Run a single guardrail
- [`check_all()`](https://ian-flores.github.io/secureguard/reference/check_all.md)
  : Run all guardrails and collect results

## Input Guardrails

Validate LLM input before processing

- [`guard_prompt_injection()`](https://ian-flores.github.io/secureguard/reference/guard_prompt_injection.md)
  : Prompt injection guardrail
- [`guard_topic_scope()`](https://ian-flores.github.io/secureguard/reference/guard_topic_scope.md)
  : Topic scope guardrail
- [`guard_input_pii()`](https://ian-flores.github.io/secureguard/reference/guard_input_pii.md)
  : Input PII guardrail

## Code Guardrails

Analyse LLM-generated R code before execution

- [`guard_code_analysis()`](https://ian-flores.github.io/secureguard/reference/guard_code_analysis.md)
  : Code AST analysis guardrail
- [`default_blocked_functions()`](https://ian-flores.github.io/secureguard/reference/default_blocked_functions.md)
  : Default blocked functions
- [`guard_code_complexity()`](https://ian-flores.github.io/secureguard/reference/guard_code_complexity.md)
  : Code complexity guardrail
- [`guard_code_dependencies()`](https://ian-flores.github.io/secureguard/reference/guard_code_dependencies.md)
  : Code dependency guardrail
- [`guard_code_dataflow()`](https://ian-flores.github.io/secureguard/reference/guard_code_dataflow.md)
  : Code data flow guardrail

## Output Guardrails

Filter and validate execution output

- [`guard_output_pii()`](https://ian-flores.github.io/secureguard/reference/guard_output_pii.md)
  : PII output guardrail
- [`guard_output_size()`](https://ian-flores.github.io/secureguard/reference/guard_output_size.md)
  : Output size guardrail
- [`guard_output_secrets()`](https://ian-flores.github.io/secureguard/reference/guard_output_secrets.md)
  : Secret output guardrail
- [`output_to_text()`](https://ian-flores.github.io/secureguard/reference/output_to_text.md)
  : Convert an R object to scannable text

## AST Utilities

Parse and walk R code abstract syntax trees

- [`parse_code()`](https://ian-flores.github.io/secureguard/reference/parse_code.md)
  : Parse code string into expressions
- [`walk_ast()`](https://ian-flores.github.io/secureguard/reference/walk_ast.md)
  : Walk an AST node recursively
- [`walk_code()`](https://ian-flores.github.io/secureguard/reference/walk_code.md)
  : Walk all expressions in a code string
- [`call_fn_name()`](https://ian-flores.github.io/secureguard/reference/call_fn_name.md)
  : Extract function name from a call expression
- [`ast_depth()`](https://ian-flores.github.io/secureguard/reference/ast_depth.md)
  : Compute maximum AST nesting depth
- [`ast_stats()`](https://ian-flores.github.io/secureguard/reference/ast_stats.md)
  : Compute summary statistics for R code AST

## Pattern Libraries

Regex pattern collections for detection

- [`pii_patterns()`](https://ian-flores.github.io/secureguard/reference/pii_patterns.md)
  : PII detection patterns
- [`detect_pii()`](https://ian-flores.github.io/secureguard/reference/detect_pii.md)
  : Detect PII in text
- [`secret_patterns()`](https://ian-flores.github.io/secureguard/reference/secret_patterns.md)
  : Secret detection patterns
- [`detect_secrets()`](https://ian-flores.github.io/secureguard/reference/detect_secrets.md)
  : Detect secrets in text
- [`injection_patterns()`](https://ian-flores.github.io/secureguard/reference/injection_patterns.md)
  : Prompt injection detection patterns
- [`detect_injection()`](https://ian-flores.github.io/secureguard/reference/detect_injection.md)
  : Detect prompt injection attempts

## Integration

Compose guardrails into pipelines and securer hooks

- [`as_pre_execute_hook()`](https://ian-flores.github.io/secureguard/reference/as_pre_execute_hook.md)
  : Convert code guardrails to a securer pre-execute hook
- [`guard_output()`](https://ian-flores.github.io/secureguard/reference/guard_output.md)
  : Run output guardrails on a result
- [`secure_pipeline()`](https://ian-flores.github.io/secureguard/reference/secure_pipeline.md)
  : Create a complete guardrail pipeline
