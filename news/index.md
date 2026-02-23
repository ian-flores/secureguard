# Changelog

## secureguard 0.1.0

- Initial CRAN release.

### Input guardrails

- [`guard_prompt_injection()`](https://ian-flores.github.io/secureguard/reference/guard_prompt_injection.md)
  detects common prompt injection patterns using regex-based analysis.
- [`guard_topic_scope()`](https://ian-flores.github.io/secureguard/reference/guard_topic_scope.md)
  enforces keyword-based topic allow/block lists.
- [`guard_input_pii()`](https://ian-flores.github.io/secureguard/reference/guard_input_pii.md)
  detects personally identifiable information in prompts.

### Code guardrails

- [`guard_code_analysis()`](https://ian-flores.github.io/secureguard/reference/guard_code_analysis.md)
  blocks dangerous function calls via AST inspection.
- [`guard_code_complexity()`](https://ian-flores.github.io/secureguard/reference/guard_code_complexity.md)
  enforces depth, call count, and expression limits.
- [`guard_code_dependencies()`](https://ian-flores.github.io/secureguard/reference/guard_code_dependencies.md)
  restricts allowed/blocked package namespaces.
- [`guard_code_dataflow()`](https://ian-flores.github.io/secureguard/reference/guard_code_dataflow.md)
  detects environment access, network, file read/write patterns.

### Output guardrails

- [`guard_output_pii()`](https://ian-flores.github.io/secureguard/reference/guard_output_pii.md)
  detects and optionally redacts PII in output.
- [`guard_output_secrets()`](https://ian-flores.github.io/secureguard/reference/guard_output_secrets.md)
  detects and optionally redacts secrets and credentials.
- [`guard_output_size()`](https://ian-flores.github.io/secureguard/reference/guard_output_size.md)
  enforces character, line, and element size limits.

### Core

- [`new_guardrail()`](https://ian-flores.github.io/secureguard/reference/new_guardrail.md)
  and `secureguard_class` for creating guardrail objects.
- [`guardrail_result()`](https://ian-flores.github.io/secureguard/reference/guardrail_result.md)
  for structured check results.
- [`compose_guardrails()`](https://ian-flores.github.io/secureguard/reference/compose_guardrails.md)
  combines multiple same-type guardrails.
- [`run_guardrail()`](https://ian-flores.github.io/secureguard/reference/run_guardrail.md)
  and
  [`check_all()`](https://ian-flores.github.io/secureguard/reference/check_all.md)
  for executing guardrails.
- [`as_pre_execute_hook()`](https://ian-flores.github.io/secureguard/reference/as_pre_execute_hook.md)
  converts code guardrails to ‘securer’ hooks.
- [`guard_output()`](https://ian-flores.github.io/secureguard/reference/guard_output.md)
  runs output guardrails with optional redaction.
- [`secure_pipeline()`](https://ian-flores.github.io/secureguard/reference/secure_pipeline.md)
  bundles input, code, and output guardrails.
