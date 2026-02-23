# secureguard 0.1.0

* Initial CRAN release.

## Input guardrails

* `guard_prompt_injection()` detects common prompt injection patterns using
  regex-based analysis.
* `guard_topic_scope()` enforces keyword-based topic allow/block lists.
* `guard_input_pii()` detects personally identifiable information in prompts.

## Code guardrails

* `guard_code_analysis()` blocks dangerous function calls via AST inspection.
* `guard_code_complexity()` enforces depth, call count, and expression limits.
* `guard_code_dependencies()` restricts allowed/blocked package namespaces.
* `guard_code_dataflow()` detects environment access, network, file read/write
  patterns.

## Output guardrails

* `guard_output_pii()` detects and optionally redacts PII in output.
* `guard_output_secrets()` detects and optionally redacts secrets and
  credentials.
* `guard_output_size()` enforces character, line, and element size limits.

## Core

* `new_guardrail()` and `secureguard_class` for creating guardrail objects.
* `guardrail_result()` for structured check results.
* `compose_guardrails()` combines multiple same-type guardrails.
* `run_guardrail()` and `check_all()` for executing guardrails.
* `as_pre_execute_hook()` converts code guardrails to 'securer' hooks.
* `guard_output()` runs output guardrails with optional redaction.
* `secure_pipeline()` bundles input, code, and output guardrails.
