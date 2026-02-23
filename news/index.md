# Changelog

## secureguard 0.2.0

### PII detection

- Expanded from 5 to 14 PII types: added `ip_address_v6`, `phone_intl`
  (E.164), `iban`, `dob`, `mac_address`, `us_passport`,
  `drivers_license`, `itin`, and `vin`.
- Upgraded `ssn` pattern to exclude invalid area numbers (000, 666,
  900-999), group (00), and serial (0000); now supports no-dash format.
- Upgraded `credit_card` pattern with card-type-aware prefixes
  (Visa/MC/Amex/Discover) and Luhn checksum validation to reduce false
  positives.
- Renamed `ip_address` to `ip_address_v4` for clarity. **Breaking
  change.**
- Keyword-contextual patterns (`dob`, `us_passport`, `drivers_license`,
  `vin`) require keyword proximity to reduce false positives.

### Secret detection

- Expanded from 6 to 51 secret types across 10 categories: Cloud,
  SaaS/Messaging, Payment, Package Registries, Version Control, AI/ML,
  E-commerce, Infrastructure, Database, and Social.
- New patterns include AWS secret keys, Stripe/Square/PayPal tokens,
  Slack/Discord tokens, OpenAI/Anthropic API keys, Shopify tokens, JWTs,
  database connection strings, and more.

### Entropy detection

- New
  [`shannon_entropy()`](https://ian-flores.github.io/secureguard/reference/shannon_entropy.md)
  calculates Shannon entropy (bits) of a string.
- New
  [`is_high_entropy()`](https://ian-flores.github.io/secureguard/reference/is_high_entropy.md)
  detects suspiciously high-entropy strings with separate thresholds for
  base64-like and hex-like character classes.
- New
  [`guard_output_entropy()`](https://ian-flores.github.io/secureguard/reference/guard_output_entropy.md)
  output guardrail scans output for high-entropy substrings with
  block/redact/warn modes.

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
