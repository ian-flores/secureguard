# secureguard 0.2.0

## PII detection

* Expanded from 5 to 14 PII types: added `ip_address_v6`, `phone_intl`
  (E.164), `iban`, `dob`, `mac_address`, `us_passport`, `drivers_license`,
  `itin`, and `vin`.
* Upgraded `ssn` pattern to exclude invalid area numbers (000, 666, 900-999),
  group (00), and serial (0000); now supports no-dash format.
* Upgraded `credit_card` pattern with card-type-aware prefixes
  (Visa/MC/Amex/Discover) and Luhn checksum validation to reduce false
  positives.
* Renamed `ip_address` to `ip_address_v4` for clarity. **Breaking change.**
* Keyword-contextual patterns (`dob`, `us_passport`, `drivers_license`, `vin`)
  require keyword proximity to reduce false positives.

## Secret detection

* Expanded from 6 to 51 secret types across 10 categories: Cloud, SaaS/Messaging,
  Payment, Package Registries, Version Control, AI/ML, E-commerce,
  Infrastructure, Database, and Social.
* New patterns include AWS secret keys, Stripe/Square/PayPal tokens,
  Slack/Discord tokens, OpenAI/Anthropic API keys, Shopify tokens, JWTs,
  database connection strings, and more.

## Entropy detection

* New `shannon_entropy()` calculates Shannon entropy (bits) of a string.
* New `is_high_entropy()` detects suspiciously high-entropy strings with
  separate thresholds for base64-like and hex-like character classes.
* New `guard_output_entropy()` output guardrail scans output for high-entropy
  substrings with block/redact/warn modes.

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
