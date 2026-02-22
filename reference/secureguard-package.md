# secureguard: Input, Code, and Output Guardrails for R LLM Agents

Composable guardrails for large language model (LLM) agent workflows in
R. Provides three defense layers – input validation (prompt injection
detection, topic scoping, PII filtering), code analysis (AST-based
function blocking, complexity limits, dependency control, data flow
restrictions), and output filtering (PII redaction, secret detection,
size limits). All analysis is local with zero external API calls.
Integrates with 'securer' pre-execution hooks for seamless sandboxed
execution.

## See also

Useful links:

- <https://ian-flores.github.io/secureguard/>

- <https://github.com/ian-flores/secureguard>

- Report bugs at <https://github.com/ian-flores/secureguard/issues>

## Author

**Maintainer**: Ian Flores Siaca <iflores.siaca@hey.com>
