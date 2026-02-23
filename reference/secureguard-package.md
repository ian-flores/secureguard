# secureguard: Input, Code, and Output Guardrails for Large Language Model Agents

Composable guardrails for Large Language Model (LLM) agent workflows.
Provides three defense layers – input validation (prompt injection
detection, topic scoping, Personally Identifiable Information (PII)
filtering), code analysis (Abstract Syntax Tree (AST) based function
blocking, complexity limits, dependency control, data flow
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

**Maintainer**: Ian Flores Siaca <iflores.siaca@hey.com> \[copyright
holder\]
