# Advanced Guardrail Patterns

This vignette covers advanced usage patterns for secureguard: building
custom guardrails, composing them into layered defenses, assembling full
pipelines, and integrating with securer for sandboxed execution.

If you are new to secureguard, start with
[`vignette("secureguard")`](https://ian-flores.github.io/secureguard/articles/secureguard.md)
for an overview of the three defense layers.

## Creating Custom Guardrails

Every guardrail in secureguard is an S7 object of class `secureguard`
with four properties: `name`, `type`, `check_fn`, and `description`. The
[`new_guardrail()`](https://ian-flores.github.io/secureguard/reference/new_guardrail.md)
constructor validates these and returns a guardrail you can use with
[`run_guardrail()`](https://ian-flores.github.io/secureguard/reference/run_guardrail.md),
[`compose_guardrails()`](https://ian-flores.github.io/secureguard/reference/compose_guardrails.md),
and
[`secure_pipeline()`](https://ian-flores.github.io/secureguard/reference/secure_pipeline.md).

### A SQL Injection Detector

Suppose your agent generates SQL queries. You want a guardrail that
blocks common SQL injection patterns before any query reaches a
database.

``` r
library(secureguard)

guard_sql_injection <- function() {
  sql_patterns <- c(
    "(?i)\\b(?:UNION\\s+SELECT|DROP\\s+TABLE|DELETE\\s+FROM)\\b",
    "(?i)\\b(?:INSERT\\s+INTO|UPDATE\\s+.+\\s+SET)\\b.*?;\\s*--",
    "(?i)'\\s*(?:OR|AND)\\s+['\"]?\\d['\"]?\\s*=\\s*['\"]?\\d",
    "(?i)(?:--|#|/\\*).*(?:SELECT|DROP|INSERT|UPDATE|DELETE)"
  )

  check_fn <- function(x) {
    hits <- vapply(sql_patterns, function(pat) {
      grepl(pat, x, perl = TRUE)
    }, logical(1))

    if (any(hits)) {
      guardrail_result(
        pass = FALSE,
        reason = "Potential SQL injection detected",
        details = list(
          matched_patterns = which(hits)
        )
      )
    } else {
      guardrail_result(pass = TRUE)
    }
  }

  new_guardrail(
    name = "sql_injection",
    type = "input",
    check_fn = check_fn,
    description = "Detects common SQL injection patterns"
  )
}
```

Now use it like any built-in guardrail:

``` r
g <- guard_sql_injection()
g
#> <secureguard> sql_injection (input)
#> Detects common SQL injection patterns

# Safe query
run_guardrail(g, "SELECT name FROM users WHERE id = 42")
#> <guardrail_result> PASS

# Injection attempt
run_guardrail(g, "SELECT * FROM users WHERE id = 1; DROP TABLE users; --")
#> <guardrail_result> FAIL
#> Reason: Potential SQL injection detected
```

### A Code Length Limiter

Custom guardrails of type `"code"` work exactly the same way. Here is
one that limits the number of lines in LLM-generated code:

``` r
guard_code_length <- function(max_lines = 100L) {
  check_fn <- function(code) {
    n_lines <- length(strsplit(code, "\n", fixed = TRUE)[[1L]])
    if (n_lines > max_lines) {
      guardrail_result(
        pass = FALSE,
        reason = sprintf("Code has %d lines (max %d)", n_lines, max_lines),
        details = list(n_lines = n_lines, max_lines = max_lines)
      )
    } else {
      guardrail_result(pass = TRUE, details = list(n_lines = n_lines))
    }
  }

  new_guardrail(
    name = "code_length",
    type = "code",
    check_fn = check_fn,
    description = sprintf("Limits code to %d lines", max_lines)
  )
}

g_len <- guard_code_length(max_lines = 5)
run_guardrail(g_len, "x <- 1\ny <- 2\nz <- x + y")
#> <guardrail_result> PASS

long_code <- paste(sprintf("x%d <- %d", 1:10, 1:10), collapse = "\n")
run_guardrail(g_len, long_code)
#> <guardrail_result> FAIL
#> Reason: Code has 10 lines (max 5)
```

### Anatomy of a check_fn

Every `check_fn` must:

1.  Accept a single argument (the text or object to check).
2.  Return a
    [`guardrail_result()`](https://ian-flores.github.io/secureguard/reference/guardrail_result.md)
    with at minimum `pass = TRUE` or `pass = FALSE`.
3.  Optionally include `reason` (why it failed), `warnings` (advisory
    notes), and `details` (a named list of metadata).

The `@` operator accesses properties on the result:

``` r
result <- run_guardrail(guard_code_analysis(), "system('ls')")
result@pass
#> [1] FALSE
result@reason
#> [1] "Blocked function(s) detected: system"
result@details
#> $blocked_calls
#> [1] "system"
```

## Composing Guardrails

### compose_guardrails(): Same-Type Composition

[`compose_guardrails()`](https://ian-flores.github.io/secureguard/reference/compose_guardrails.md)
merges multiple guardrails of the **same type** into a single composite
guardrail. This is useful when you want to treat a group of checks as
one unit.

``` r
# Compose three code guardrails -- ALL must pass (default)
strict_code <- compose_guardrails(
  guard_code_analysis(),
  guard_code_complexity(max_ast_depth = 10, max_calls = 50),
  guard_code_dependencies(allowed_packages = c("dplyr", "ggplot2"))
)

strict_code
#> <secureguard> composed(code_analysis + code_complexity + code_dependencies)
#> (code)
#> Composite guardrail (mode=all): code_analysis + code_complexity +
#> code_dependencies

# Clean code passes all three
run_guardrail(strict_code, "dplyr::filter(mtcars, cyl == 4)")
#> <guardrail_result> PASS

# system() fails code analysis
run_guardrail(strict_code, "system('whoami')")
#> <guardrail_result> FAIL
#> Reason: Blocked function(s) detected: system

# processx fails dependency check
run_guardrail(strict_code, "processx::run('ls')")
#> <guardrail_result> FAIL
#> Reason: Blocked function(s) detected: processx::run; Disallowed package(s):
#> processx
```

### mode = “any”: At Least One Must Pass

When `mode = "any"`, the composite passes if **any** child guardrail
passes. This is useful for allowlist-style checks where multiple
patterns are acceptable:

``` r
# Accept prompts about either statistics OR machine learning
topic_guard <- compose_guardrails(
  guard_topic_scope(allowed_topics = c("statistics", "regression", "t-test")),
  guard_topic_scope(allowed_topics = c("machine learning", "neural network")),
  mode = "any"
)

run_guardrail(topic_guard, "How do I run a t-test in R?")
#> <guardrail_result> PASS
run_guardrail(topic_guard, "Explain neural network backpropagation")
#> <guardrail_result> PASS
run_guardrail(topic_guard, "What is the weather today?")
#> <guardrail_result> FAIL
#> Reason: Input does not match any allowed topic.; Input does not match any
#> allowed topic.
```

### check_all(): Run a List and Collect Results

Sometimes you need individual results from each guardrail rather than a
single composite result.
[`check_all()`](https://ian-flores.github.io/secureguard/reference/check_all.md)
runs a list of guardrails and returns a summary:

``` r
guards <- list(
  guard_code_analysis(),
  guard_code_complexity(max_ast_depth = 10),
  guard_code_dataflow()
)

result <- check_all(guards, "x <- mean(1:10)")
result$pass
#> [1] TRUE
length(result$results)  # one per guardrail
#> [1] 3

# Inspect individual results
vapply(result$results, function(r) r@pass, logical(1))
#> [1] TRUE TRUE TRUE
```

When a check fails,
[`check_all()`](https://ian-flores.github.io/secureguard/reference/check_all.md)
collects all failure reasons:

``` r
result <- check_all(guards, "Sys.getenv('SECRET_KEY')")
result$pass
#> [1] FALSE
result$reasons
#> [1] "Data flow violation(s): Sys.getenv"
```

## Building Pipelines with secure_pipeline()

A pipeline bundles guardrails for all three layers – input, code, and
output – into a single object with dedicated methods for each stage.

### Defining a Pipeline

``` r
pipeline <- secure_pipeline(
  input_guardrails = list(
    guard_prompt_injection(sensitivity = "high"),
    guard_input_pii(),
    guard_topic_scope(allowed_topics = c("statistics", "data analysis", "R"))
  ),
  code_guardrails = list(
    guard_code_analysis(),
    guard_code_complexity(max_ast_depth = 15, max_calls = 100),
    guard_code_dependencies(allowed_packages = c("dplyr", "ggplot2", "tidyr")),
    guard_code_dataflow(block_network = TRUE, block_file_write = TRUE)
  ),
  output_guardrails = list(
    guard_output_pii(),
    guard_output_secrets(action = "redact"),
    guard_output_size(max_chars = 10000, max_lines = 200)
  )
)
```

### Running Each Stage

``` r
# Stage 1: validate user input
input_result <- pipeline$check_input("Calculate the mean and sd of mtcars$mpg")
input_result$pass
#> [1] TRUE
```

``` r
# Stage 2: validate LLM-generated code
code_result <- pipeline$check_code("
  library(dplyr)
  mtcars %>%
    summarise(mean_mpg = mean(mpg), sd_mpg = sd(mpg))
")
code_result$pass
#> [1] TRUE
```

``` r
# Stage 3: filter execution output
output_result <- pipeline$check_output("mean_mpg = 20.09, sd_mpg = 6.03")
output_result$pass
#> [1] TRUE
output_result$result  # possibly redacted text
#> [1] "mean_mpg = 20.09, sd_mpg = 6.03"
```

### Pipeline in an Agent Loop

Here is how a pipeline fits into a typical agent turn. This pattern
processes one user request through all three layers sequentially,
short-circuiting on failure:

``` r
process_turn <- function(pipeline, user_prompt, llm_fn, execute_fn) {
  # 1. Input guardrails

  input_check <- pipeline$check_input(user_prompt)
  if (!input_check$pass) {
    return(list(
      success = FALSE,
      stage = "input",
      reasons = input_check$reasons
    ))
  }

  # 2. LLM generates code
  code <- llm_fn(user_prompt)

  # 3. Code guardrails
  code_check <- pipeline$check_code(code)
  if (!code_check$pass) {
    return(list(
      success = FALSE,
      stage = "code",
      reasons = code_check$reasons
    ))
  }

  # 4. Execute in sandbox
  result <- execute_fn(code)

  # 5. Output guardrails
  output_check <- pipeline$check_output(result)
  if (!output_check$pass) {
    return(list(
      success = FALSE,
      stage = "output",
      reasons = output_check$reasons
    ))
  }

  list(success = TRUE, result = output_check$result)
}
```

## Mixing Custom and Built-In Guardrails

Custom guardrails compose seamlessly with built-in ones. You can mix
them in
[`compose_guardrails()`](https://ian-flores.github.io/secureguard/reference/compose_guardrails.md),
[`check_all()`](https://ian-flores.github.io/secureguard/reference/check_all.md),
and
[`secure_pipeline()`](https://ian-flores.github.io/secureguard/reference/secure_pipeline.md):

``` r
# The SQL injection guard from earlier alongside built-in input guards
input_guards <- compose_guardrails(
  guard_prompt_injection(),
  guard_input_pii(),
  guard_sql_injection()
)

run_guardrail(input_guards, "Please help me write a SELECT query")
#> <guardrail_result> PASS
run_guardrail(input_guards, "' OR 1=1 --")
#> <guardrail_result> FAIL
#> Reason: Potential SQL injection detected
```

Similarly for code guardrails:

``` r
# Custom length guard composed with built-in code guards
code_guards <- compose_guardrails(
  guard_code_analysis(),
  guard_code_complexity(max_ast_depth = 10),
  guard_code_length(max_lines = 50)
)

run_guardrail(code_guards, "x <- mean(1:10)")
#> <guardrail_result> PASS
```

## Integration with securer

secureguard integrates with the
[securer](https://github.com/ian-flores/securer) package to guard
sandboxed R execution sessions. securer is a suggested dependency – all
of the patterns above work without it. The integration layer adds two
capabilities: pre-execution hooks and output guarding after execution.

### Pre-Execute Hooks

[`as_pre_execute_hook()`](https://ian-flores.github.io/secureguard/reference/as_pre_execute_hook.md)
converts code guardrails into a function that securer calls before
executing each code snippet. It returns `TRUE` to allow execution or
`FALSE` to block it.

``` r
library(securer)
library(secureguard)

hook <- as_pre_execute_hook(
  guard_code_analysis(),
  guard_code_complexity(max_ast_depth = 15),
  guard_code_dataflow()
)

sess <- SecureSession$new(pre_execute_hook = hook)
sess$execute("mean(1:10)")        # allowed
sess$execute("system('whoami')")  # blocked by code_analysis
sess$execute("Sys.getenv('KEY')") # blocked by dataflow
sess$close()
```

### Post-Execute Output Guarding

[`guard_output()`](https://ian-flores.github.io/secureguard/reference/guard_output.md)
runs output guardrails on execution results. Guardrails with
`action = "redact"` transform the output rather than blocking it:

``` r
result <- sess$execute("paste('My API key is', 'AKIAIOSFODNN7EXAMPLE')")

checked <- guard_output(
  result,
  guard_output_pii(),
  guard_output_secrets(action = "redact")
)

if (checked$pass) {
  # Return the (possibly redacted) result to the user
  checked$result
} else {
  paste("Blocked:", paste(checked$reasons, collapse = "; "))
}
```

### Pipeline Hook

A pipeline can produce a pre-execute hook from its code guardrails:

``` r
pipeline <- secure_pipeline(
  input_guardrails = list(guard_prompt_injection()),
  code_guardrails = list(
    guard_code_analysis(),
    guard_code_dataflow()
  ),
  output_guardrails = list(
    guard_output_secrets(action = "redact")
  )
)

sess <- SecureSession$new(
  pre_execute_hook = pipeline$as_pre_execute_hook()
)

# The session now has code guardrails enforced automatically.
# Input and output guardrails are checked manually:
input_check <- pipeline$check_input(user_prompt)
# ... LLM generates code, session executes it ...
output_check <- pipeline$check_output(execution_result)

sess$close()
```

## Advanced Composition Patterns

### Layered Sensitivity

Use different sensitivity levels for different contexts. For example, a
public chatbot may need stricter injection detection than an internal
tool:

``` r
# Public-facing: high sensitivity, strict topic scoping
public_guards <- compose_guardrails(
  guard_prompt_injection(sensitivity = "high"),
  guard_input_pii(),
  guard_topic_scope(allowed_topics = c("data analysis", "statistics"))
)

# Internal tool: lower sensitivity, broader topics
internal_guards <- compose_guardrails(
  guard_prompt_injection(sensitivity = "low"),
  guard_input_pii()
)

run_guardrail(
  public_guards,
  "Continue from where we left off with the regression"
)
#> <guardrail_result> FAIL
#> Reason: Prompt injection detected: continuation_attack; Input does not match
#> any allowed topic.

run_guardrail(
  internal_guards,
  "Continue from where we left off with the regression"
)
#> <guardrail_result> PASS
```

### Graduated Code Restrictions

Tighten code guardrails progressively depending on trust level:

``` r
# Trusted context: only block the most dangerous operations
trusted_code <- compose_guardrails(
  guard_code_analysis(blocked_functions = c("system", "system2", "shell")),
  guard_code_dataflow(
    block_env_access = TRUE,
    block_network = FALSE,
    block_file_write = FALSE
  )
)

# Untrusted context: strict lockdown
untrusted_code <- compose_guardrails(
  guard_code_analysis(),
  guard_code_complexity(max_ast_depth = 10, max_calls = 30),
  guard_code_dependencies(allowed_packages = c("dplyr", "ggplot2")),
  guard_code_dataflow(
    block_env_access = TRUE,
    block_network = TRUE,
    block_file_write = TRUE,
    block_file_read = TRUE
  )
)

# The same code may pass in trusted but fail in untrusted
code <- "readLines('data.csv')"
run_guardrail(trusted_code, code)
#> <guardrail_result> PASS
run_guardrail(untrusted_code, code)
#> <guardrail_result> FAIL
#> Reason: Data flow violation(s): readLines
```

### Redact vs Block Decision

Output guardrails support three actions: `"block"`, `"redact"`, and
`"warn"`. Combining these in a pipeline lets you redact recoverable
issues while blocking critical ones:

``` r
# PII blocks the output entirely
# Secrets get redacted so the response is still useful
pipeline <- secure_pipeline(
  output_guardrails = list(
    guard_output_pii(),                         # blocks on PII
    guard_output_secrets(action = "redact"),     # redacts secrets
    guard_output_size(max_chars = 5000)          # blocks oversized output
  )
)

# Secrets are redacted, not blocked
result <- pipeline$check_output("API key: AKIAIOSFODNN7EXAMPLE, data looks good")
result$pass
#> [1] TRUE
result$result
#> [1] "API key: [REDACTED_AWS_KEY], data looks good"

# PII causes a block
result <- pipeline$check_output("Patient SSN: 123-45-6789")
result$pass
#> [1] FALSE
result$reasons
#> [1] "PII detected in output: ssn"
```

## Summary

| Pattern               | Function                                                                                             | Use Case                     |
|-----------------------|------------------------------------------------------------------------------------------------------|------------------------------|
| Custom guardrail      | [`new_guardrail()`](https://ian-flores.github.io/secureguard/reference/new_guardrail.md)             | Domain-specific checks       |
| Same-type composition | [`compose_guardrails()`](https://ian-flores.github.io/secureguard/reference/compose_guardrails.md)   | Merge guards into one        |
| Batch check           | [`check_all()`](https://ian-flores.github.io/secureguard/reference/check_all.md)                     | Individual results per guard |
| Full pipeline         | [`secure_pipeline()`](https://ian-flores.github.io/secureguard/reference/secure_pipeline.md)         | Three-layer defense          |
| Pre-execute hook      | [`as_pre_execute_hook()`](https://ian-flores.github.io/secureguard/reference/as_pre_execute_hook.md) | securer integration          |
| Output guard          | [`guard_output()`](https://ian-flores.github.io/secureguard/reference/guard_output.md)               | Post-execution filtering     |

The key design principle: guardrails are composable values. Build small,
focused guards, compose them for your context, and assemble them into
pipelines that protect every stage of an agent workflow.
