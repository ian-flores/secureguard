# Secret output guardrail

Creates a guardrail that scans output for secrets and credentials.

## Usage

``` r
guard_output_secrets(detect = NULL, action = c("block", "redact", "warn"))
```

## Arguments

- detect:

  Character vector of secret types to detect. Defaults to all types from
  [`secret_patterns()`](https://ian-flores.github.io/secureguard/reference/secret_patterns.md):
  `"api_key"`, `"aws_key"`, `"password"`, `"token"`, `"private_key"`,
  `"github_token"`, `"aws_secret_key"`, `"gcp_api_key"`,
  `"gcp_service_account"`, `"google_oauth_token"`,
  `"azure_client_secret"`, `"alibaba_access_key"`,
  `"digitalocean_token"`, `"heroku_api_key"`, `"slack_bot_token"`,
  `"slack_user_token"`, `"slack_webhook"`, `"discord_token"`,
  `"twilio_api_key"`, `"sendgrid_api_key"`, `"mailgun_api_key"`,
  `"mailchimp_api_key"`, `"stripe_api_key"`, `"square_access_token"`,
  `"square_oauth_secret"`, `"paypal_braintree_token"`,
  `"plaid_api_token"`, `"npm_token"`, `"pypi_token"`, `"nuget_api_key"`,
  `"rubygems_api_key"`, `"github_fine_grained_pat"`, `"gitlab_pat"`,
  `"gitlab_deploy_token"`, `"bitbucket_app_password"`,
  `"openai_api_key"`, `"anthropic_api_key"`, `"anthropic_admin_key"`,
  `"shopify_access_token"`, `"shopify_secret"`, `"shopify_custom_app"`,
  `"shopify_private_app"`, `"jwt"`, `"cloudinary_url"`,
  `"firebase_url"`, `"postgres_conn"`, `"mysql_conn"`, `"mongodb_conn"`,
  `"redis_conn"`, `"facebook_access_token"`, `"amazon_mws_token"`.

- action:

  Character(1). What to do when secrets are found:

  - `"block"` (default): fail the check.

  - `"redact"`: pass but replace secrets with `[REDACTED_API_KEY]` etc.

  - `"warn"`: pass with advisory warnings.

## Value

A guardrail object of class `"secureguard"` with type `"output"`.

## Examples

``` r
g <- guard_output_secrets()
run_guardrail(g, "AKIAIOSFODNN7EXAMPLE")
#> <guardrail_result> FAIL
#> Reason: Secrets detected in output: aws_key

g_redact <- guard_output_secrets(action = "redact")
result <- run_guardrail(g_redact, "AKIAIOSFODNN7EXAMPLE")
result@details$redacted_text
#> [1] "[REDACTED_AWS_KEY]"
```
