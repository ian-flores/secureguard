# Detect secrets in text

Scans text for secrets and credentials using regex patterns.

## Usage

``` r
detect_secrets(text, types = NULL)
```

## Arguments

- text:

  Character(1). The text to scan.

- types:

  Character vector of secret types to check. Defaults to all available
  types from
  [`secret_patterns()`](https://ian-flores.github.io/secureguard/reference/secret_patterns.md).
  See
  [`secret_patterns()`](https://ian-flores.github.io/secureguard/reference/secret_patterns.md)
  for the full list of ~40 supported types.

## Value

A named list where each element is a character vector of matches found
for that secret type. Empty character vectors indicate no matches.

## Examples

``` r
detect_secrets("API_KEY = 'sk_live_abc123def456ghi789jkl0'")
#> $api_key
#> [1] "API_KEY = 'sk_live_abc123def456ghi789jkl0"
#> 
#> $aws_key
#> character(0)
#> 
#> $password
#> character(0)
#> 
#> $token
#> character(0)
#> 
#> $private_key
#> character(0)
#> 
#> $github_token
#> character(0)
#> 
#> $aws_secret_key
#> character(0)
#> 
#> $gcp_api_key
#> character(0)
#> 
#> $gcp_service_account
#> character(0)
#> 
#> $google_oauth_token
#> character(0)
#> 
#> $azure_client_secret
#> character(0)
#> 
#> $alibaba_access_key
#> character(0)
#> 
#> $digitalocean_token
#> character(0)
#> 
#> $heroku_api_key
#> character(0)
#> 
#> $slack_bot_token
#> character(0)
#> 
#> $slack_user_token
#> character(0)
#> 
#> $slack_webhook
#> character(0)
#> 
#> $discord_token
#> character(0)
#> 
#> $twilio_api_key
#> character(0)
#> 
#> $sendgrid_api_key
#> character(0)
#> 
#> $mailgun_api_key
#> character(0)
#> 
#> $mailchimp_api_key
#> character(0)
#> 
#> $stripe_api_key
#> character(0)
#> 
#> $square_access_token
#> character(0)
#> 
#> $square_oauth_secret
#> character(0)
#> 
#> $paypal_braintree_token
#> character(0)
#> 
#> $plaid_api_token
#> character(0)
#> 
#> $npm_token
#> character(0)
#> 
#> $pypi_token
#> character(0)
#> 
#> $nuget_api_key
#> character(0)
#> 
#> $rubygems_api_key
#> character(0)
#> 
#> $github_fine_grained_pat
#> character(0)
#> 
#> $gitlab_pat
#> character(0)
#> 
#> $gitlab_deploy_token
#> character(0)
#> 
#> $bitbucket_app_password
#> character(0)
#> 
#> $openai_api_key
#> character(0)
#> 
#> $anthropic_api_key
#> character(0)
#> 
#> $anthropic_admin_key
#> character(0)
#> 
#> $shopify_access_token
#> character(0)
#> 
#> $shopify_secret
#> character(0)
#> 
#> $shopify_custom_app
#> character(0)
#> 
#> $shopify_private_app
#> character(0)
#> 
#> $jwt
#> character(0)
#> 
#> $cloudinary_url
#> character(0)
#> 
#> $firebase_url
#> character(0)
#> 
#> $postgres_conn
#> character(0)
#> 
#> $mysql_conn
#> character(0)
#> 
#> $mongodb_conn
#> character(0)
#> 
#> $redis_conn
#> character(0)
#> 
#> $facebook_access_token
#> character(0)
#> 
#> $amazon_mws_token
#> character(0)
#> 
detect_secrets("AKIAIOSFODNN7EXAMPLE", types = "aws_key")
#> $aws_key
#> [1] "AKIAIOSFODNN7EXAMPLE"
#> 
```
