# Secret detection patterns

Returns a named list of regex patterns for detecting secrets and
credentials in text. Covers ~40 secret types across cloud providers,
SaaS platforms, payment processors, package registries, version control,
AI/ML services, e-commerce, infrastructure, databases, and social
platforms.

## Usage

``` r
secret_patterns()
```

## Value

A named list of character(1) regex patterns.

## Examples

``` r
pats <- secret_patterns()
names(pats)
#>  [1] "api_key"                 "aws_key"                
#>  [3] "password"                "token"                  
#>  [5] "private_key"             "github_token"           
#>  [7] "aws_secret_key"          "gcp_api_key"            
#>  [9] "gcp_service_account"     "google_oauth_token"     
#> [11] "azure_client_secret"     "alibaba_access_key"     
#> [13] "digitalocean_token"      "heroku_api_key"         
#> [15] "slack_bot_token"         "slack_user_token"       
#> [17] "slack_webhook"           "discord_token"          
#> [19] "twilio_api_key"          "sendgrid_api_key"       
#> [21] "mailgun_api_key"         "mailchimp_api_key"      
#> [23] "stripe_api_key"          "square_access_token"    
#> [25] "square_oauth_secret"     "paypal_braintree_token" 
#> [27] "plaid_api_token"         "npm_token"              
#> [29] "pypi_token"              "nuget_api_key"          
#> [31] "rubygems_api_key"        "github_fine_grained_pat"
#> [33] "gitlab_pat"              "gitlab_deploy_token"    
#> [35] "bitbucket_app_password"  "openai_api_key"         
#> [37] "anthropic_api_key"       "anthropic_admin_key"    
#> [39] "shopify_access_token"    "shopify_secret"         
#> [41] "shopify_custom_app"      "shopify_private_app"    
#> [43] "jwt"                     "cloudinary_url"         
#> [45] "firebase_url"            "postgres_conn"          
#> [47] "mysql_conn"              "mongodb_conn"           
#> [49] "redis_conn"              "facebook_access_token"  
#> [51] "amazon_mws_token"       
grepl(pats$aws_key, "AKIAIOSFODNN7EXAMPLE")
#> [1] TRUE
```
