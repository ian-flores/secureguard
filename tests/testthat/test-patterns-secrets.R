all_secret_types <- c(
  "api_key", "aws_key", "password", "token", "private_key", "github_token",
  "aws_secret_key", "gcp_api_key", "gcp_service_account", "google_oauth_token",
  "azure_client_secret", "alibaba_access_key", "digitalocean_token",
  "heroku_api_key", "slack_bot_token", "slack_user_token", "slack_webhook",
  "discord_token", "twilio_api_key", "sendgrid_api_key", "mailgun_api_key",
  "mailchimp_api_key", "stripe_api_key", "square_access_token",
  "square_oauth_secret", "paypal_braintree_token", "plaid_api_token",
  "npm_token", "pypi_token", "nuget_api_key", "rubygems_api_key",
  "github_fine_grained_pat", "gitlab_pat", "gitlab_deploy_token",
  "bitbucket_app_password", "openai_api_key", "anthropic_api_key",
  "anthropic_admin_key", "shopify_access_token", "shopify_secret",
  "shopify_custom_app", "shopify_private_app", "jwt", "cloudinary_url",
  "firebase_url", "postgres_conn", "mysql_conn", "mongodb_conn",
  "redis_conn", "facebook_access_token", "amazon_mws_token"
)

test_that("secret_patterns returns named list with expected types", {
  pats <- secret_patterns()
  expect_type(pats, "list")
  expect_named(pats, all_secret_types)
  for (p in pats) {
    expect_type(p, "character")
    expect_length(p, 1L)
  }
})

# -- API Key (original) --
test_that("detect_secrets finds API keys", {
  expect_length(detect_secrets("api_key = 'sk_live_abc123def456ghi789jkl0'")$api_key, 1L)
  expect_length(detect_secrets("API-KEY: abcdefghijklmnopqrst1234")$api_key, 1L)
  expect_length(detect_secrets("apiKey=ABCDEFGHIJKLMNOPQRSTUVWXYZ")$api_key, 1L)
  expect_length(detect_secrets("my api_key = very_long_key_value_1234567890")$api_key, 1L)
  expect_length(detect_secrets("API_KEY='a1b2c3d4e5f6g7h8i9j0k1l2'")$api_key, 1L)
})

test_that("detect_secrets rejects non-API-keys", {
  expect_length(detect_secrets("no secrets here")$api_key, 0L)
  expect_length(detect_secrets("api_key = short")$api_key, 0L)
  expect_length(detect_secrets("just a regular sentence")$api_key, 0L)
  expect_length(detect_secrets("api documentation link")$api_key, 0L)
  expect_length(detect_secrets("key = 123")$api_key, 0L)
})

# -- AWS Key (original) --
test_that("detect_secrets finds AWS keys", {
  expect_length(detect_secrets("AKIAIOSFODNN7EXAMPLE")$aws_key, 1L)
  expect_length(detect_secrets("key: ASIAIOSFODNN7EXAMPLE")$aws_key, 1L)
  expect_length(detect_secrets("aws AKIAI44QH8DHBEXAMPLE")$aws_key, 1L)
  expect_length(detect_secrets("AKIAEXAMPLEKEYID1234")$aws_key, 1L)
  expect_equal(
    detect_secrets("creds: AKIAIOSFODNN7EXAMPLE")$aws_key,
    "AKIAIOSFODNN7EXAMPLE"
  )
})

test_that("detect_secrets rejects non-AWS-keys", {
  expect_length(detect_secrets("AKIA")$aws_key, 0L)
  expect_length(detect_secrets("no aws here")$aws_key, 0L)
  expect_length(detect_secrets("AKIAlowercase1234567")$aws_key, 0L)
  expect_length(detect_secrets("ABCDEFGHIJKLMNOPQRST")$aws_key, 0L)
  expect_length(detect_secrets("random text")$aws_key, 0L)
})

# -- Password (original) --
test_that("detect_secrets finds passwords", {
  expect_length(detect_secrets("password = mysecretpassword")$password, 1L)
  expect_length(detect_secrets("PASSWORD: longpassword123")$password, 1L)
  expect_length(detect_secrets("password='super_secret!'")$password, 1L)
  expect_length(detect_secrets("Password=Str0ngP@ss!")$password, 1L)
  expect_length(detect_secrets("password = \"verylongpassword\"")$password, 1L)
})

test_that("detect_secrets rejects non-passwords", {
  expect_length(detect_secrets("no password here")$password, 0L)
  expect_length(detect_secrets("password = short")$password, 0L)
  expect_length(detect_secrets("just words")$password, 0L)
  expect_length(detect_secrets("passw0rd mention")$password, 0L)
  expect_length(detect_secrets("enter your password")$password, 0L)
})

# -- Token (original) --
test_that("detect_secrets finds tokens", {
  expect_length(detect_secrets(paste0("bearer eyJhbGciOiJIUzI1Ni", "IsInR5cCI6IkpXVCJ9"))$token, 1L)
  expect_length(detect_secrets("Authorization: Bearer abc123def456ghi789jkl0")$token, 1L)
  expect_length(detect_secrets("auth = 'very_long_auth_token_value_123'")$token, 1L)
  expect_length(detect_secrets("Bearer abcdefghijklmnopqrstu")$token, 1L)
  expect_length(detect_secrets("authorization=tok_1234567890abcdefgh")$token, 1L)
})

test_that("detect_secrets rejects non-tokens", {
  expect_length(detect_secrets("no token here")$token, 0L)
  expect_length(detect_secrets("bear with me")$token, 0L)
  expect_length(detect_secrets("authorize access")$token, 0L)
  expect_length(detect_secrets("random words")$token, 0L)
  expect_length(detect_secrets("bearer ab")$token, 0L)
})

# -- Private Key (original) --
test_that("detect_secrets finds private key headers", {
  expect_length(
    detect_secrets("-----BEGIN RSA PRIVATE KEY-----")$private_key, 1L
  )
  expect_length(
    detect_secrets("-----BEGIN PRIVATE KEY-----")$private_key, 1L
  )
  expect_length(
    detect_secrets("-----BEGIN EC PRIVATE KEY-----")$private_key, 1L
  )
  expect_length(
    detect_secrets("-----BEGIN DSA PRIVATE KEY-----")$private_key, 1L
  )
  expect_length(
    detect_secrets("-----BEGIN OPENSSH PRIVATE KEY-----")$private_key, 1L
  )
})

test_that("detect_secrets rejects non-private-keys", {
  expect_length(detect_secrets("-----BEGIN PUBLIC KEY-----")$private_key, 0L)
  expect_length(detect_secrets("no key here")$private_key, 0L)
  expect_length(detect_secrets("BEGIN PRIVATE")$private_key, 0L)
  expect_length(detect_secrets("private key mentioned")$private_key, 0L)
  expect_length(
    detect_secrets("-----BEGIN CERTIFICATE-----")$private_key, 0L
  )
})

# -- GitHub Token (original) --
test_that("detect_secrets finds GitHub tokens", {
  fake36 <- paste0(rep("a", 36), collapse = "")
  expect_length(detect_secrets(paste0("ghp_", fake36))$github_token, 1L)
  expect_length(detect_secrets(paste0("gho_", fake36))$github_token, 1L)
  expect_length(detect_secrets(paste0("ghu_", fake36))$github_token, 1L)
  expect_length(detect_secrets(paste0("ghs_", fake36))$github_token, 1L)
  expect_length(detect_secrets(paste0("ghr_", fake36))$github_token, 1L)
})

test_that("detect_secrets rejects non-GitHub-tokens", {
  expect_length(detect_secrets("ghp_short")$github_token, 0L)
  expect_length(detect_secrets("ghx_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")$github_token, 0L)
  expect_length(detect_secrets("no github token")$github_token, 0L)
  expect_length(detect_secrets("gh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")$github_token, 0L)
  expect_length(detect_secrets("just text")$github_token, 0L)
})

# ============================================================================
# NEW PATTERNS
# ============================================================================

# -- AWS Secret Key --
test_that("detect_secrets finds AWS secret keys", {
  fake40 <- paste0(rep("A", 40), collapse = "")
  expect_length(detect_secrets(paste0("aws_secret_key = ", fake40))$aws_secret_key, 1L)
  expect_length(detect_secrets(paste0("AWS_SECRET_ACCESS_KEY=", fake40))$aws_secret_key, 1L)
  expect_length(detect_secrets(paste0("aws secret key: '", fake40, "'"))$aws_secret_key, 1L)
  expect_length(detect_secrets(paste0("AWS_SECRET_KEY = \"", fake40, "\""))$aws_secret_key, 1L)
})

test_that("detect_secrets rejects non-AWS-secret-keys", {
  expect_length(detect_secrets("aws_secret_key = short")$aws_secret_key, 0L)
  expect_length(detect_secrets("no aws here")$aws_secret_key, 0L)
  expect_length(detect_secrets("aws_access_key_id = AKIA1234")$aws_secret_key, 0L)
})

# -- GCP API Key --
test_that("detect_secrets finds GCP API keys", {
  fake35 <- paste0(rep("A", 35), collapse = "")
  expect_length(detect_secrets(paste0("AIza", fake35))$gcp_api_key, 1L)
  expect_length(detect_secrets(paste0("key=AIza", fake35))$gcp_api_key, 1L)
  expect_length(detect_secrets(paste0("AIza", paste0(rep("x", 35), collapse = "")))$gcp_api_key, 1L)
})

test_that("detect_secrets rejects non-GCP-API-keys", {
  expect_length(detect_secrets("AIza_short")$gcp_api_key, 0L)
  expect_length(detect_secrets("no gcp key")$gcp_api_key, 0L)
  expect_length(detect_secrets("AIzb1234567890123456789012345678901234")$gcp_api_key, 0L)
})

# -- GCP Service Account --
test_that("detect_secrets finds GCP service account", {
  expect_length(detect_secrets('"type" : "service_account"')$gcp_service_account, 1L)
  expect_length(detect_secrets('"type":"service_account"')$gcp_service_account, 1L)
  expect_length(detect_secrets('"type"  :  "service_account"')$gcp_service_account, 1L)
})

test_that("detect_secrets rejects non-GCP-service-accounts", {
  expect_length(detect_secrets("type: service_account")$gcp_service_account, 0L)
  expect_length(detect_secrets("service_account")$gcp_service_account, 0L)
  expect_length(detect_secrets('"type": "user"')$gcp_service_account, 0L)
})

# -- Google OAuth Token --
test_that("detect_secrets finds Google OAuth tokens", {
  expect_length(detect_secrets("ya29.abc123def456")$google_oauth_token, 1L)
  expect_length(detect_secrets("ya29.Gl0xBC-1234_abcd")$google_oauth_token, 1L)
  expect_length(detect_secrets("token: ya29.AHES6ZRN3-HZYk")$google_oauth_token, 1L)
})

test_that("detect_secrets rejects non-Google-OAuth-tokens", {
  expect_length(detect_secrets("ya28.something")$google_oauth_token, 0L)
  expect_length(detect_secrets("ya29")$google_oauth_token, 0L)
  expect_length(detect_secrets("no google token")$google_oauth_token, 0L)
})

# -- Azure Client Secret --
test_that("detect_secrets finds Azure client secrets", {
  fake34 <- paste0(rep("a", 34), collapse = "")
  expect_length(detect_secrets(paste0("azure_secret = ", fake34))$azure_client_secret, 1L)
  expect_length(detect_secrets(paste0("client_secret:", fake34))$azure_client_secret, 1L)
  expect_length(detect_secrets(paste0("AZURE_SECRET='", fake34, "'"))$azure_client_secret, 1L)
  expect_length(detect_secrets(paste0("CLIENT_SECRET = \"", fake34, "\""))$azure_client_secret, 1L)
})

test_that("detect_secrets rejects non-Azure-client-secrets", {
  expect_length(detect_secrets("azure_secret = short")$azure_client_secret, 0L)
  expect_length(detect_secrets("no azure here")$azure_client_secret, 0L)
  expect_length(detect_secrets("client_id = abcd1234")$azure_client_secret, 0L)
})

# -- Alibaba Access Key --
test_that("detect_secrets finds Alibaba access keys", {
  fake20 <- paste0(rep("A", 20), collapse = "")
  expect_length(detect_secrets(paste0("LTAI", fake20))$alibaba_access_key, 1L)
  expect_length(detect_secrets(paste0("key=LTAI", fake20))$alibaba_access_key, 1L)
  expect_length(detect_secrets(paste0("LTAI", paste0(rep("x", 20), collapse = "")))$alibaba_access_key, 1L)
})

test_that("detect_secrets rejects non-Alibaba-access-keys", {
  expect_length(detect_secrets("LTAIshort")$alibaba_access_key, 0L)
  expect_length(detect_secrets("no alibaba key")$alibaba_access_key, 0L)
  expect_length(detect_secrets("LTBI12345678901234567890")$alibaba_access_key, 0L)
})

# -- DigitalOcean Token --
test_that("detect_secrets finds DigitalOcean tokens", {
  fake64 <- paste0(rep("a", 64), collapse = "")
  expect_length(detect_secrets(paste0("dop_v1_", fake64))$digitalocean_token, 1L)
  expect_length(detect_secrets(paste0("key: dop_v1_", fake64))$digitalocean_token, 1L)
  expect_length(detect_secrets(paste0("dop_v1_", paste0(rep("0", 64), collapse = "")))$digitalocean_token, 1L)
})

test_that("detect_secrets rejects non-DigitalOcean-tokens", {
  expect_length(detect_secrets("dop_v1_short")$digitalocean_token, 0L)
  expect_length(detect_secrets("no do token")$digitalocean_token, 0L)
  expect_length(detect_secrets("dop_v2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")$digitalocean_token, 0L)
})

# -- Heroku API Key --
test_that("detect_secrets finds Heroku API keys", {
  uuid <- "12345678-abcd-ef01-2345-678901234567"
  expect_length(detect_secrets(paste0("heroku_api_key = ", uuid))$heroku_api_key, 1L)
  expect_length(detect_secrets(paste0("HEROKU_KEY:", uuid))$heroku_api_key, 1L)
  expect_length(detect_secrets(paste0("heroku key = '", uuid, "'"))$heroku_api_key, 1L)
})

test_that("detect_secrets rejects non-Heroku-API-keys", {
  expect_length(detect_secrets("heroku_api_key = short")$heroku_api_key, 0L)
  expect_length(detect_secrets("no heroku here")$heroku_api_key, 0L)
  expect_length(detect_secrets("heroku_api_key = notauuid")$heroku_api_key, 0L)
})

# -- Slack Bot Token --
# NOTE: Tokens constructed via paste0() to avoid triggering GitHub push protection
test_that("detect_secrets finds Slack bot tokens", {
  pfx <- "xox"
  tok1 <- paste0(pfx, "b-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx")
  tok2 <- paste0("token: ", pfx, "b-9876543210-9876543210-aAbBcCdDeEfFgGhHiIjJkKlL")
  tok3 <- paste0(pfx, "b-1234567890123-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWx")
  expect_length(detect_secrets(tok1)$slack_bot_token, 1L)
  expect_length(detect_secrets(tok2)$slack_bot_token, 1L)
  expect_length(detect_secrets(tok3)$slack_bot_token, 1L)
})

test_that("detect_secrets rejects non-Slack-bot-tokens", {
  pfx <- "xox"
  expect_length(detect_secrets(paste0(pfx, "b-short"))$slack_bot_token, 0L)
  expect_length(detect_secrets("no slack here")$slack_bot_token, 0L)
  expect_length(detect_secrets(paste0(pfx, "a-1234567890-1234567890-aaaaaaaaaaaaaaaaaaaaaaaa"))$slack_bot_token, 0L)
})

# -- Slack User Token --
test_that("detect_secrets finds Slack user tokens", {
  pfx <- "xox"
  hex32 <- paste0(rep("a", 32), collapse = "")
  expect_length(detect_secrets(paste0(pfx, "p-1234567890-1234567890-1234567890-", hex32))$slack_user_token, 1L)
  expect_length(detect_secrets(paste0(pfx, "p-9876543210123-9876543210123-9876543210123-", hex32))$slack_user_token, 1L)
})

test_that("detect_secrets rejects non-Slack-user-tokens", {
  pfx <- "xox"
  expect_length(detect_secrets(paste0(pfx, "p-short"))$slack_user_token, 0L)
  expect_length(detect_secrets("no slack token")$slack_user_token, 0L)
})

# -- Slack Webhook --
test_that("detect_secrets finds Slack webhooks", {
  hook_base <- paste0("https://hooks.slack", ".com/services/")
  expect_length(
    detect_secrets(paste0(hook_base, "T12345678/B12345678/AbCdEfGhIjKlMnOpQrStUvWx"))$slack_webhook,
    1L
  )
  expect_length(
    detect_secrets(paste0(hook_base, "TABCDEFGH/BABCDEFGH/aAbBcCdDeEfFgGhHiIjJkKlL"))$slack_webhook,
    1L
  )
})

test_that("detect_secrets rejects non-Slack-webhooks", {
  hook_base <- paste0("https://hooks.slack", ".com/services/")
  expect_length(detect_secrets(paste0(hook_base, "short"))$slack_webhook, 0L)
  expect_length(detect_secrets("no slack webhook")$slack_webhook, 0L)
  expect_length(detect_secrets("https://example.com/webhook")$slack_webhook, 0L)
})

# -- Discord Token --
# NOTE: Tokens constructed via paste0() to avoid triggering GitHub push protection
test_that("detect_secrets finds Discord tokens", {
  tok1 <- paste0("MTIzNDU2Nzg5MDEy", "MzQ1Njc4.AbCdEf.AbCdEfGhIjKlMnOpQrStUvWxYz0")
  tok2 <- paste0("NTIzNDU2Nzg5MDEy", "MzQ1Njc4OQ.GhIjKl.MnOpQrStUvWxYz0AbCdEfGhIjKlM")
  expect_length(detect_secrets(tok1)$discord_token, 1L)
  expect_length(detect_secrets(tok2)$discord_token, 1L)
})

test_that("detect_secrets rejects non-Discord-tokens", {
  expect_length(detect_secrets("Ashort.abc.def")$discord_token, 0L)
  expect_length(detect_secrets("no discord token")$discord_token, 0L)
})

# -- Twilio API Key --
test_that("detect_secrets finds Twilio API keys", {
  fake32 <- paste0(rep("a", 32), collapse = "")
  expect_length(detect_secrets(paste0("SK", fake32))$twilio_api_key, 1L)
  expect_length(detect_secrets(paste0("SK", paste0(rep("0", 32), collapse = "")))$twilio_api_key, 1L)
  expect_length(detect_secrets(paste0("key: SK", paste0(rep("F", 32), collapse = "")))$twilio_api_key, 1L)
})

test_that("detect_secrets rejects non-Twilio-API-keys", {
  expect_length(detect_secrets("SKshort")$twilio_api_key, 0L)
  expect_length(detect_secrets("no twilio here")$twilio_api_key, 0L)
  expect_length(detect_secrets("SX12345678901234567890123456789012")$twilio_api_key, 0L)
})

# -- SendGrid API Key --
test_that("detect_secrets finds SendGrid API keys", {
  part1 <- paste0(rep("A", 22), collapse = "")
  part2 <- paste0(rep("B", 43), collapse = "")
  expect_length(detect_secrets(paste0("SG.", part1, ".", part2))$sendgrid_api_key, 1L)
  part1b <- paste0(rep("x", 22), collapse = "")
  part2b <- paste0(rep("y", 43), collapse = "")
  expect_length(detect_secrets(paste0("SG.", part1b, ".", part2b))$sendgrid_api_key, 1L)
})

test_that("detect_secrets rejects non-SendGrid-API-keys", {
  expect_length(detect_secrets("SG.short.short")$sendgrid_api_key, 0L)
  expect_length(detect_secrets("no sendgrid here")$sendgrid_api_key, 0L)
})

# -- Mailgun API Key --
test_that("detect_secrets finds Mailgun API keys", {
  fake32 <- paste0(rep("a", 32), collapse = "")
  expect_length(detect_secrets(paste0("key-", fake32))$mailgun_api_key, 1L)
  expect_length(detect_secrets(paste0("key-", paste0(rep("X", 32), collapse = "")))$mailgun_api_key, 1L)
  expect_length(detect_secrets(paste0("key-", paste0(rep("0", 32), collapse = "")))$mailgun_api_key, 1L)
})

test_that("detect_secrets rejects non-Mailgun-API-keys", {
  expect_length(detect_secrets("key-short")$mailgun_api_key, 0L)
  expect_length(detect_secrets("no mailgun here")$mailgun_api_key, 0L)
})

# -- Mailchimp API Key --
test_that("detect_secrets finds Mailchimp API keys", {
  hex32 <- paste0(rep("a", 32), collapse = "")
  expect_length(detect_secrets(paste0(hex32, "-us1"))$mailchimp_api_key, 1L)
  expect_length(detect_secrets(paste0(hex32, "-us20"))$mailchimp_api_key, 1L)
  hex32b <- paste0(rep("0", 32), collapse = "")
  expect_length(detect_secrets(paste0(hex32b, "-us5"))$mailchimp_api_key, 1L)
})

test_that("detect_secrets rejects non-Mailchimp-API-keys", {
  expect_length(detect_secrets("short-us1")$mailchimp_api_key, 0L)
  expect_length(detect_secrets("no mailchimp here")$mailchimp_api_key, 0L)
})

# -- Stripe API Key --
test_that("detect_secrets finds Stripe API keys", {
  fake24 <- paste0(rep("a", 24), collapse = "")
  expect_length(detect_secrets(paste0("sk_test_", fake24))$stripe_api_key, 1L)
  expect_length(detect_secrets(paste0("sk_live_", fake24))$stripe_api_key, 1L)
  expect_length(detect_secrets(paste0("pk_test_", fake24))$stripe_api_key, 1L)
  expect_length(detect_secrets(paste0("rk_live_", fake24))$stripe_api_key, 1L)
})

test_that("detect_secrets rejects non-Stripe-API-keys", {
  expect_length(detect_secrets("sk_test_short")$stripe_api_key, 0L)
  expect_length(detect_secrets("no stripe here")$stripe_api_key, 0L)
  expect_length(detect_secrets("sk_prod_aaaaaaaaaaaaaaaaaaaaaaaa")$stripe_api_key, 0L)
})

# -- Square Access Token --
test_that("detect_secrets finds Square access tokens", {
  fake22 <- paste0(rep("A", 22), collapse = "")
  expect_length(detect_secrets(paste0("sq0atp-", fake22))$square_access_token, 1L)
  expect_length(detect_secrets(paste0("sq0atp-", paste0(rep("x", 22), collapse = "")))$square_access_token, 1L)
})

test_that("detect_secrets rejects non-Square-access-tokens", {
  expect_length(detect_secrets("sq0atp-short")$square_access_token, 0L)
  expect_length(detect_secrets("no square here")$square_access_token, 0L)
})

# -- Square OAuth Secret --
test_that("detect_secrets finds Square OAuth secrets", {
  fake43 <- paste0(rep("A", 43), collapse = "")
  expect_length(detect_secrets(paste0("sq0csp-", fake43))$square_oauth_secret, 1L)
  expect_length(detect_secrets(paste0("sq0csp-", paste0(rep("z", 43), collapse = "")))$square_oauth_secret, 1L)
})

test_that("detect_secrets rejects non-Square-OAuth-secrets", {
  expect_length(detect_secrets("sq0csp-short")$square_oauth_secret, 0L)
  expect_length(detect_secrets("no square oauth")$square_oauth_secret, 0L)
})

# -- PayPal/Braintree Token --
test_that("detect_secrets finds PayPal/Braintree tokens", {
  prod16 <- paste0(rep("a", 16), collapse = "")
  hex32 <- paste0(rep("0", 32), collapse = "")
  expect_length(
    detect_secrets(paste0("access_token$production$", prod16, "$", hex32))$paypal_braintree_token,
    1L
  )
  prod16b <- paste0(rep("z", 16), collapse = "")
  hex32b <- paste0(rep("f", 32), collapse = "")
  expect_length(
    detect_secrets(paste0("access_token$production$", prod16b, "$", hex32b))$paypal_braintree_token,
    1L
  )
})

test_that("detect_secrets rejects non-PayPal-Braintree-tokens", {
  expect_length(detect_secrets("access_token$production$short$short")$paypal_braintree_token, 0L)
  expect_length(detect_secrets("no paypal here")$paypal_braintree_token, 0L)
})

# -- Plaid API Token --
test_that("detect_secrets finds Plaid API tokens", {
  uuid <- "12345678-abcd-ef01-2345-678901234567"
  expect_length(detect_secrets(paste0("access-sandbox-", uuid))$plaid_api_token, 1L)
  expect_length(detect_secrets(paste0("access-production-", uuid))$plaid_api_token, 1L)
  expect_length(detect_secrets(paste0("client-development-", uuid))$plaid_api_token, 1L)
})

test_that("detect_secrets rejects non-Plaid-API-tokens", {
  expect_length(detect_secrets("access-sandbox-short")$plaid_api_token, 0L)
  expect_length(detect_secrets("no plaid here")$plaid_api_token, 0L)
})

# -- NPM Token --
test_that("detect_secrets finds NPM tokens", {
  fake36 <- paste0(rep("A", 36), collapse = "")
  expect_length(detect_secrets(paste0("npm_", fake36))$npm_token, 1L)
  expect_length(detect_secrets(paste0("npm_", paste0(rep("z", 36), collapse = "")))$npm_token, 1L)
  expect_length(detect_secrets(paste0("npm_", paste0(rep("0", 36), collapse = "")))$npm_token, 1L)
})

test_that("detect_secrets rejects non-NPM-tokens", {
  expect_length(detect_secrets("npm_short")$npm_token, 0L)
  expect_length(detect_secrets("no npm token")$npm_token, 0L)
})

# -- PyPI Token --
test_that("detect_secrets finds PyPI tokens", {
  fake50 <- paste0(rep("A", 50), collapse = "")
  expect_length(detect_secrets(paste0("pypi-", fake50))$pypi_token, 1L)
  fake60 <- paste0(rep("x", 60), collapse = "")
  expect_length(detect_secrets(paste0("pypi-", fake60))$pypi_token, 1L)
})

test_that("detect_secrets rejects non-PyPI-tokens", {
  expect_length(detect_secrets("pypi-short")$pypi_token, 0L)
  expect_length(detect_secrets("no pypi token")$pypi_token, 0L)
})

# -- NuGet API Key --
test_that("detect_secrets finds NuGet API keys", {
  fake43 <- paste0(rep("a", 43), collapse = "")
  expect_length(detect_secrets(paste0("oy2", fake43))$nuget_api_key, 1L)
  fake43b <- paste0(rep("0", 43), collapse = "")
  expect_length(detect_secrets(paste0("oy2", fake43b))$nuget_api_key, 1L)
})

test_that("detect_secrets rejects non-NuGet-API-keys", {
  expect_length(detect_secrets("oy2short")$nuget_api_key, 0L)
  expect_length(detect_secrets("no nuget key")$nuget_api_key, 0L)
})

# -- RubyGems API Key --
test_that("detect_secrets finds RubyGems API keys", {
  fake48 <- paste0(rep("a", 48), collapse = "")
  expect_length(detect_secrets(paste0("rubygems_", fake48))$rubygems_api_key, 1L)
  fake48b <- paste0(rep("0", 48), collapse = "")
  expect_length(detect_secrets(paste0("rubygems_", fake48b))$rubygems_api_key, 1L)
})

test_that("detect_secrets rejects non-RubyGems-API-keys", {
  expect_length(detect_secrets("rubygems_short")$rubygems_api_key, 0L)
  expect_length(detect_secrets("no rubygems key")$rubygems_api_key, 0L)
})

# -- GitHub Fine-Grained PAT --
test_that("detect_secrets finds GitHub fine-grained PATs", {
  fake82 <- paste0(rep("A", 82), collapse = "")
  expect_length(detect_secrets(paste0("github_pat_", fake82))$github_fine_grained_pat, 1L)
  fake82b <- paste0(rep("0", 82), collapse = "")
  expect_length(detect_secrets(paste0("github_pat_", fake82b))$github_fine_grained_pat, 1L)
})

test_that("detect_secrets rejects non-GitHub-fine-grained-PATs", {
  expect_length(detect_secrets("github_pat_short")$github_fine_grained_pat, 0L)
  expect_length(detect_secrets("no github pat")$github_fine_grained_pat, 0L)
})

# -- GitLab PAT --
test_that("detect_secrets finds GitLab PATs", {
  fake20 <- paste0(rep("A", 20), collapse = "")
  expect_length(detect_secrets(paste0("glpat-", fake20))$gitlab_pat, 1L)
  fake30 <- paste0(rep("x", 30), collapse = "")
  expect_length(detect_secrets(paste0("glpat-", fake30))$gitlab_pat, 1L)
})

test_that("detect_secrets rejects non-GitLab-PATs", {
  expect_length(detect_secrets("glpat-short")$gitlab_pat, 0L)
  expect_length(detect_secrets("no gitlab pat")$gitlab_pat, 0L)
})

# -- GitLab Deploy Token --
test_that("detect_secrets finds GitLab deploy tokens", {
  fake20 <- paste0(rep("A", 20), collapse = "")
  expect_length(detect_secrets(paste0("gldt-", fake20))$gitlab_deploy_token, 1L)
  fake25 <- paste0(rep("z", 25), collapse = "")
  expect_length(detect_secrets(paste0("gldt-", fake25))$gitlab_deploy_token, 1L)
})

test_that("detect_secrets rejects non-GitLab-deploy-tokens", {
  expect_length(detect_secrets("gldt-short")$gitlab_deploy_token, 0L)
  expect_length(detect_secrets("no gitlab deploy")$gitlab_deploy_token, 0L)
})

# -- Bitbucket App Password --
test_that("detect_secrets finds Bitbucket app passwords", {
  fake18 <- paste0(rep("A", 18), collapse = "")
  expect_length(detect_secrets(paste0("bitbucket_app_password = ", fake18))$bitbucket_app_password, 1L)
  expect_length(detect_secrets(paste0("BITBUCKET_PASSWORD:", fake18))$bitbucket_app_password, 1L)
  expect_length(detect_secrets(paste0("bitbucket password = '", fake18, "'"))$bitbucket_app_password, 1L)
})

test_that("detect_secrets rejects non-Bitbucket-app-passwords", {
  expect_length(detect_secrets("bitbucket_app_password = short")$bitbucket_app_password, 0L)
  expect_length(detect_secrets("no bitbucket here")$bitbucket_app_password, 0L)
})

# -- OpenAI API Key --
test_that("detect_secrets finds OpenAI API keys", {
  fake20 <- paste0(rep("A", 20), collapse = "")
  expect_length(detect_secrets(paste0("sk-", fake20))$openai_api_key, 1L)
  fake40 <- paste0(rep("x", 40), collapse = "")
  expect_length(detect_secrets(paste0("sk-proj-", fake40))$openai_api_key, 1L)
  expect_length(detect_secrets(paste0("sk-", paste0(rep("0", 48), collapse = "")))$openai_api_key, 1L)
})

test_that("detect_secrets rejects non-OpenAI-API-keys", {
  expect_length(detect_secrets("sk-short")$openai_api_key, 0L)
  expect_length(detect_secrets("no openai key")$openai_api_key, 0L)
})

# -- Anthropic API Key --
test_that("detect_secrets finds Anthropic API keys", {
  fake90 <- paste0(rep("A", 90), collapse = "")
  expect_length(detect_secrets(paste0("sk-ant-", fake90))$anthropic_api_key, 1L)
  expect_length(detect_secrets(paste0("sk-ant-api03-", fake90))$anthropic_api_key, 1L)
  fake100 <- paste0(rep("x", 100), collapse = "")
  expect_length(detect_secrets(paste0("sk-ant-", fake100))$anthropic_api_key, 1L)
})

test_that("detect_secrets rejects non-Anthropic-API-keys", {
  expect_length(detect_secrets("sk-ant-short")$anthropic_api_key, 0L)
  expect_length(detect_secrets("no anthropic key")$anthropic_api_key, 0L)
})

# -- Anthropic Admin Key --
test_that("detect_secrets finds Anthropic admin keys", {
  fake90 <- paste0(rep("A", 90), collapse = "")
  expect_length(detect_secrets(paste0("sk-ant-admin01-", fake90))$anthropic_admin_key, 1L)
  fake100 <- paste0(rep("x", 100), collapse = "")
  expect_length(detect_secrets(paste0("sk-ant-admin01-", fake100))$anthropic_admin_key, 1L)
})

test_that("detect_secrets rejects non-Anthropic-admin-keys", {
  expect_length(detect_secrets("sk-ant-admin01-short")$anthropic_admin_key, 0L)
  expect_length(detect_secrets("no anthropic admin key")$anthropic_admin_key, 0L)
})

# -- Shopify Access Token --
test_that("detect_secrets finds Shopify access tokens", {
  fake32 <- paste0(rep("a", 32), collapse = "")
  expect_length(detect_secrets(paste0("shpat_", fake32))$shopify_access_token, 1L)
  fake32b <- paste0(rep("0", 32), collapse = "")
  expect_length(detect_secrets(paste0("shpat_", fake32b))$shopify_access_token, 1L)
})

test_that("detect_secrets rejects non-Shopify-access-tokens", {
  expect_length(detect_secrets("shpat_short")$shopify_access_token, 0L)
  expect_length(detect_secrets("no shopify token")$shopify_access_token, 0L)
})

# -- Shopify Secret --
test_that("detect_secrets finds Shopify secrets", {
  fake32 <- paste0(rep("a", 32), collapse = "")
  expect_length(detect_secrets(paste0("shpss_", fake32))$shopify_secret, 1L)
  fake32b <- paste0(rep("F", 32), collapse = "")
  expect_length(detect_secrets(paste0("shpss_", fake32b))$shopify_secret, 1L)
})

test_that("detect_secrets rejects non-Shopify-secrets", {
  expect_length(detect_secrets("shpss_short")$shopify_secret, 0L)
  expect_length(detect_secrets("no shopify secret")$shopify_secret, 0L)
})

# -- Shopify Custom App --
test_that("detect_secrets finds Shopify custom app tokens", {
  fake32 <- paste0(rep("a", 32), collapse = "")
  expect_length(detect_secrets(paste0("shpca_", fake32))$shopify_custom_app, 1L)
})

test_that("detect_secrets rejects non-Shopify-custom-app-tokens", {
  expect_length(detect_secrets("shpca_short")$shopify_custom_app, 0L)
  expect_length(detect_secrets("no shopify custom")$shopify_custom_app, 0L)
})

# -- Shopify Private App --
test_that("detect_secrets finds Shopify private app tokens", {
  fake32 <- paste0(rep("a", 32), collapse = "")
  expect_length(detect_secrets(paste0("shppa_", fake32))$shopify_private_app, 1L)
})

test_that("detect_secrets rejects non-Shopify-private-app-tokens", {
  expect_length(detect_secrets("shppa_short")$shopify_private_app, 0L)
  expect_length(detect_secrets("no shopify private")$shopify_private_app, 0L)
})

# -- JWT --
# NOTE: Tokens constructed via paste0() to avoid triggering GitHub push protection
test_that("detect_secrets finds JWTs", {
  jwt1 <- paste0("eyJhbGciOiJIUzI1", "NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456_-ghi")
  jwt2 <- paste0("eyJhbGciOiJSUzI1", "NiJ9.eyJpc3MiOiJ0ZXN0In0.QRSTUVWXYZ0123456789")
  jwt3 <- paste0("token: eyJhbGciOi", "JIUzI1NiJ9.eyJkYXRhIjoiZm9vIn0.sig_value_here")
  expect_length(detect_secrets(jwt1)$jwt, 1L)
  expect_length(detect_secrets(jwt2)$jwt, 1L)
  expect_length(detect_secrets(jwt3)$jwt, 1L)
})

test_that("detect_secrets rejects non-JWTs", {
  expect_length(detect_secrets("no jwt here")$jwt, 0L)
  expect_length(detect_secrets("eyX.eyY.sig")$jwt, 0L)
  expect_length(detect_secrets("just.two.parts.not.jwt")$jwt, 0L)
})

# -- Cloudinary URL --
test_that("detect_secrets finds Cloudinary URLs", {
  expect_length(
    detect_secrets("cloudinary://123456789:abcDEF_ghiJKL@my_cloud")$cloudinary_url,
    1L
  )
  expect_length(
    detect_secrets("cloudinary://999999:secret-key_123@cloud-name")$cloudinary_url,
    1L
  )
})

test_that("detect_secrets rejects non-Cloudinary-URLs", {
  expect_length(detect_secrets("cloudinary://invalid")$cloudinary_url, 0L)
  expect_length(detect_secrets("no cloudinary url")$cloudinary_url, 0L)
})

# -- Firebase URL --
test_that("detect_secrets finds Firebase URLs", {
  expect_length(detect_secrets("https://my-project.firebaseio.com")$firebase_url, 1L)
  expect_length(detect_secrets("https://test-app-123.firebaseio.com")$firebase_url, 1L)
  expect_length(detect_secrets("url: https://prod_db.firebaseio.com")$firebase_url, 1L)
})

test_that("detect_secrets rejects non-Firebase-URLs", {
  expect_length(detect_secrets("https://example.com")$firebase_url, 0L)
  expect_length(detect_secrets("no firebase url")$firebase_url, 0L)
  expect_length(detect_secrets("http://test.firebase.com")$firebase_url, 0L)
})

# -- PostgreSQL Connection --
test_that("detect_secrets finds PostgreSQL connection strings", {
  expect_length(
    detect_secrets("postgres://user:pass@host:5432/dbname")$postgres_conn,
    1L
  )
  expect_length(
    detect_secrets("postgresql://admin:secret@localhost/mydb")$postgres_conn,
    1L
  )
  expect_length(
    detect_secrets("conn: postgres://user:p@ss@db.example.com:5432/prod")$postgres_conn,
    1L
  )
})

test_that("detect_secrets rejects non-PostgreSQL-connections", {
  expect_length(detect_secrets("postgres://short")$postgres_conn, 0L)
  expect_length(detect_secrets("no postgres here")$postgres_conn, 0L)
})

# -- MySQL Connection --
test_that("detect_secrets finds MySQL connection strings", {
  expect_length(
    detect_secrets("mysql://user:pass@host:3306/dbname")$mysql_conn,
    1L
  )
  expect_length(
    detect_secrets("mysql://admin:secret@localhost/mydb")$mysql_conn,
    1L
  )
})

test_that("detect_secrets rejects non-MySQL-connections", {
  expect_length(detect_secrets("mysql://short")$mysql_conn, 0L)
  expect_length(detect_secrets("no mysql here")$mysql_conn, 0L)
})

# -- MongoDB Connection --
test_that("detect_secrets finds MongoDB connection strings", {
  expect_length(
    detect_secrets("mongodb://user:pass@host:27017/dbname")$mongodb_conn,
    1L
  )
  expect_length(
    detect_secrets("mongodb+srv://admin:secret@cluster0.abc12.mongodb.net/mydb")$mongodb_conn,
    1L
  )
})

test_that("detect_secrets rejects non-MongoDB-connections", {
  expect_length(detect_secrets("mongodb://short")$mongodb_conn, 0L)
  expect_length(detect_secrets("no mongodb here")$mongodb_conn, 0L)
})

# -- Redis Connection --
test_that("detect_secrets finds Redis connection strings", {
  expect_length(
    detect_secrets("redis://user:pass@host:6379/0")$redis_conn,
    1L
  )
  expect_length(
    detect_secrets("redis://:password@redis.example.com:6379")$redis_conn,
    1L
  )
})

test_that("detect_secrets rejects non-Redis-connections", {
  expect_length(detect_secrets("redis://short")$redis_conn, 0L)
  expect_length(detect_secrets("no redis here")$redis_conn, 0L)
})

# -- Facebook Access Token --
test_that("detect_secrets finds Facebook access tokens", {
  fake100 <- paste0(rep("A", 100), collapse = "")
  expect_length(detect_secrets(paste0("EAA", fake100))$facebook_access_token, 1L)
  fake120 <- paste0(rep("x", 120), collapse = "")
  expect_length(detect_secrets(paste0("EAA", fake120))$facebook_access_token, 1L)
})

test_that("detect_secrets rejects non-Facebook-access-tokens", {
  expect_length(detect_secrets("EAAshort")$facebook_access_token, 0L)
  expect_length(detect_secrets("no facebook token")$facebook_access_token, 0L)
})

# -- Amazon MWS Token --
test_that("detect_secrets finds Amazon MWS tokens", {
  expect_length(
    detect_secrets("amzn.mws.12345678-abcd-ef01-2345-678901234567")$amazon_mws_token,
    1L
  )
  expect_length(
    detect_secrets("amzn.mws.aabbccdd-1122-3344-5566-778899aabbcc")$amazon_mws_token,
    1L
  )
})

test_that("detect_secrets rejects non-Amazon-MWS-tokens", {
  expect_length(detect_secrets("amzn.mws.short")$amazon_mws_token, 0L)
  expect_length(detect_secrets("no amazon mws")$amazon_mws_token, 0L)
})

# -- API / edge cases (original) --
test_that("detect_secrets validates text argument", {
  expect_error(detect_secrets(42), "single character string")
  expect_error(detect_secrets(c("a", "b")), "single character string")
})

test_that("detect_secrets filters by types", {
  result <- detect_secrets("AKIAIOSFODNN7EXAMPLE", types = "aws_key")
  expect_named(result, "aws_key")
  expect_length(result$aws_key, 1L)
})

test_that("detect_secrets rejects unknown types", {
  expect_error(detect_secrets("test", types = "ssh_key"), "Unknown secret type")
})

test_that("detect_secrets returns empty for clean text", {
  result <- detect_secrets("This is clean text with no secrets at all.")
  for (nm in names(result)) {
    expect_length(result[[nm]], 0L)
  }
})
