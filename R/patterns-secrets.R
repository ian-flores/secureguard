#' Secret detection patterns
#'
#' Returns a named list of regex patterns for detecting secrets and credentials
#' in text. Covers ~40 secret types across cloud providers, SaaS platforms,
#' payment processors, package registries, version control, AI/ML services,
#' e-commerce, infrastructure, databases, and social platforms.
#'
#' @return A named list of character(1) regex patterns.
#' @keywords internal
#' @export
#' @examples
#' pats <- secret_patterns()
#' names(pats)
#' grepl(pats$aws_key, "AKIAIOSFODNN7EXAMPLE")
secret_patterns <- function() {
  list(
    # -- Original 6 --
    api_key = "(?i)api[_-]?key\\s*[:=]\\s*['\"]?[A-Za-z0-9_\\-]{20,}",
    aws_key = "(?:AKIA|ASIA)[A-Z0-9]{16}",
    password = "(?i)password\\s*[:=]\\s*['\"]?[^\\s'\"]{8,}",
    token = "(?i)(?:bearer|auth(?:orization)?)\\s*[:=]?\\s*['\"]?[A-Za-z0-9_\\-.]{20,}",
    private_key = "-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    github_token = "gh[pousr]_[A-Za-z0-9_]{36,}",

    # -- Cloud (8) --
    aws_secret_key = "(?i)aws[_\\s]?secret[_\\s]?(?:access[_\\s]?)?key[\\s]*[:=][\\s]*['\"]?[A-Za-z0-9/+=]{40}",
    gcp_api_key = "AIza[0-9A-Za-z\\-_]{35}",
    gcp_service_account = "\"type\"\\s*:\\s*\"service_account\"",
    google_oauth_token = "ya29\\.[0-9A-Za-z\\-_]+",
    azure_client_secret = "(?i)(?:azure|client)[_\\s]?secret[\\s]*[:=][\\s]*['\"]?[A-Za-z0-9~._\\-]{34,}",
    alibaba_access_key = "\\bLTAI[A-Za-z0-9]{20}\\b",
    digitalocean_token = "\\bdop_v1_[a-f0-9]{64}\\b",
    heroku_api_key = "(?i)heroku[\\s_]*(?:api[\\s_]*)?key[\\s]*[:=][\\s]*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",

    # -- SaaS/Messaging (8) --
    slack_bot_token = "xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}",
    slack_user_token = "xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}",
    slack_webhook = "https://hooks\\.slack\\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}",
    discord_token = "[MN][A-Za-z\\d]{23,}\\.[\\w-]{6}\\.[\\w-]{27,}",
    twilio_api_key = "SK[0-9a-fA-F]{32}",
    sendgrid_api_key = "SG\\.[A-Za-z0-9_\\-]{22}\\.[A-Za-z0-9_\\-]{43}",
    mailgun_api_key = "key-[0-9a-zA-Z]{32}",
    mailchimp_api_key = "[0-9a-f]{32}-us\\d{1,2}",

    # -- Payment (5) --
    stripe_api_key = "(?:sk|pk|rk)_(?:test|live)_[0-9a-zA-Z]{24,}",
    square_access_token = "sq0atp-[0-9A-Za-z\\-_]{22}",
    square_oauth_secret = "sq0csp-[0-9A-Za-z\\-_]{43}",
    paypal_braintree_token = "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
    plaid_api_token = "(?:access|client)-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",

    # -- Package Registries (4) --
    npm_token = "npm_[A-Za-z0-9]{36}",
    pypi_token = "pypi-[A-Za-z0-9_\\-]{50,}",
    nuget_api_key = "oy2[a-z0-9]{43}",
    rubygems_api_key = "rubygems_[0-9a-f]{48}",

    # -- Version Control (4) --
    github_fine_grained_pat = "github_pat_[A-Za-z0-9_]{82}",
    gitlab_pat = "glpat-[A-Za-z0-9\\-_]{20,}",
    gitlab_deploy_token = "gldt-[A-Za-z0-9\\-_]{20,}",
    bitbucket_app_password = "(?i)bitbucket[\\s_]*(?:app[\\s_]*)?password[\\s]*[:=][\\s]*['\"]?[A-Za-z0-9]{18,}",

    # -- AI/ML (3) --
    openai_api_key = "sk-(?:proj-)?[A-Za-z0-9]{20,}",
    anthropic_api_key = "sk-ant-(?:api03-)?[A-Za-z0-9\\-_]{90,}",
    anthropic_admin_key = "sk-ant-admin01-[A-Za-z0-9\\-_]{90,}",

    # -- E-commerce (4) --
    shopify_access_token = "shpat_[0-9a-fA-F]{32}",
    shopify_secret = "shpss_[0-9a-fA-F]{32}",
    shopify_custom_app = "shpca_[0-9a-fA-F]{32}",
    shopify_private_app = "shppa_[0-9a-fA-F]{32}",

    # -- Infrastructure (3) --
    jwt = "eyJ[A-Za-z0-9_-]*\\.eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_\\-]+",
    cloudinary_url = "cloudinary://[0-9]+:[A-Za-z0-9_\\-]+@[A-Za-z0-9_\\-]+",
    firebase_url = "https://[A-Za-z0-9_\\-]+\\.firebaseio\\.com",

    # -- Database (4) --
    postgres_conn = "postgres(?:ql)?://[^\\s'\"]{10,}",
    mysql_conn = "mysql://[^\\s'\"]{10,}",
    mongodb_conn = "mongodb(?:\\+srv)?://[^\\s'\"]{10,}",
    redis_conn = "redis://[^\\s'\"]{10,}",

    # -- Social (2) --
    facebook_access_token = "EAA[A-Za-z0-9]{100,}",
    amazon_mws_token = "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
  )
}

#' Detect secrets in text
#'
#' Scans text for secrets and credentials using regex patterns.
#'
#' @param text Character(1). The text to scan.
#' @param types Character vector of secret types to check. Defaults to all
#'   available types from [secret_patterns()]. See [secret_patterns()] for the
#'   full list of ~40 supported types.
#' @return A named list where each element is a character vector of matches
#'   found for that secret type. Empty character vectors indicate no matches.
#' @export
#' @examples
#' detect_secrets("API_KEY = 'sk_live_abc123def456ghi789jkl0'")
#' detect_secrets("AKIAIOSFODNN7EXAMPLE", types = "aws_key")
detect_secrets <- function(text, types = NULL) {
  if (!is_string(text)) {
    cli_abort("{.arg text} must be a single character string.")
  }

  all_patterns <- secret_patterns()

  if (is.null(types)) {
    types <- names(all_patterns)
  } else {
    if (!is.character(types)) {
      cli_abort("{.arg types} must be a character vector.")
    }
    unknown <- setdiff(types, names(all_patterns))
    if (length(unknown) > 0L) {
      cli_abort("Unknown secret type{?s}: {.val {unknown}}.")
    }
  }

  patterns <- all_patterns[types]
  results <- lapply(patterns, function(pat) {
    m <- gregexpr(pat, text, perl = TRUE)
    regmatches(text, m)[[1L]]
  })

  results
}
