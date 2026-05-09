#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────
# Q-SAG secret-scanning library — source this from pre-commit / pre-push
# / CI workflows.
#
# Provides:
#   PATTERNS                      — array of "name|regex" pairs
#   CONTENT_ALLOWLIST             — array of substring markers
#   PATH_ALLOWLIST_REGEX          — POSIX-extended regex of paths to skip
#   REGEX_LITERAL_PATTERN         — markers for Python regex literal lines
#   qsag_build_allowlist_regex()  — joins CONTENT_ALLOWLIST into one regex
#   qsag_scan_added_lines()       — scans a string of added lines, mutates
#                                   FINDINGS and FINDINGS_DETAIL globals
#
# Required globals before sourcing:
#   None. Library defines what callers need.
#
# Required globals after sourcing, before calling qsag_scan_added_lines:
#   FINDINGS=0
#   FINDINGS_DETAIL=""
#
# Designed for: bash 4+, POSIX grep -E (no Perl regex).
# Zero third-party dependencies.
# ─────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────
# Path allowlist — files in these directories are NOT scanned at all.
# These directories contain placeholders, test fixtures, or content that
# legitimately includes credential-shaped strings.
# ─────────────────────────────────────────────────────────────────────────

QSAG_PATH_ALLOWLIST_REGEX='^(tests/|docs/|policies/|_backups/|scripts/audit/results/|scripts/git-hooks/lib/|\.gitleaks\.toml$|\.env\.example$|migrations/versions/|src/static/)'

# ─────────────────────────────────────────────────────────────────────────
# Content allowlist — added lines containing any of these substrings are
# skipped before pattern matching.
# ─────────────────────────────────────────────────────────────────────────

QSAG_CONTENT_ALLOWLIST=(
  'your_key'
  'your_token'
  'your_admin_key'
  'your_secret'
  'your_password'
  '<REDACTED>'
  'placeholder'
  'EXAMPLE'
  'X25519MLKEM768'
  'ML-KEM-768'
  'ML-KEM-512'
  'ML-DSA-44'
  'ML-DSA-65'
  'SLH-DSA'
  'SHAKE-128s'
  'NIST FIPS'
  # Tier 6.0.5: Squawk-via-Alembic wrapper uses a syntactically-valid but
  # semantically-fake postgres URL for offline-mode dialect detection.
  # The URL never connects (alembic --sql is offline). The .local TLD is
  # reserved (RFC 6762) and cannot resolve in production. Allowlist the
  # unique host substring so the URL passes secret-scan without
  # weakening the db_url_with_password pattern for real credentials.
  'dummy-not-real.local'
  'change-this-to'
  'change-in-production'
  'PatternFamily'
  'CREDENTIAL_ACCESS'
  'qsag_test_'
  'qsag_canary_'
  'qsag_abc'
  'CANARY-AGENT'
  'qsag-canary@neoxyber'
  '...your_'
  '<your-'
)

# Regex-literal markers — lines containing Python regex literals are
# almost always pattern-matching code, not secret leaks. Skip them.
QSAG_REGEX_LITERAL_PATTERN=' r"|r'\''|re\.compile\('

# ─────────────────────────────────────────────────────────────────────────
# Detection patterns. Each entry: "pattern_name|posix_extended_regex".
# Patterns must work in `grep -E` (POSIX). No `\s`, no `(?i)`.
# ─────────────────────────────────────────────────────────────────────────

QSAG_PATTERNS=(
  # Q-SAG-native patterns
  'qsag_agent_api_key|qsag_[a-f0-9]{64}'
  'qsag_admin_key|admin_[a-f0-9]{64}'
  'qsag_canary_internal|CANARY-[a-f0-9]{32}'
  'qsag_admin_keys_multi|ADMIN_KEYS[[:space:]]*=[[:space:]]*[\"'\'']?[A-Za-z0-9_-]+:admin_[a-f0-9]{64}'
  'qsag_secret_key_assignment|SECRET_KEY[[:space:]]*=[[:space:]]*[\"'\'']?[a-f0-9]{32,}[\"'\'']?'
  'qsag_admin_key_assignment|ADMIN_KEY[[:space:]]*=[[:space:]]*[\"'\'']?[A-Za-z0-9_-]{32,}[\"'\'']?'

  # Anthropic
  'anthropic_api_key|sk-ant-api[0-9]+-[A-Za-z0-9_-]{40,}'

  # OpenAI
  'openai_legacy_key|sk-[A-Za-z0-9]{48}'
  'openai_project_key|sk-proj-[A-Za-z0-9_-]{40,}'

  # GitHub
  'github_pat_classic|ghp_[A-Za-z0-9]{36}'
  'github_oauth|gho_[A-Za-z0-9]{36}'
  'github_user|ghu_[A-Za-z0-9]{36}'
  'github_server|ghs_[A-Za-z0-9]{36}'
  'github_refresh|ghr_[A-Za-z0-9]{36}'
  'github_finegrained|github_pat_[A-Za-z0-9_]{82,}'

  # Slack
  'slack_bot|xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]{20,}'
  'slack_user|xoxp-[0-9]+-[0-9]+-[0-9]+-[A-Za-z0-9]{20,}'
  'slack_webhook|hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24}'

  # AWS
  'aws_access_key_id|AKIA[0-9A-Z]{16}'

  # Stripe
  'stripe_secret_live|sk_live_[A-Za-z0-9]{24,}'
  'stripe_restricted_live|rk_live_[A-Za-z0-9]{24,}'

  # Twilio / Mailgun / SendGrid
  'twilio_sid|SK[a-f0-9]{32}'
  'mailgun_key|key-[a-f0-9]{32}'
  'sendgrid|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'

  # JWT (Supabase service-role / anon, generic)
  'jwt_token|eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'

  # Database URL with embedded password
  'db_url_with_password|postgres(ql)?://[^:]+:[^@[:space:]]{6,}@[A-Za-z0-9.-]+'

  # Bearer / Basic auth in code
  'bearer_token_literal|Bearer[[:space:]]+[A-Za-z0-9_.-]{40,}'
  'basic_auth_literal|Authorization:[[:space:]]*Basic[[:space:]]+[A-Za-z0-9+/=]{20,}'

  # URL-embedded credentials
  'url_embedded_credentials|https?://[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]{8,}@[A-Za-z0-9.-]+'

  # Password assignments
  'password_assignment|(^|[^a-z_])(password|passwd|pwd)[[:space:]]*[=:][[:space:]]*[\"'\''][^\"'\''[:space:]]{8,}[\"'\'']'
  'username_password_pair|username[[:space:]]*[=:][[:space:]]*[\"'\''][^\"'\'']{1,}[\"'\''].{0,40}password'

  # Private key headers
  'private_key_pem|-----BEGIN ([A-Z]+ )?PRIVATE KEY-----'
  'pgp_private_key|-----BEGIN PGP PRIVATE KEY BLOCK-----'

  # Generic secret assignments (case-insensitive via character classes)
  'generic_secret_assignment|([Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|[Aa][Pp][Ii][Kk][Ee][Yy]|[Ss][Ee][Cc][Rr][Ee][Tt][_-]?[Kk][Ee][Yy]|[Aa][Cc][Cc][Ee][Ss][Ss][_-]?[Tt][Oo][Kk][Ee][Nn]|[Aa][Uu][Tt][Hh][_-]?[Tt][Oo][Kk][Ee][Nn]|[Cc][Ll][Ii][Ee][Nn][Tt][_-]?[Ss][Ee][Cc][Rr][Ee][Tt]|[Pp][Rr][Ii][Vv][Aa][Tt][Ee][_-]?[Tt][Oo][Kk][Ee][Nn])[\"'\'']?[[:space:]]*[=:][[:space:]]*[\"'\''][A-Za-z0-9_/+=.-]{32,}[\"'\'']'
)

# ─────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────

# Build the joined allowlist regex from QSAG_CONTENT_ALLOWLIST.
# Echoes the regex string for the caller to capture.
qsag_build_allowlist_regex() {
  local regex
  regex=$(printf '%s|' "${QSAG_CONTENT_ALLOWLIST[@]}")
  # Strip trailing |
  echo "${regex%|}"
}

# Scan a string of added lines (typically from a `+` diff) for secret
# patterns. Mutates FINDINGS (count) and FINDINGS_DETAIL (formatted text)
# in the caller's scope.
#
# Args:
#   $1 — file path (for reporting)
#   $2 — added-lines content (newline-separated, no leading + signs)
#
# Caller must have set:
#   FINDINGS=0
#   FINDINGS_DETAIL=""
#   ALLOWLIST_REGEX=$(qsag_build_allowlist_regex)
qsag_scan_added_lines() {
  local file="$1"
  local content="$2"

  # Skip files matching path allowlist
  if echo "$file" | grep -qE -e "$QSAG_PATH_ALLOWLIST_REGEX"; then
    return 0
  fi

  if [ -z "$content" ]; then
    return 0
  fi

  # Filter out lines matching the content allowlist
  local filtered
  filtered=$(echo "$content" | grep -vE -e "$ALLOWLIST_REGEX" || true)
  # Filter out Python regex literal lines
  filtered=$(echo "$filtered" | grep -vE -e "$QSAG_REGEX_LITERAL_PATTERN" || true)

  if [ -z "$filtered" ]; then
    return 0
  fi

  # Run each pattern
  local entry pattern_name pattern_regex matches
  for entry in "${QSAG_PATTERNS[@]}"; do
    pattern_name="${entry%%|*}"
    pattern_regex="${entry#*|}"

    matches=$(echo "$filtered" | grep -nE -e "$pattern_regex" || true)

    if [ -n "$matches" ]; then
      while IFS= read -r match; do
        # Redact 8 chars + replace rest
        local redacted
        redacted=$(echo "$match" | sed -E 's/([A-Za-z0-9_+/=.-]{8})[A-Za-z0-9_+/=.-]+/\1<REDACTED>/g')
        # Truncate display
        if [ ${#redacted} -gt 200 ]; then
          redacted="${redacted:0:197}..."
        fi
        FINDINGS=$((FINDINGS + 1))
        FINDINGS_DETAIL="${FINDINGS_DETAIL}
  [${pattern_name}] in ${file}
    ${redacted}"
      done <<< "$matches"
    fi
  done
}
