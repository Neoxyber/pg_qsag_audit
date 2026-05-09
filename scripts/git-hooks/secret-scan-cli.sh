#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────
# Q-SAG secret-scan CLI wrapper for pre-commit framework.
#
# Sourced library: scripts/git-hooks/lib/secret-scan.sh (unchanged, 33 patterns).
# This wrapper adapts the library's function-based API to the CLI form
# pre-commit expects: file paths as positional args, exit 0 (clean) or 1 (findings).
#
# Per ADR-0023 Layer 2 Path A1: pre-commit framework owns hooks; mature
# secret-scan library preserved verbatim, this thin shim provides the
# calling convention pre-commit needs without refactoring security code.
#
# Semantic shift from prior custom pre-commit/pre-push: scans full file
# content, not diff. Strictly stricter — secrets committed earlier and
# never removed will be flagged on every subsequent push until removed.
# This closes a previously-missed failure mode.
#
# Usage (by pre-commit framework, automatic):
#   secret-scan-cli.sh path/to/file1 path/to/file2 ...
#
# Usage (manual debugging):
#   pre-commit run qsag-secret-scan --all-files
#   bash scripts/git-hooks/secret-scan-cli.sh src/main.py
#
# Exit codes:
#   0 — all files clean (or no files scanned, e.g. all in path allowlist)
#   1 — one or more findings
#
# Bypass (NOT recommended): git commit/push --no-verify
# ─────────────────────────────────────────────────────────────────────────
set -eu

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

LIB="$REPO_ROOT/scripts/git-hooks/lib/secret-scan.sh"
if [ ! -f "$LIB" ]; then
  echo "[secret-scan-cli] FATAL: library missing at $LIB" >&2
  echo "[secret-scan-cli] Reinstall via: bash scripts/install-hooks.sh" >&2
  exit 1
fi

# shellcheck source=lib/secret-scan.sh
source "$LIB"

FINDINGS=0
FINDINGS_DETAIL=""
ALLOWLIST_REGEX=$(qsag_build_allowlist_regex)

# pre-commit framework passes file paths as positional args.
# If no files were passed (e.g. pre-commit invoked us with an empty file list),
# exit cleanly without doing work.
if [ "$#" -eq 0 ]; then
  exit 0
fi

for file in "$@"; do
  # Skip if file no longer exists (e.g. deleted in this commit).
  if [ ! -f "$file" ]; then
    continue
  fi

  # Read full file content. The library's qsag_scan_added_lines applies
  # path-allowlist filtering (QSAG_PATH_ALLOWLIST_REGEX) and content-
  # allowlist filtering (QSAG_CONTENT_ALLOWLIST) internally before pattern
  # matching. Files in tests/, docs/, policies/, migrations/versions/, etc.
  # are skipped at the path-allowlist layer.
  content=$(cat "$file" 2>/dev/null || true)

  if [ -z "$content" ]; then
    continue
  fi

  qsag_scan_added_lines "$file" "$content"
done

if [ "$FINDINGS" -gt 0 ]; then
  echo "" >&2
  echo "[secret-scan-cli] REJECTED: $FINDINGS potential secret(s) found." >&2
  echo "$FINDINGS_DETAIL" >&2
  echo "" >&2
  echo "[secret-scan-cli] To fix:" >&2
  echo "  1. ROTATE the secret with the provider (assume compromised)" >&2
  echo "  2. Remove the literal value from the file" >&2
  echo "  3. If genuine false positive: add the literal to QSAG_CONTENT_ALLOWLIST" >&2
  echo "     in scripts/git-hooks/lib/secret-scan.sh and document why in commit msg" >&2
  echo "" >&2
  echo "[secret-scan-cli] Bypass (NOT recommended): git commit/push --no-verify" >&2
  exit 1
fi

# Quiet on success — pre-commit framework prints '.....Passed' per hook.
exit 0
