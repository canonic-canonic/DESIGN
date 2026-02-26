#!/bin/bash
# sync-secrets.sh — push .secrets → wrangler secret put
# Governed by CANON.md config table. MAGIC enforced.

SECRETS_FILE="$(dirname "$0")/.secrets"

if [ ! -f "$SECRETS_FILE" ]; then
  echo "ERROR: $SECRETS_FILE not found"
  exit 1
fi

COUNT=0
while IFS= read -r line; do
  # Allow comments/blank lines; allow values containing '='.
  [[ -z "${line//[[:space:]]/}" || "$line" =~ ^[[:space:]]*# ]] && continue
  [[ "$line" != *"="* ]] && continue

  key="${line%%=*}"
  value="${line#*=}"
  # Trim whitespace + surrounding quotes.
  key="$(printf '%s' "$key" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
  value="$(printf '%s' "$value" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g; s/^\"(.*)\"$/\\1/; s/^\\x27(.*)\\x27$/\\1/')"

  [[ -z "$key" || "$key" =~ ^# ]] && continue
  [[ -z "$value" ]] && { echo "SKIP: $key (empty)"; continue; }

  # Wrangler reads the secret value from stdin.
  printf '%s' "$value" | wrangler secret put "$key" --name canonic-services >/dev/null
  COUNT=$((COUNT + 1))
done < "$SECRETS_FILE"

echo "SYNCED: $COUNT secrets → canonic-services"
