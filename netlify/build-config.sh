#!/usr/bin/env bash
# Generates js/config.js at deploy time from Netlify environment variables.
#
# Set these in Netlify -> Site configuration -> Environment variables:
#   CALMIO_SUPABASE_URL       https://yourproject.supabase.co
#   CALMIO_SUPABASE_ANON_KEY  the long "anon / public" key
#
# If they are not set, the js/config.js committed in the repo is left
# untouched, so nothing breaks and the site stays in demo mode.
#
# Note: the anon key is PUBLIC by design - it ends up in the browser
# either way. Using env vars here is about convenience (changing projects
# without a commit), not secrecy. The service-role key must NEVER be put
# in these two variables; it belongs only in the function environment.

set -euo pipefail

URL="${CALMIO_SUPABASE_URL:-}"
KEY="${CALMIO_SUPABASE_ANON_KEY:-}"

if [ -z "$URL" ] || [ -z "$KEY" ]; then
  echo "build-config: CALMIO_SUPABASE_* not set - keeping js/config.js as committed (demo mode unless the file already has values)."
  exit 0
fi

case "$URL" in
  https://*) ;;
  *) echo "build-config: CALMIO_SUPABASE_URL must start with https:// (got '$URL')"; exit 1 ;;
esac

cat > js/config.js <<EOF
/* Generated at deploy time by netlify/build-config.sh - do not edit.
   Values come from the CALMIO_SUPABASE_* environment variables. */
window.CALMIO_REMOTE = {
  url: "${URL}",
  anonKey: "${KEY}"
};
EOF

echo "build-config: multi-user mode enabled for ${URL}"
