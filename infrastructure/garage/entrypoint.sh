#!/bin/sh
# First-boot bootstrap for Garage, then run the server in the foreground.
#
# Garage has no env-driven "create these buckets with this root user" story
# like MinIO did -- it needs: a cluster layout (even for 1 node), an access
# key imported with specific id/secret, buckets created, and per-bucket
# key grants. All of that has to happen locally, in the same container as the
# running server (the admin CLI resolves its own node identity from the local
# metadata_dir -- a separate init container has no way to do this without
# already knowing the node ID). Every step below is written to be safe to
# run again on container restart.
set -eu

: "${MINIO_ACCESS_KEY:?MINIO_ACCESS_KEY not set}"
: "${MINIO_SECRET_KEY:?MINIO_SECRET_KEY not set}"

BUCKETS="screenshots evidence reports exports"

garage server &
SERVER_PID=$!
trap 'echo "[garage-entrypoint] stopping..."; kill -TERM "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID"' TERM INT

echo "[garage-entrypoint] waiting for garage to come up..."
i=0
until garage status >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 60 ]; then
    echo "[garage-entrypoint] garage did not become ready in time" >&2
    exit 1
  fi
  sleep 1
done

# --- cluster layout (one-shot: only before any role has ever been assigned) ---
if garage status 2>&1 | grep -q "NO ROLE ASSIGNED"; then
  echo "[garage-entrypoint] assigning single-node layout..."
  NODE_ID=$(garage node id -q | cut -d'@' -f1)
  garage layout assign -z dc1 -c 100G "$NODE_ID"
  garage layout apply --version 1
else
  echo "[garage-entrypoint] layout already assigned, skipping."
fi

# --- app access key (import is one-shot: re-importing an existing id errors) ---
if ! garage key info "$MINIO_ACCESS_KEY" >/dev/null 2>&1; then
  echo "[garage-entrypoint] importing app access key..."
  garage key import "$MINIO_ACCESS_KEY" "$MINIO_SECRET_KEY" --yes -n asm-app
else
  echo "[garage-entrypoint] app access key already imported, skipping."
fi

# --- buckets + per-key grants (safe to re-run: ignore "already exists") ---
for b in $BUCKETS; do
  garage bucket create "$b" >/dev/null 2>&1 || true
  garage bucket allow --read --write --key "$MINIO_ACCESS_KEY" "$b"
done

# screenshots is served anonymously through nginx's /storage/screenshots/
# proxy -- this is Garage's equivalent of MinIO's `mc anonymous set download`.
garage bucket website --allow screenshots

echo "[garage-entrypoint] bootstrap complete, garage server running (pid $SERVER_PID)."
wait "$SERVER_PID"
