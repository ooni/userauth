#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG_PREFIX="userauth"
YELLOW=$'\033[33m'
RESET=$'\033[0m'

if ! command -v git >/dev/null 2>&1; then
  echo "Error: git is required but was not found in PATH" >&2
  exit 1
fi

CURRENT_BRANCH="$(git -C "$ROOT_DIR" rev-parse --abbrev-ref HEAD)"
COMMIT_SHA="$(git -C "$ROOT_DIR" rev-parse --short HEAD)"
MAX_RELEASE_NUM="$(
  git -C "$ROOT_DIR" tag --list "${TAG_PREFIX}-*" \
    | awk -F '-' '
      $1 "-" $2 == "ooniauth-py" && $NF ~ /^[0-9]+$/ {
        if ($NF > max) max = $NF
      }
      END { print max + 0 }
    '
)"
NEXT_RELEASE_NUM=$((MAX_RELEASE_NUM + 1))
TAG_NAME="${TAG_PREFIX}-${COMMIT_SHA}-${NEXT_RELEASE_NUM}"

if git -C "$ROOT_DIR" rev-parse "$TAG_NAME" >/dev/null 2>&1; then
  echo "Error: tag $TAG_NAME already exists locally." >&2
  exit 1
fi

if git -C "$ROOT_DIR" ls-remote --tags origin "refs/tags/$TAG_NAME" | grep -q "$TAG_NAME"; then
  echo "Error: tag $TAG_NAME already exists on origin." >&2
  exit 1
fi

echo "Release tag preview:"
echo "  Tag scheme:     ${TAG_PREFIX}-<shortsha>-<release_number>"
echo "  Release number: $NEXT_RELEASE_NUM"
echo "  Tag:            ${YELLOW}${TAG_NAME}${RESET}"
echo "  Branch:         $CURRENT_BRANCH"
echo "  Commit:         $COMMIT_SHA"
echo
read -r -p "Create and push tag $TAG_NAME to origin? [y/N] " answer

case "$answer" in
  y|Y|yes|YES)
    git -C "$ROOT_DIR" tag -a "$TAG_NAME" -m "Release $TAG_NAME"
    git -C "$ROOT_DIR" push origin "$TAG_NAME"
    echo "Done: pushed $TAG_NAME"
    ;;
  *)
    echo "Aborted."
    exit 0
    ;;
esac
