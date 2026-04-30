#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG_PREFIX="userauth"
CYAN=$'\033[36m'
YELLOW=$'\033[33m'
RED=$'\033[31m'
RESET=$'\033[0m'

if ! command -v git >/dev/null 2>&1; then
  echo "Error: git is required but was not found in PATH" >&2
  exit 1
fi

CURRENT_BRANCH="$(git -C "$ROOT_DIR" rev-parse --abbrev-ref HEAD)"
COMMIT_SHA="$(git -C "$ROOT_DIR" rev-parse --short HEAD)"
MAX_RELEASE_NUM="$(
  git -C "$ROOT_DIR" tag --list "${TAG_PREFIX}-*" \
    | awk -v prefix="${TAG_PREFIX}-" '
      index($0, prefix) == 1 && match($0, /-([0-9]+)$/, m) {
        release_num = m[1] + 0
        if (release_num > max) max = release_num
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
echo "  Tag:            ${CYAN}${TAG_NAME}${RESET}"
if [[ "$CURRENT_BRANCH" == "main" ]]; then
  echo "  Branch:         $CURRENT_BRANCH"
else
  echo "  Branch:         ${RED}${CURRENT_BRANCH} (WARNING: not main)${RESET}"
fi
echo "  Commit:         $COMMIT_SHA"
echo
if [[ "$CURRENT_BRANCH" != "main" ]]; then
  printf "%b\n" "  ${YELLOW}WARNING: current branch is '$CURRENT_BRANCH' (not main): commit $COMMIT_SHA may not be on main${RESET}"
fi

read -r -p "Create and push tag ${CYAN} $TAG_NAME ${RESET} to origin? [y/N] " answer

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
