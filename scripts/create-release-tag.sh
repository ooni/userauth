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

CARGO_TOML="$ROOT_DIR/ooniauth-py/Cargo.toml"
if [[ ! -f "$CARGO_TOML" ]]; then
  echo "Error: expected $CARGO_TOML" >&2
  exit 1
fi

LOCAL_VERSION="$(awk -F '"' '/^version = "/ { print $2; exit }' "$CARGO_TOML")"
PYPI_VERSION="$(python3 - <<'PY'
import json
import urllib.request

url = "https://pypi.org/pypi/ooniauth-py/json"
with urllib.request.urlopen(url, timeout=20) as response:
    data = json.load(response)
print(data["info"]["version"])
PY
)"

if [[ -z "$LOCAL_VERSION" || -z "$PYPI_VERSION" ]]; then
  echo "Failed to parse local or PyPI version." >&2
  exit 1
fi

HIGHEST="$(printf '%s\n%s\n' "$PYPI_VERSION" "$LOCAL_VERSION" | sort -V | tail -n 1)"
if [[ "$LOCAL_VERSION" == "$PYPI_VERSION" || "$HIGHEST" != "$LOCAL_VERSION" ]]; then
  echo "Local ooniauth-py version must be greater than PyPI (bump ooniauth-py/Cargo.toml before releasing)." >&2
  echo "  Local: $LOCAL_VERSION" >&2
  echo "  PyPI:  $PYPI_VERSION" >&2
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
echo "  ooniauth-py:    $LOCAL_VERSION (PyPI: $PYPI_VERSION)"
echo
if [[ "$CURRENT_BRANCH" != "main" ]]; then
  printf "%b\n" "  ${YELLOW}WARNING: current branch is '$CURRENT_BRANCH' (not main): commit $COMMIT_SHA is not in main${RESET}"
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
