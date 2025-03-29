#!/usr/bin/env bash

set -eu
version="$1"
commit_msg="Release v$version"

check-git-dirty() {
  CHANGES=$(git status --porcelain | wc -l)
  if [ "$CHANGES" -gt "0" ]; then
    echo "Git is dirty. Commit all changes before doing a release"
    git status --porcelain
    exit 1
  fi
}

check-git-dirty
poetry version $version
git add pyproject.toml
git commit -m "$commit_msg"
git tag $version
git push origin && git push origin --tags
git push gh && git push gh --tags
