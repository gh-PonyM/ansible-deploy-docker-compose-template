#!/usr/bin/env bash

set -eu
version="$1"
commit_msg="Release v$version"

CHANGES=$(git status --porcelain | wc -l)
if [ "$CHANGES" -gt "0" ]; then
  echo "Git is dirty. Commit all changes before doing a release"
  git status --porcelain
  exit 1
fi

poetry version $version
sed -e "s/version: [0-9]\+\.[0-9]\+\.[0-9]\+/version: $version/g" README.md
poetry export -n -o scripts/requirements.txt
git add .
git commit -m "$commit_msg"
git tag $version
git push origin && git push origin --tags
git push gh && git push gh --tags
