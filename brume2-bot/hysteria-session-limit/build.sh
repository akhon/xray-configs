#!/bin/sh
set -eu

# Mount public source only; never mount live router configs or keys.
commit=e1366b173ccf5706e1e4630fe8aa654a4b574085
image=docker.io/library/golang:1.26.8@sha256:eb36c1664dd974cde625f736e02c204383deebe03977365caaec5bf49f794348
package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output=${1:?Usage: build.sh /absolute/output/directory}
case "$output" in /*) ;; *) echo 'Output directory must be absolute.' >&2; exit 1;; esac
mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd)
test ! -e "$output/hysteria-linux-arm64"
task_dir=$(mktemp -d "${TMPDIR:-/tmp}/hysteria-session-limit.XXXXXX")
trap 'rm -rf "$task_dir"' EXIT
trap 'exit 1' HUP INT TERM
git clone --quiet --no-checkout https://github.com/apernet/hysteria.git "$task_dir/source"
git -C "$task_dir/source" checkout --quiet --detach "$commit"
git -C "$task_dir/source" apply --check "$package_dir/session-limit.patch"
git -C "$task_dir/source" apply "$package_dir/session-limit.patch"
docker run --rm -v "$task_dir/source:/src" -v "$output:/out" -w /src "$image" sh -ec '
    go test -race -short ./core/... ./app/cmd
    go test -race ./extras/auth -run "Test(Password|UserPass)Authenticator"
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false \
      -ldflags="-s -w -buildid= -X github.com/apernet/hysteria/app/v2/cmd.appVersion=v2.12.3-session-limit.1 -X github.com/apernet/hysteria/app/v2/cmd.appDate=2026-11-08T00:00:00Z -X github.com/apernet/hysteria/app/v2/cmd.appType=custom -X github.com/apernet/hysteria/app/v2/cmd.appToolchain=go1.26.8 -X github.com/apernet/hysteria/app/v2/cmd.appCommit=e1366b173ccf5706e1e4630fe8aa654a4b574085 -X github.com/apernet/hysteria/app/v2/cmd.appPlatform=linux -X github.com/apernet/hysteria/app/v2/cmd.appArch=arm64 -X github.com/apernet/hysteria/app/v2/cmd.libVersion=v0.62.1-0.20260912175848-73339f7edbb9" \
      -o /out/hysteria-linux-arm64 ./app
    cd /out
    sha256sum hysteria-linux-arm64 > hysteria-linux-arm64.sha256
    # This build script runs natively on the target architecture (Apple Silicon Docker).
    ./hysteria-linux-arm64 version
'
