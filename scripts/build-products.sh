#!/usr/bin/env bash
set -euo pipefail

lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="$lab_root/.lab/artifacts"
# shellcheck source=scripts/lab-config.sh
source "$lab_root/scripts/lab-config.sh"
jobman_repo="$(lab_config_value versions.products.jobman_repo --absolute)"
control_repo="$(lab_config_value versions.products.jobman_control_repo --absolute)"
toolchain="go$(lab_config_value versions.guest_software.go)"

mkdir -p "$artifact_root/bin/linux-arm64" "$artifact_root/bin/windows-arm64"

build_one() {
  local repo="$1" package="$2" goos="$3" output="$4"
  (
    cd "$repo"
    GOTOOLCHAIN="$toolchain" GOOS="$goos" GOARCH=arm64 CGO_ENABLED=0 \
      go build -trimpath -buildvcs=true -o "$output" "$package"
  )
}

build_one "$jobman_repo" . linux "$artifact_root/bin/linux-arm64/jobman"
build_one "$jobman_repo" ./cmd/jobman-agent linux "$artifact_root/bin/linux-arm64/jobman-agent"
build_one "$control_repo" . linux "$artifact_root/bin/linux-arm64/jobman-control"
build_one "$jobman_repo" . windows "$artifact_root/bin/windows-arm64/jobman.exe"
build_one "$jobman_repo" ./cmd/jobman-agent windows "$artifact_root/bin/windows-arm64/jobman-agent.exe"

git -C "$jobman_repo" rev-parse HEAD > "$artifact_root/jobman.commit"
git -C "$control_repo" rev-parse HEAD > "$artifact_root/jobman-control.commit"
(
  cd "$artifact_root"
  find bin -type f -print0 | sort -z | xargs -0 shasum -a 256
) > "$artifact_root/SHA256SUMS"

printf 'built product artifacts under %s\n' "$artifact_root"
