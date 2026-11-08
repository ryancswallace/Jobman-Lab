#!/usr/bin/env bash
# Shared scalar access; callers retain their own shell policy.
lab_config_value() {
  local config_script_root
  config_script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  "${JOBMAN_CONFIG_PYTHON:-python3}" "$config_script_root/scripts/lab-config.py" get "$@"
}
