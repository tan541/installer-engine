#!/usr/bin/env bash
# ==============================================================================
# Installer Engine Endpoint Agent Management Script (macOS & Linux)
# ==============================================================================
# Description:
#   Utility script to build and execute Installer Engine operations across
#   macOS (>15) and Linux (>13) systems.
#
# Usage:
#   ./scripts/run_agent.sh [COMMAND] [OPTIONS]
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_BIN="${ROOT_DIR}/target/release/installer-agent"

# Default Configurations
ORG_ID="${ORG_ID:-1}"
DEVICE_ID="${DEVICE_ID:-}"
CONTROL_PLANE_URL="${CONTROL_PLANE_URL:-}"
POLL_INTERVAL="${POLL_INTERVAL:-10}"
ALLOW_NON_ROOT="${ALLOW_NON_ROOT:-false}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

# Ensure release binary is compiled and up to date
build_agent() {
    if [[ ! -f "${TARGET_BIN}" ]]; then
        log_info "Binary not found. Building installer-agent in release mode..."
        (cd "${ROOT_DIR}" && cargo build --release --bin installer-agent)
        log_success "Build complete: ${TARGET_BIN}"
    fi
}

# Helper to execute the binary with appropriate root privileges if necessary
run_binary() {
    local needs_root=true
    local cmd=("$TARGET_BIN")

    # If --allow-non-root or unprivileged mode is requested
    if [[ "$ALLOW_NON_ROOT" == "true" ]]; then
        cmd+=("--allow-non-root")
        needs_root=false
    fi

    if [[ -n "$ORG_ID" ]]; then
        cmd+=("--org-id" "$ORG_ID")
    fi

    if [[ -n "$DEVICE_ID" ]]; then
        cmd+=("--device-id" "$DEVICE_ID")
    fi

    if [[ -n "$CONTROL_PLANE_URL" ]]; then
        cmd+=("--control-plane-url" "$CONTROL_PLANE_URL")
    fi

    # Append command-specific arguments
    cmd+=("$@")

    if [[ "$needs_root" == "true" && "$(id -u)" -ne 0 ]]; then
        log_info "Elevating with sudo to run administrative installer engine..."
        exec sudo "${cmd[@]}"
    else
        exec "${cmd[@]}"
    fi
}

print_usage() {
    cat <<EOF
Installer Engine Agent CLI Runner (macOS & Linux)

Usage:
  ./scripts/run_agent.sh <command> [arguments...]

Commands:
  inventory                Scan and display installed software inventory table
  inventory-json           Scan and export installed software inventory as JSON
  sync-inventory           Scan and synchronize installed apps directly with Control Plane
  test-block <app_name>    Evaluate application name against security blocklist / allowlist policies
  install <pkg_path>       Install a local package (.pkg, .deb, .rpm) and verify installation
  daemon                   Start endpoint agent daemon loop (polls tasks & real-time app blocker)
  one-shot                 Poll Control Plane once, execute pending tasks, and exit
  build                    Compile/recompile release binary

Environment Variables:
  ORG_ID                  Organization ID (default: 1)
  DEVICE_ID               Device Identifier (default: endpoint-<hostname>)
  CONTROL_PLANE_URL       Control plane HTTP endpoint (if omitted, uses embedded mock service)
  POLL_INTERVAL           Daemon polling interval in seconds (default: 10)
  ALLOW_NON_ROOT          Set to 'true' to allow running without sudo for testing

Examples:
  ./scripts/run_agent.sh inventory
  ./scripts/run_agent.sh test-block "uTorrent"
  ./scripts/run_agent.sh test-block "Microsoft Teams"
  ./scripts/run_agent.sh install "data/ShieldNet 360-1.6.0-arm64.pkg"
  ./scripts/run_agent.sh daemon
EOF
}

# Main Command Dispatcher
COMMAND="${1:-}"

if [[ -z "$COMMAND" || "$COMMAND" == "-h" || "$COMMAND" == "--help" ]]; then
    print_usage
    exit 0
fi

shift || true

case "$COMMAND" in
    build)
        log_info "Rebuilding installer-agent release binary..."
        (cd "${ROOT_DIR}" && cargo build --release --bin installer-agent)
        log_success "Release binary ready at ${TARGET_BIN}"
        ;;

    inventory)
        build_agent
        ALLOW_NON_ROOT="true"
        run_binary "--inventory" "$@"
        ;;

    inventory-json)
        build_agent
        ALLOW_NON_ROOT="true"
        run_binary "--inventory" "--json" "$@"
        ;;

    sync-inventory)
        build_agent
        run_binary "--sync-inventory" "$@"
        ;;

    test-block)
        if [[ $# -lt 1 ]]; then
            log_error "Missing application name or target to test."
            echo "Usage: ./scripts/run_agent.sh test-block <app_name>"
            exit 1
        fi
        build_agent
        ALLOW_NON_ROOT="true"
        TARGET_APP="$1"
        shift
        run_binary "--test-block" "$TARGET_APP" "$@"
        ;;

    install)
        if [[ $# -lt 1 ]]; then
            log_error "Missing package path argument."
            echo "Usage: ./scripts/run_agent.sh install <path_to_pkg>"
            exit 1
        fi
        build_agent
        PKG_PATH="$1"
        shift
        run_binary "--pkg" "$PKG_PATH" "$@"
        ;;

    daemon)
        build_agent
        run_binary "--poll-interval" "$POLL_INTERVAL" "--enable-blocking" "$@"
        ;;

    one-shot)
        build_agent
        run_binary "--one-shot" "$@"
        ;;

    *)
        log_error "Unknown command: '$COMMAND'"
        print_usage
        exit 1
        ;;
esac
