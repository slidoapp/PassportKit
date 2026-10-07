#!/usr/bin/env bash
# PostToolUse hook: formats an edited Swift file with swift-format.
# Formatting must never block the agent, so this always exits 0.

file_path=$(jq -r '.tool_input.file_path // empty' 2>/dev/null)

if [[ "$file_path" == *.swift && -f "$file_path" ]]; then
    swift format format --in-place --configuration "$CLAUDE_PROJECT_DIR/.swift-format" "$file_path" >/dev/null 2>&1
fi

exit 0
