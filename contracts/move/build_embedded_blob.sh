#!/bin/bash
# Build blob for embedded node testing
# This script:
# 1. Reads address from embeded-node-constant-blob/config.json
# 2. Updates Move.toml with the address
# 3. Runs mpm release to generate blob
# 4. Copies the blob to embeded-node-constant-blob/
# 5. Restores Move.toml

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CONFIG_FILE="embeded-node-constant-blob/config.json"
MOVE_TOML="Move.toml"
RELEASE_DIR="release"
OUTPUT_DIR="embeded-node-constant-blob"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file not found: $CONFIG_FILE"
    exit 1
fi

if [ -z "$MPM_PATH" ]; then
    echo "Error: MPM_PATH environment variable is not set"
    echo "Please set it to the path of your mpm binary"
    exit 1
fi

ADDRESS=$(grep -o '"address"[[:space:]]*:[[:space:]]*"[^"]*"' "$CONFIG_FILE" | sed 's/"address"[[:space:]]*:[[:space:]]*"\([^"]*\)"/\1/')

if [ -z "$ADDRESS" ]; then
    echo "Error: Could not extract address from $CONFIG_FILE"
    exit 1
fi

echo "Using address: $ADDRESS"

cp "$MOVE_TOML" "${MOVE_TOML}.bak"
echo "Backed up Move.toml"

sed -i '' "s/^Bridge = \"0x[a-fA-F0-9]*\"/Bridge = \"$ADDRESS\"/" "$MOVE_TOML"
echo "Updated Move.toml with address: $ADDRESS"

echo "Running mpm release..."
"$MPM_PATH" release

BLOB_FILE=$(ls -1 "$RELEASE_DIR"/*.blob 2>/dev/null | head -n 1)
if [ -z "$BLOB_FILE" ]; then
    echo "Error: No blob file found in $RELEASE_DIR"
    mv "${MOVE_TOML}.bak" "$MOVE_TOML"
    exit 1
fi

cp "$BLOB_FILE" "$OUTPUT_DIR/"
echo "Copied blob to $OUTPUT_DIR/"

mv "${MOVE_TOML}.bak" "$MOVE_TOML"
echo "Restored Move.toml"

echo "Done! Blob file created in $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR"/*.blob
