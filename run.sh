#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$HOME/TeamSwipe"
APP_FILE="TeamSwipe.py"
PYTHON_BIN="${PYTHON_BIN:-python3.12}"
VENV_DIR="$APP_DIR/.venv"
PY="$VENV_DIR/bin/python"
REQ_FILE="requirement.txt"
LOG_FILE="$APP_DIR/log.txt"

cd "$APP_DIR"

echo "Deploying TeamSwipe from $APP_DIR"

if [ ! -d "$VENV_DIR" ]; then
  echo "Creating virtual environment..."
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

echo "Installing dependencies..."
"$PY" -m pip install --upgrade pip
"$PY" -m pip install -r "$REQ_FILE"

echo "Stopping existing TeamSwipe process if running..."
pkill -f "$PY $APP_FILE" || true
pkill -f "$PYTHON_BIN $APP_FILE" || true

echo "Starting TeamSwipe..."
nohup "$PY" "$APP_FILE" > "$LOG_FILE" 2>&1 &

sleep 2

if pgrep -f "$PY $APP_FILE" > /dev/null; then
  echo "TeamSwipe started successfully."
  echo "View logs with: tail -n 200 -f $LOG_FILE"
else
  echo "TeamSwipe did not stay running. Check logs:"
  echo "tail -n 200 $LOG_FILE"
  exit 1
fi
