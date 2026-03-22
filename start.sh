#!/bin/bash
set -e
source /home/ubuntu/blackbox-protocol/venv/bin/activate
echo "==== Blackbox Protocol — Linux Startup ===="

echo "[1/4] Starting Xvfb..."
Xvfb :99 -screen 0 1920x1080x24 -ac +extension GLX +render -noreset &
XVFB_PID=$!
sleep 1
export DISPLAY=:99
echo "      Xvfb PID: $XVFB_PID"

echo "[2/4] Starting API server..."
python3 api.py &
API_PID=$!
sleep 1

echo "[3/4] Starting dashboard..."
cd dashboard && npm run dev &
DASH_PID=$!
cd ..
sleep 2

echo ""
echo "==== Ready! Now run in a new tmux window: ===="
echo "cd ~/blackbox-protocol && source venv/bin/activate && python3 main.py 2>&1 | tee -a logs/fuzzer.log"
echo ""
