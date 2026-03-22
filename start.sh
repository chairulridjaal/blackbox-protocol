#!/bin/bash
source /home/ubuntu/blackbox-protocol/venv/bin/activate
set -e
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

echo "[4/4] Starting fuzzer..."
echo "      Press Ctrl+C to stop all processes"
trap "kill $XVFB_PID $API_PID $DASH_PID 2>/dev/null; echo 'Stopped.'" EXIT
mkdir -p logs
if [ -f logs/fuzzer.log ] && \
   [ $(stat -c%s logs/fuzzer.log 2>/dev/null || echo 0) \
     -gt 52428800 ]; then
  mv logs/fuzzer.log logs/fuzzer.$(date +%Y%m%d_%H%M%S).log
  echo "Log rotated" > logs/fuzzer.log
fi
python3 main.py 2>&1 | tee -a logs/fuzzer.log
