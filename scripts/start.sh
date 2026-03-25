#!/bin/bash
set -e
source /home/ubuntu/blackbox-protocol/venv/bin/activate
echo "==== Blackbox Protocol — Linux Startup ===="

echo "[1/5] Starting Xvfb..."
Xvfb :99 -screen 0 1920x1080x24 -ac +extension GLX +render -noreset &
XVFB_PID=$!
sleep 1
export DISPLAY=:99
echo "      Xvfb PID: $XVFB_PID"

echo "[2/5] Starting API server..."
python3 api.py &
API_PID=$!
sleep 1

echo "[3/5] Starting crash verifier..."
python3 verify.py >> logs/verifier.log 2>&1 &
VERIFY_PID=$!
sleep 1
echo "      Verifier PID: $VERIFY_PID"

echo "[4/5] Starting dashboard..."
cd dashboard && npm run dev &
DASH_PID=$!
cd ..
sleep 2

trap "kill $XVFB_PID $API_PID $VERIFY_PID $DASH_PID 2>/dev/null; exit" INT TERM

echo ""
echo "==== Ready! Now run in a new tmux window: ===="
echo "cd ~/blackbox-protocol && source venv/bin/activate && python3 main.py 2>&1 | tee -a logs/fuzzer.log"
echo ""
echo "Services running:"
echo "  Xvfb:     PID $XVFB_PID (display :99)"
echo "  API:      PID $API_PID (port 6767)"
echo "  Verifier: PID $VERIFY_PID (watching crashes/)"
echo "  Dashboard: PID $DASH_PID (port 6868)"
echo ""
echo "Press Ctrl+C to stop all services."
wait
