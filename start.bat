@echo off
echo Starting Firefox Fuzzer Stack...
echo.

echo [1/3] Starting API server...
start "Fuzzer API" cmd /k "python api.py"

echo [2/3] Starting dashboard...
cd dashboard
start "Fuzzer Dashboard" cmd /k "npm run dev"
cd ..

timeout /t 3 /nobreak > nul

echo [3/3] Starting fuzzer...
echo.
python main.py
