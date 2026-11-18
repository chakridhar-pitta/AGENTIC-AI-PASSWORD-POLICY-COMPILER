@echo off
cd /d "%~dp0"
echo [BUILDING] Compiling C++ Password Policy Compiler (7 Specialized Agents)...
g++ -std=c++14 -O2 -I src src/*.cpp -o policy_compiler.exe
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Compilation failed.
    exit /b %ERRORLEVEL%
)
echo [RUNNING] Executing policy_compiler on tests/policy_dsl2.txt...
policy_compiler.exe tests/policy_dsl2.txt
