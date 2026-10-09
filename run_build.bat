@echo off
REM Offline export only; no execution-policy bypass.
python "%~dp0generate_dataset.py" %*
exit /b %errorlevel%
