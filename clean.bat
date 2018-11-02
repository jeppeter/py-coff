
echo off
set filename=%~f0
for %%F in ("%filename%") do set script_dir=%%~dpF

rmdir /Q /S %script_dir%dist 2>NUL
rmdir /Q /S %script_dir%coff 2>NUL

rmdir /Q /S %script_dir%__pycache__ 2>NUL
rmdir /Q /S %script_dir%src\coff\__pycache__ 2>NUL
rmdir /Q /S %script_dir%coff.egg-info 2>NUL
del %script_dir%setup.py 2>NUL

echo on