echo off
set filename=%~f0
for %%F in ("%filename%") do set script_dir=%%~dpF
echo %script_dir%

if -%PYTHON%- == -- (
	set PYTHON=python
)

echo "PYTHON [%PYTHON%]"

del /Q /F %script_dir%src\coff\__init__.py.touched 2>NUL

%PYTHON% %script_dir%make_setup.py


if EXIST %script_dir%coff (
	rmdir /s /q %script_dir%coff
)
mkdir %script_dir%coff

copy /y %script_dir%\src\coff\__init__.py %script_dir%coff\__init__.py
copy /Y %script_dir%README.md %script_dir%coff\README

echo on