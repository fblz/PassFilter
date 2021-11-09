#pragma once

#define WIN32_LEAN_AND_MEAN             // Selten verwendete Komponenten aus Windows-Headern ausschließen
// Windows-Headerdateien
#include <windows.h>
#include <SubAuth.h>
#include <winreg.h>
#include <stdio.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#include <fstream>
#include <cstring>