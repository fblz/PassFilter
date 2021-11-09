#pragma once
// Der folgende ifdef-Block ist die Standardmethode zum Erstellen von Makros, die das Exportieren
// aus einer DLL vereinfachen. Alle Dateien in dieser DLL werden mit dem PASSFILTER_EXPORTS-Symbol
// (in der Befehlszeile definiert) kompiliert. Dieses Symbol darf für kein Projekt definiert werden,
// das diese DLL verwendet. Alle anderen Projekte, deren Quelldateien diese Datei beinhalten, sehen
// PASSFILTER_API-Funktionen als aus einer DLL importiert an, während diese DLL
// mit diesem Makro definierte Symbole als exportiert ansieht.
#ifdef PASSFILTER_EXPORTS
#define PASSFILTER_API __declspec(dllexport)
#else
#define PASSFILTER_API __declspec(dllimport)
#endif

#include "framework.h"

extern "C" PASSFILTER_API BOOLEAN __stdcall PasswordFilter(PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, BOOLEAN);