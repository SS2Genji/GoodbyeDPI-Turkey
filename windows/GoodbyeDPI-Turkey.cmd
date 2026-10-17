@ECHO OFF
SETLOCAL EnableDelayedExpansion
PUSHD "%~dp0"

:: ============================================================================
:: GoodbyeDPI-Turkey Unified Smart Launcher & Auto-ISP Probe
:: ============================================================================

:: 1. Detect CPU Architecture (x86 vs x86_64)
SET "_arch=x86"
IF "%PROCESSOR_ARCHITECTURE%"=="AMD64" SET "_arch=x86_64"
IF DEFINED PROCESSOR_ARCHITEW6432 SET "_arch=x86_64"
SET "GDPI_EXE=%~dp0%_arch%\goodbyedpi.exe"

:: 2. Define Turkish ISP Profiles (0 = Standard, 1..6 = Superonline / Alternative)
SET "DNS_ARGS=--dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253"

SET "PROF_0_NAME=Standart Turkiye (Turk Telekom / TurkNet / Kablonet)"
SET "PROF_0_ARGS=-5 --set-ttl 5 %DNS_ARGS%"

SET "PROF_1_NAME=Alternatif 1 (Superonline - Sadece TTL 3)"
SET "PROF_1_ARGS=--set-ttl 3"

SET "PROF_2_NAME=Alternatif 2 (Superonline - Mod -5 Auto-TTL)"
SET "PROF_2_ARGS=-5"

SET "PROF_3_NAME=Alternatif 3 (Superonline - TTL 3 + Yandex DNS)"
SET "PROF_3_ARGS=--set-ttl 3 %DNS_ARGS%"

SET "PROF_4_NAME=Alternatif 4 (Superonline - Mod -5 + Yandex DNS)"
SET "PROF_4_ARGS=-5 %DNS_ARGS%"

SET "PROF_5_NAME=Alternatif 5 (Modern Mod -9 + Yandex DNS - En Az Site Bozan)"
SET "PROF_5_ARGS=-9 %DNS_ARGS%"

SET "PROF_6_NAME=Alternatif 6 (Modern Mod -9 Sadece)"
SET "PROF_6_ARGS=-9"

:: 3. Auto-Elevation Check (Administrator Privileges Required for WinDivert & SC)
net session >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO [!] Yonetici yetkisi gerekiyor, otomatik yetki yükseltiliyor...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    POPD
    EXIT /B
)

:: 4. Parse CLI Arguments (Used by legacy wrapper scripts or power users)
IF /I "%~1"=="--run" (
    CALL :RUN_PROFILE %~2
    POPD
    EXIT /B
)
IF /I "%~1"=="--install" (
    CALL :INSTALL_SERVICE %~2
    POPD
    EXIT /B
)
IF /I "%~1"=="--remove" (
    CALL :REMOVE_SERVICE
    POPD
    EXIT /B
)
IF /I "%~1"=="--auto" (
    CALL :AUTO_PROBE
    POPD
    EXIT /B
)
IF /I "%~1"=="--status" (
    CALL :SHOW_STATUS
    PAUSE
    POPD
    EXIT /B
)

:: 5. Interactive Smart Menu
:MAIN_MENU
CLS
ECHO ============================================================================
ECHO   GoodbyeDPI-Turkey Akilli Baslatici ve Otomatik ISS Profil Algilayici
ECHO   Mimari: %_arch% ^| Yonetici Yetkisi: Aktif
ECHO ============================================================================
ECHO.
ECHO   [A] OTOMATIK ALGILAMA (ISS'niz icin en hizli/uyumlu profili bul ve calistir)
ECHO.
ECHO   --- Gecici Calistir (Pencere Kapaninca Durur) ----------------------------
ECHO   [0] %PROF_0_NAME%
ECHO   [1] %PROF_1_NAME%
ECHO   [2] %PROF_2_NAME%
ECHO   [3] %PROF_3_NAME%
ECHO   [4] %PROF_4_NAME%
ECHO   [5] %PROF_5_NAME%
ECHO   [6] %PROF_6_NAME%
ECHO.
ECHO   --- Windows Hizmeti (Servis) Yonetimi ------------------------------------
ECHO   [S] Hizmet Olarak Kur (Her acilista otomatik baslar)
ECHO   [R] Hizmeti ve WinDivert Surucusunu Tamamen Kaldir (REVERT)
ECHO   [D] Durum Kontrolu ve Baglanti Testi
ECHO   [Q] Cikis
ECHO.
SET /P "CHOICE=Seciminiz [A/0-6/S/R/D/Q]: "

IF /I "%CHOICE%"=="A" (
    CALL :AUTO_PROBE
    PAUSE
    GOTO MAIN_MENU
)
IF "%CHOICE%"=="0" ( CALL :RUN_PROFILE 0 & GOTO MAIN_MENU )
IF "%CHOICE%"=="1" ( CALL :RUN_PROFILE 1 & GOTO MAIN_MENU )
IF "%CHOICE%"=="2" ( CALL :RUN_PROFILE 2 & GOTO MAIN_MENU )
IF "%CHOICE%"=="3" ( CALL :RUN_PROFILE 3 & GOTO MAIN_MENU )
IF "%CHOICE%"=="4" ( CALL :RUN_PROFILE 4 & GOTO MAIN_MENU )
IF "%CHOICE%"=="5" ( CALL :RUN_PROFILE 5 & GOTO MAIN_MENU )
IF "%CHOICE%"=="6" ( CALL :RUN_PROFILE 6 & GOTO MAIN_MENU )
IF /I "%CHOICE%"=="S" (
    ECHO.
    SET /P "SPROF=Hizmet olarak kurulacak profil numarasi [0-6, varsayilan 0]: "
    IF "!SPROF!"=="" SET "SPROF=0"
    CALL :INSTALL_SERVICE !SPROF!
    PAUSE
    GOTO MAIN_MENU
)
IF /I "%CHOICE%"=="R" (
    CALL :REMOVE_SERVICE
    PAUSE
    GOTO MAIN_MENU
)
IF /I "%CHOICE%"=="D" (
    CALL :SHOW_STATUS
    PAUSE
    GOTO MAIN_MENU
)
IF /I "%CHOICE%"=="Q" (
    POPD
    EXIT /B 0
)
GOTO MAIN_MENU

:: ============================================================================
:: Subroutines
:: ============================================================================

:RUN_PROFILE
SET "PIDX=%~1"
IF "%PIDX%"=="" SET "PIDX=0"
CALL SET "PNAME=%%PROF_%PIDX%_NAME%%"
CALL SET "PARGS=%%PROF_%PIDX%_ARGS%%"
IF "%PARGS%"=="" (
    ECHO [HATA] Gecersiz profil numarasi: %PIDX%
    EXIT /B 1
)
ECHO [*] Baslatiliyor: [Profil %PIDX%] %PNAME%
ECHO [*] Parametreler : %PARGS%
ipconfig /flushdns >nul 2>&1
PUSHD "%~dp0%_arch%"
start "GoodbyeDPI-Turkey [Profil %PIDX%]" goodbyedpi.exe %PARGS%
POPD
EXIT /B 0

:INSTALL_SERVICE
SET "PIDX=%~1"
IF "%PIDX%"=="" SET "PIDX=0"
CALL SET "PNAME=%%PROF_%PIDX%_NAME%%"
CALL SET "PARGS=%%PROF_%PIDX%_ARGS%%"
IF "%PARGS%"=="" (
    ECHO [HATA] Gecersiz profil numarasi: %PIDX%
    EXIT /B 1
)
ECHO [*] Mevcut GoodbyeDPI hizmeti temizleniyor...
sc stop "GoodbyeDPI" >nul 2>&1
sc delete "GoodbyeDPI" >nul 2>&1
taskkill /F /IM goodbyedpi.exe >nul 2>&1
ECHO [*] Hizmet kuruluyor: [Profil %PIDX%] %PNAME%
sc create "GoodbyeDPI" binPath= "\"%GDPI_EXE%\" %PARGS%" start= "auto"
sc description "GoodbyeDPI" "Turkiye icin DNS ve DPI engelini kaldirir (%PNAME%)"
sc start "GoodbyeDPI"
ipconfig /flushdns >nul 2>&1
ECHO [+] GoodbyeDPI hizmeti basariyla kuruldu ve baslatildi!
EXIT /B 0

:REMOVE_SERVICE
ECHO [*] GoodbyeDPI hizmeti ve WinDivert surucusu kaldiriliyor...
sc stop "GoodbyeDPI" >nul 2>&1
sc delete "GoodbyeDPI" >nul 2>&1
taskkill /F /IM goodbyedpi.exe >nul 2>&1
sc stop "WinDivert" >nul 2>&1
sc delete "WinDivert" >nul 2>&1
sc stop "WinDivert14" >nul 2>&1
sc delete "WinDivert14" >nul 2>&1
ipconfig /flushdns >nul 2>&1
ECHO [+] Tum GoodbyeDPI hizmetleri ve suruculeri basariyla kaldirildi.
EXIT /B 0

:AUTO_PROBE
ECHO.
ECHO [*] Otomatik ISS / DPI Profil Algilama baslatiliyor...
ECHO [*] En dusuk gecikmeli ve siteleri bozmayan profilden baslayarak test ediliyor:
sc stop "GoodbyeDPI" >nul 2>&1
taskkill /F /IM goodbyedpi.exe >nul 2>&1
ipconfig /flushdns >nul 2>&1

:: Order from least intrusive (no fixed low TTL) to most aggressive TTL modes
FOR %%P IN (5 6 4 2 0 3 1) DO (
    CALL SET "TNAME=%%PROF_%%P_NAME%%"
    CALL SET "TARGS=%%PROF_%%P_ARGS%%"
    ECHO.
    ECHO [Test %%P] Deneniyor: !TNAME! ^(!TARGS!^)
    PUSHD "%~dp0%_arch%"
    start "" /MIN goodbyedpi.exe !TARGS!
    POPD
    timeout /t 1 /nobreak >nul
    ipconfig /flushdns >nul 2>&1
    curl.exe -I -s -m 3 https://discord.com >nul 2>&1
    IF !ERRORLEVEL! EQU 0 (
        ECHO [+] BASARILI! ISS'niz icin en uygun profil bulundu: [Profil %%P] !TNAME!
        ECHO.
        SET /P "INSTALL_ASK=Bu profili kalici Windows Hizmeti olarak kurmak ister misiniz? [E/H]: "
        IF /I "!INSTALL_ASK!"=="E" (
            CALL :INSTALL_SERVICE %%P
        ) ELSE (
            ECHO [+] GoodbyeDPI arka planda gecici modda calismaya devam ediyor.
        )
        EXIT /B 0
    )
    taskkill /F /IM goodbyedpi.exe >nul 2>&1
)

ECHO.
ECHO [!] Otomatik testte hicbir profil dogrudan baglanti saglayamadi.
ECHO [!] Lutfen Windows Ag Ayarlarindan DNS adresinizi 77.88.8.8 veya 1.1.1.1 yapip tekrar deneyin.
EXIT /B 1

:SHOW_STATUS
ECHO.
ECHO --- GoodbyeDPI Hizmet Durumu ---
sc query "GoodbyeDPI"
ECHO.
ECHO --- HTTPS DPI Erisim Testi (discord.com) ---
curl.exe -I -s -m 4 https://discord.com | findstr /I "HTTP/"
IF %ERRORLEVEL% EQU 0 (
    ECHO [+] Erisim ACIK: HTTPS baglantisi basarili!
) ELSE (
    ECHO [-] Erisim KAPALI veya zaman asimi!
)
EXIT /B 0
