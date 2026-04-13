using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.ServiceProcess;

namespace WindowsFormsApp2
{
    public partial class Form1 : Form
    {
        private const string LOADER_VERSION = "1.0.1";
        private string tempGameFolder = "";
        Process gameProcess = null;
        private string activatedKey = null;
        private int watchdogPid = 0;
        private string gamePidPath;
        private string loaderPidPath;
        private DateTime lastActivateTime = DateTime.MinValue;
        private bool intentionalClose = false;

        private string heartbeatPath;
        private System.Threading.CancellationTokenSource heartbeatCts;

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        const uint THREAD_QUERY_INFORMATION = 0x0040;

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

        [DllImport("ntdll.dll")]
        static extern uint NtSetInformationProcess(IntPtr hProcess, int infoClass,
    IntPtr info, int infoLen);

        void BlockRemoteThreads(Process proc)
        {
            int value = 1;
            IntPtr ptr = Marshal.AllocHGlobal(4);
            Marshal.WriteInt32(ptr, value);

            // 29 = ProcessBreakOnTermination, 31 = ProcessChildProcessPolicy
            // 30 = ProcessProtectionLevel, 7 = ProcessDebugFlags

            NtSetInformationProcess(proc.Handle, 7, ptr, 4);   // Disable debug attach
            NtSetInformationProcess(proc.Handle, 31, ptr, 4);  // Child process block

            Marshal.FreeHGlobal(ptr);
        }

        [DllImport("kernel32.dll")]
        static extern int VirtualQueryEx(
   IntPtr hProcess,
   IntPtr lpAddress,
   out MEMORY_BASIC_INFORMATION lpBuffer,
   int dwLength
);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetInformationJobObject(IntPtr hJob, int JobObjectInfoClass, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

        byte[] DecryptSWF(byte[] encrypted)
        {
            string keyString = "Gh72KD93nA0cFmX4qWbP1sE6Lt9YvR5Z"; // Aynı key
            byte[] key = Encoding.UTF8.GetBytes(keyString);
            byte[] iv = new byte[16];

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;

                using (var ms = new MemoryStream())
                using (var crypto = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    crypto.Write(encrypted, 0, encrypted.Length);
                    crypto.Close();
                    return ms.ToArray();
                }
            }
        }


        [DllImport("ntdll.dll")]
        static extern int NtQueryInformationThread(IntPtr threadHandle, int threadInformationClass,
    IntPtr threadInformation, int threadInformationLength, out int returnLength);

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        bool IsThreadSuspended(ProcessThread th)
        {
            try
            {
                IntPtr hThread = OpenThread(0x0010, false, (uint)th.Id);
                IntPtr info = Marshal.AllocHGlobal(8);
                int ret;

                NtQueryInformationThread(hThread, 8, info, 8, out ret);

                int state = Marshal.ReadInt32(info);

                Marshal.FreeHGlobal(info);

                return state == 5; // Suspended
            }
            catch { }

            return false;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

        [DllImport("ntdll.dll")]
        static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass,
    out IntPtr processInformation, int processInformationLength, out int returnLength);

        bool CheckPEBForDebugger()
        {
            try
            {
                bool remoteDbg;
                CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, out remoteDbg);

                if (remoteDbg || IsDebuggerPresent())
                    return true;
            }
            catch { }

            return false;
        }

        bool DetectCheatDrivers()
        {
            string[] drivers = { "dbk64", "dbk32", "cedriver", "ksdumper", "ksdumperclient" };

            foreach (string d in drivers)
            {
                try
                {
                    ServiceController sc = new ServiceController(d);

                    if (sc.Status == ServiceControllerStatus.Running ||
                        sc.Status == ServiceControllerStatus.StartPending)
                    {
                        return true; // CE driver aktif
                    }
                }
                catch
                {
                    // Servis yok = sorun yok
                }
            }
            return false;
        }



        bool HasSeDebugPrivilege()
        {
            try
            {
                using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent())
                {
                    foreach (var claim in identity.Claims)
                    {
                        if (claim.Value.ToLower().Contains("sedebugprivilege"))
                            return true;
                    }
                }
            }
            catch { }

            return false;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

        const uint PROCESS_VM_READ = 0x10;
        const uint PROCESS_VM_WRITE = 0x20;
        const uint PROCESS_VM_OPERATION = 0x08;
        const uint PROCESS_QUERY_INFORMATION = 0x400;
        const uint PROCESS_ALL_ACCESS = 0x1F0FFF;

        int suspiciousOpenAttempts = 0;


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
    IntPtr hProcess,
    IntPtr lpBaseAddress,
    byte[] lpBuffer,
    int dwSize,
    out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern bool DebugActiveProcess(int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool isDebuggerPresent);

        List<MemoryWatchRegion> memoryWatchList = new List<MemoryWatchRegion>();

        public struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public int LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public int ActiveProcessLimit;
            public long Affinity;
            public int PriorityClass;
            public int SchedulingClass;
        }

        public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        public struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        const int JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9;
        const int JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800;
        const int JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000;

        void ProtectProcessWithJob(Process proc)
        {
            IntPtr hJob = CreateJobObject(IntPtr.Zero, null);
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;

            int length = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr ptr = Marshal.AllocHGlobal(length);
            Marshal.StructureToPtr(info, ptr, false);

            SetInformationJobObject(hJob, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ptr, (uint)length);
            AssignProcessToJobObject(hJob, proc.Handle);
            Marshal.FreeHGlobal(ptr);
        }

        [DllImport("kernel32.dll")]
        static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        static extern bool DebugActiveProcessStop(uint dwProcessId);

        [DllImport("user32.dll")]
        public static extern bool ReleaseCapture();


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);


        [DllImport("user32.dll")]
        public static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);

        [DllImport("kernel32.dll")]
        static extern bool DebugSetProcessKillOnExit(bool KillOnExit);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(
    IntPtr hProcess,
    IntPtr lpBaseAddress,
    byte[] lpBuffer,
    int nSize,
    out IntPtr lpNumberOfBytesWritten
);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string StringSecurityDescriptor,
            uint StringSDRevision,
            out IntPtr SecurityDescriptor,
            out uint SecurityDescriptorSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SetKernelObjectSecurity(
            IntPtr Handle,
            int securityInformation,
            IntPtr pSecurityDescriptor);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LocalFree(IntPtr hMem);

        const uint SDDL_REVISION_1 = 1;
        const int DACL_SECURITY_INFORMATION = 0x00000004;

        [DllImport("kernel32.dll")]
        static extern bool SetProcessMitigationPolicy(int policy, ref PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY buffer, int size);

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY
        {
            public uint Flags;
        }

        // 🔥►► BURAYA EKLENDİ – Anti JPEXS Timer
        System.Windows.Forms.Timer antiJpexsTimer;



        public Form1()
        {
            InitializeComponent();


            textBox1.ForeColor = Color.Gray;
            textBox1.Text = "Enter your license key";

            textBox1.GotFocus += RemovePlaceholder;
            textBox1.LostFocus += SetPlaceholder;

            try
            {
                string path = Path.Combine(Path.GetTempPath(), "activate_time.dat");
                if (File.Exists(path))
                {
                    long ticks = long.Parse(File.ReadAllText(path));
                    lastActivateTime = new DateTime(ticks, DateTimeKind.Utc);
                }
            }
            catch { }


            // 1) Microsoft dışı binary çalışmasın (oyun dışı her şeyi engeller)
            // EnableSignaturePolicy();

            // 2) Loader’ın kendi handle’ını kilitle (CE -> Access Denied)
            // LockSelfProcess();

            // ------------------------------------------------------------
            // 🔥 LOADER AŞAMASINDA SADECE GÜVENLİ KONTROLLER
            // ------------------------------------------------------------

            // 3) JPEXS / FFDEC / Java → Loader'a saldırı
            StartAntiDecompilerMonitor();

            // 4) Başlık + isim taraması yapan CE kontrolü (loader crash etmez)
            StartAntiCheatMonitor();

            // 5) Debugger tespiti (dnSpy, VS, x64dbg)
            StartAntiDebugMonitor();

            DetectCheatDrivers();

            DetectInjectedThreads();

            // 6) Arkaplanda JPEXS taraması
            Task.Run(() => MonitorForJPEXS());

            StartGlobalKillMonitor();


            // ------------------------------------------------------------
            // ❌ AŞAĞIDAKİLERİ LOADER AŞAMASINDA ÇALIŞTIRMAK YASAK !!!
            //
            // StartOpenProcessMonitor()
            // StartSuspendMonitor()

            // 
            // CheckPEBForDebugger()
            // HasSeDebugPrivilege()
            //
            // Bunlar *oyun henüz yokken* loader'ı tehdit sanıp öldürdüğü için
            // LaunchGame() içinde başlatılıyor.
            // ------------------------------------------------------------


            // ------------------------------------------------------------
            // 🔥🔥 YENİ EKLENEN — Loader kapanınca oyunu %100 KAPATAN failsafe
            // ------------------------------------------------------------
            this.FormClosed += Form1_FormClosed;

            AppDomain.CurrentDomain.ProcessExit += (s, e) =>
            {
                try
                {
                    if (gameProcess != null && !gameProcess.HasExited)
                    {
                        gameProcess.Kill();
                        gameProcess.WaitForExit();
                    }
                }
                catch { }

                // Fail-safe dış kill (loader çökerse bile çalışır)
                try
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = "/c taskkill /IM sherwoods*.exe /F & taskkill /FI \"WINDOWTITLE eq sherwood*\" /F",
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        WindowStyle = ProcessWindowStyle.Hidden
                    });
                }
                catch { }
            };
            Task.Run(async () =>
            {
                while (true)
                {
                    try
                    {
                        using (HttpClient client = new HttpClient())
                        {
                            var data = new
                            {
                                hwid = GetHWID(),
                                version = LOADER_VERSION
                            };

                            var json = JsonConvert.SerializeObject(data);
                            var content = new StringContent(json, Encoding.UTF8, "application/json");

                            var response = await client.PostAsync("http://91.132.49.175:5000/check", content);
                            string result = await response.Content.ReadAsStringAsync();
                            dynamic obj = JsonConvert.DeserializeObject(result);

                            if (obj.kill == true)
                            {
                                UltraKillAll();
                                return;
                            }
                        }
                    }
                    catch { }

                    await Task.Delay(4000);
                }
            });

        }



        // 🔥 Anti-Decompiler Sistemi -------------------------------------------
        void StartAntiDecompilerMonitor()
        {
            antiJpexsTimer = new System.Windows.Forms.Timer();
            antiJpexsTimer.Interval = 200; // 🔥 2500 yerine 200ms (Saniyenin 5'te 1'i)
            antiJpexsTimer.Tick += (s, e) =>
            {
                Process[] allProcesses = Process.GetProcesses(); // Listeyi bir kere al, performans artar
                foreach (var p in allProcesses)
                {
                    string name = "";
                    string title = "";
                    try { name = p.ProcessName.ToLower(); } catch { }
                    try { title = p.MainWindowTitle.ToLower(); } catch { }

                    // 🔥 Cheat Engine Tespiti (İsmi değişse bile Title ele verir)
                    if (name.Contains("cheatengine") ||
                        name.Contains("cheat engine") ||
                        title.Contains("cheat engine") ||
                        title.Contains("memory view") ||  // Memory Viewer penceresi
                        title.Contains("string map") ||
                        name.StartsWith("ce") && name.EndsWith(".exe")) // Bazen ce.exe olur
                    {
                        // Cheat Engine açıksa, oyunu kapatma riskine girme, DİREKT CHEAT ENGINE'İ ÖLDÜR
                        try { p.Kill(); } catch { }
                        // İstersen UltraKillAll(); diyerek oyunu da kapatabilirsin.
                    }

                    // JPEXS / Java Tespiti
                    if (name == "javaw" || name == "java" ||
                        title.Contains("ffdec") || title.Contains("jpexs"))
                    {
                        UltraKillAll();
                    }
                }
            };
            antiJpexsTimer.Start();
        }

        async Task OverwriteSwfInRamAfterDelay()
        {
            try
            {
                // Oyun açıldıktan sonra sahnelerin yüklenmesi için ilk bekleme
                await Task.Delay(15000);

                if (gameProcess == null || gameProcess.HasExited)
                    return;

                IntPtr hProc = gameProcess.Handle;

                // Memory info için struct boyutu
                int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));

                // WinAPI sabitleri
                const uint MEM_COMMIT = 0x1000;
                const uint PAGE_NOACCESS = 0x01;
                const uint PAGE_GUARD = 0x100;

                // 64-bit usermode üst sınırı (fazlasına zaten VirtualQueryEx dönmez)
                long maxAddress = 0x00007FFF00000000;

                byte[] fws = { 0x46, 0x57, 0x53 }; // "FWS"
                byte[] cws = { 0x43, 0x57, 0x53 }; // "CWS"
                Random rng = new Random();

                // Sürekli çalışma: belli aralıklarla tüm süreci tarayıp FWS/CWS boz
                while (true)
                {
                    if (gameProcess == null || gameProcess.HasExited)
                        break;

                    long address = 0;

                    while (address < maxAddress)
                    {
                        MEMORY_BASIC_INFORMATION mbi;

                        int result = VirtualQueryEx(
                            hProc,
                            (IntPtr)address,
                            out mbi,
                            mbiSize
                        );

                        if (result == 0)
                            break; // daha ilerisi yok

                        long regionSize = (long)mbi.RegionSize;
                        long regionBase = (long)mbi.BaseAddress;

                        bool committed = (mbi.State & MEM_COMMIT) != 0;
                        bool noAccess = (mbi.Protect & PAGE_NOACCESS) != 0;
                        bool guard = (mbi.Protect & PAGE_GUARD) != 0;

                        if (committed && !noAccess && !guard && regionSize > 0)
                        {
                            // Bu bölgeyi küçük chunk'lar halinde tara
                            const int CHUNK = 0x10000; // 64 KB
                            long offset = 0;

                            while (offset < regionSize)
                            {
                                int toRead = (int)Math.Min(CHUNK, regionSize - offset);
                                byte[] buffer = new byte[toRead];

                                if (ReadProcessMemory(
                                        hProc,
                                        (IntPtr)(regionBase + offset),
                                        buffer,
                                        toRead,
                                        out IntPtr bytesRead) && (int)bytesRead > 0)
                                {
                                    bool modified = false;
                                    int limit = (int)bytesRead - 3;

                                    for (int i = 0; i <= limit; i++)
                                    {
                                        byte b0 = buffer[i];
                                        byte b1 = buffer[i + 1];
                                        byte b2 = buffer[i + 2];

                                        bool matchFws = (b0 == fws[0] && b1 == fws[1] && b2 == fws[2]);
                                        bool matchCws = (b0 == cws[0] && b1 == cws[1] && b2 == cws[2]);

                                        if (matchFws || matchCws)
                                        {
                                            // İsteğe bağlı: SWF header gibi mi diye kaba bir kontrol
                                            // (file length 0 < len < 50MB gibi)
                                            // Şimdilik basit tutuyoruz: gördüğümüz her FWS/CWS’yi boz.

                                            byte[] repl = new byte[3];
                                            rng.NextBytes(repl);
                                            buffer[i] = repl[0];
                                            buffer[i + 1] = repl[1];
                                            buffer[i + 2] = repl[2];

                                            modified = true;
                                        }
                                    }

                                    if (modified)
                                    {
                                        // Değişen chunk'ı tekrar RAM'e yaz
                                        WriteProcessMemory(
                                            hProc,
                                            (IntPtr)(regionBase + offset),
                                            buffer,
                                            (int)bytesRead,
                                            out IntPtr _);
                                    }
                                }

                                offset += toRead;
                            }
                        }

                        // Bir sonraki bölgeye atla
                        address = (long)mbi.BaseAddress + regionSize;
                    }

                    // Çok sık tarayıp oyunu kasmamak için biraz bekle
                    await Task.Delay(10000); // 10 saniyede bir tüm process’i yeniden tara
                }
            }
            catch
            {
                // Sessiz fail; oyun/güvenlik bozulmasın
            }
        }



        private void RemovePlaceholder(object sender, EventArgs e)
        {
            if (textBox1.ForeColor == Color.Gray)
            {
                textBox1.Text = "";
                textBox1.ForeColor = Color.White;
            }
        }

        private void SetPlaceholder(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(textBox1.Text))
            {
                textBox1.ForeColor = Color.Gray;
                textBox1.Text = "Enter your license key";
            }
        }

        void StartAntiCheatMonitor()
        {
            // Arka planda CE tarayan thread
            Task.Run(() =>
            {
                while (true)
                {
                    try
                    {
                        foreach (var p in Process.GetProcesses())
                        {
                            string name = "";
                            string title = "";

                            try { name = p.ProcessName.ToLowerInvariant(); } catch { }
                            try { title = p.MainWindowTitle.ToLowerInvariant(); } catch { }

                            // Cheat Engine tespiti - isim değişse bile başlık + name kombinasyonu ile
                            if (name.Contains("cheatengine") ||
                                name.Contains("cheat engine") ||
                                name.StartsWith("cheatengine") ||
                                title.Contains("cheat engine") ||
                                title.Contains("cheatengine") ||
                                (name.Contains("cheat") && title.Contains("engine")))
                            {
                                try { p.Kill(); } catch { }
                            }
                        }
                    }
                    catch
                    {
                    }

                    Thread.Sleep(500); // 0.5 sn’de bir tarasın (yeterince agresif)
                }
            });
        }

        void MonitorForJPEXS()
        {
            while (true)
            {
                try
                {
                    // Process isimlerinden tespit (java, javaw, fiddler, fiddler4, wireshark)
                    string[] dangerousProcesses =
                    {
                "java", "javaw",     // JPEXS
                "fiddler", "fiddler4", "fiddler classic", "fiddlerclassic",
                "wireshark"
            };

                    foreach (var name in dangerousProcesses)
                    {
                        if (Process.GetProcessesByName(name).Length > 0)
                        {
                            UltraKillAll();
                        }
                    }

                    // Pencere başlıkları (FFDEC, JPEXS, FLASH, DECOMPILER, FIDDLER, WIRESHARK)
                    foreach (var p in Process.GetProcesses())
                    {
                        try
                        {
                            string title = p.MainWindowTitle.ToLower();

                            if (title.Contains("ffdec") ||
                                title.Contains("jpexs") ||
                                title.Contains("flash") ||
                                title.Contains("decompiler") ||
                                title.Contains("fiddler") ||
                                title.Contains("wireshark"))
                            {
                                UltraKillAll();
                            }
                        }
                        catch { }
                    }
                }
                catch { }

                Thread.Sleep(1000);
            }
        }

        void InitMemoryIntegrity()
        {
            // 🔥 ÖRNEK: Buraya kendi adreslerini yazacaksın
            // (Bu adresleri CE'den alacaksın, ben şu an hayali adres yazıyorum)
            IntPtr addr1 = (IntPtr)0x01234567; // örnek kritik fonksiyon adresi
            int len1 = 32;                     // 32 byte kontrol et

            var bytes1 = ReadBytesFromGame(addr1, len1);
            if (bytes1 != null)
            {
                memoryWatchList.Add(new MemoryWatchRegion
                {
                    Address = addr1,
                    Length = len1,
                    OriginalBytes = bytes1
                });
            }

            // İstersen ikinci bölge:
            /*
            IntPtr addr2 = (IntPtr)0x00ABCDEF;
            int len2 = 16;

            var bytes2 = ReadBytesFromGame(addr2, len2);
            if (bytes2 != null)
            {
                memoryWatchList.Add(new MemoryWatchRegion
                {
                    Address = addr2,
                    Length = len2,
                    OriginalBytes = bytes2
                });
            }
            */
        }


        void StartMemoryIntegrityMonitor()
        {
            Task.Run(() =>
            {
                while (true)
                {
                    try
                    {
                        if (gameProcess == null || gameProcess.HasExited)
                        {
                            // Oyun yoksa bu thread'e artık gerek yok
                            return;
                        }

                        foreach (var region in memoryWatchList)
                        {
                            var current = ReadBytesFromGame(region.Address, region.Length);
                            if (current == null)
                                continue;

                            bool changed = false;
                            for (int i = 0; i < region.Length; i++)
                            {
                                if (current[i] != region.OriginalBytes[i])
                                {
                                    changed = true;
                                    break;
                                }
                            }

                            if (changed)
                            {
                                // MEMORY PATCH TESPİT EDİLDİ 🔥
                                UltraKillAll();
                                return;
                            }
                        }
                    }
                    catch
                    {
                    }

                    Thread.Sleep(1500); // 1.5 sn'de bir integrity check
                }
            });
        }
        void StartGlobalKillMonitor()
        {
            if (string.IsNullOrEmpty(activatedKey))
                return; // KEY YOKKEN ÇALIŞMA

            Task.Run(async () =>
            {
                string hwid = GetHWID();
                string version = LOADER_VERSION;

                while (true)
                {
                    try
                    {
                        long ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                        string nonce = GenerateNonce();
                        string sig = CreateSignature(activatedKey, hwid, ts, nonce);

                        var data = new
                        {
                            key = activatedKey,
                            hwid = hwid,
                            version = version,
                            timestamp = ts,
                            nonce = nonce,
                            signature = sig
                        };

                        using (HttpClient client = new HttpClient())
                        {
                            var json = JsonConvert.SerializeObject(data);
                            var content = new StringContent(json, Encoding.UTF8, "application/json");

                            var resp = await client.PostAsync("http://91.132.49.175:5000/check", content);
                            string result = await resp.Content.ReadAsStringAsync();
                            dynamic obj = JsonConvert.DeserializeObject(result);

                            if (obj.kill == true)
                            {
                                UltraKillAll();
                                return;
                            }
                        }
                    }
                    catch
                    {
                        // burada loader'ı öldürme (internet kesik olabilir)
                    }

                    await Task.Delay(15000);
                }
            });
        }

        bool DetectInjectedThreads()
        {
            try
            {
                if (gameProcess == null || gameProcess.HasExited)
                    return false;

                foreach (ProcessThread th in gameProcess.Threads)
                {
                    try
                    {
                        IntPtr hThread = OpenThread(THREAD_QUERY_INFORMATION, false, (uint)th.Id);

                        if (hThread != IntPtr.Zero)
                        {
                            IntPtr buffer = Marshal.AllocHGlobal(IntPtr.Size);
                            int retLen;

                            // Thread start address oku
                            int status = NtQueryInformationThread(
                                hThread,
                                9, // ThreadQuerySetWin32StartAddress
                                buffer,
                                IntPtr.Size,
                                out retLen
                            );

                            if (status == 0)
                            {
                                long start = Marshal.ReadIntPtr(buffer).ToInt64();

                                // NORMAL modüllerin dışında bir adres → inject thread
                                if (start < 0x7FF000000000)
                                {
                                    Marshal.FreeHGlobal(buffer);
                                    return true;
                                }
                            }

                            Marshal.FreeHGlobal(buffer);
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return false;
        }

        class MemoryWatchRegion
        {
            public IntPtr Address;
            public byte[] OriginalBytes;
            public int Length;
        }

        byte[] ReadBytesFromGame(IntPtr address, int length)
        {
            if (gameProcess == null || gameProcess.HasExited)
                return null;

            byte[] buffer = new byte[length];
            try
            {
                if (ReadProcessMemory(gameProcess.Handle, address, buffer, length, out IntPtr read)
                    && (int)read == length)
                {
                    return buffer;
                }
            }
            catch { }

            return null;
        }




        void UltraKillAll()
        {
            intentionalClose = true;
            try
            {
                string[] badProcNames = new[]
                {
            "cheatengine","cheat engine","ce",
            "processhacker","processhacker2","procexp","procexp64","procmon",
            "x64dbg","x32dbg","ida","ollydbg","dnspy","ilspy","windbg",
            "reshacker","ghidra",

            "fiddler", "fiddler4", "fiddlerclassic", "fiddler classic",
            "wireshark",

            "java","javaw","jpexs","decompiler"
        };

                try
                {
                    foreach (var p in Process.GetProcesses())
                    {
                        string name = "";
                        string title = "";
                        try { name = p.ProcessName.ToLowerInvariant(); } catch { }
                        try { title = p.MainWindowTitle.ToLowerInvariant(); } catch { }

                        bool isBad = false;
                        foreach (var bad in badProcNames)
                        {
                            if (name.Contains(bad.Replace(" ", "")) || name.Contains(bad) || title.Contains(bad))
                            {
                                isBad = true;
                                break;
                            }
                        }

                        if (isBad)
                        {
                            try { p.Kill(); p.WaitForExit(); } catch { }
                        }
                    }
                }
                catch { }

                // 0.1) CE driver'larını durdur
                try
                {
                    string[] badServiceNames = {
                "dbk32","dbk64","cedriver","ksdumper","ksdumperclient"
            };

                    foreach (var sc in ServiceController.GetServices())
                    {
                        try
                        {
                            string n = sc.ServiceName.ToLowerInvariant();
                            string d = sc.DisplayName.ToLowerInvariant();

                            foreach (var bad in badServiceNames)
                            {
                                if (n.Contains(bad) || d.Contains(bad))
                                {
                                    if (sc.Status == ServiceControllerStatus.Running)
                                    {
                                        try { sc.Stop(); } catch { }
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }

                // 1) Ana gameProcess kill
                try
                {
                    if (gameProcess != null && !gameProcess.HasExited)
                    {
                        gameProcess.Kill();
                        gameProcess.WaitForExit();   // <-- ÖNEMLİ
                    }
                }
                catch { }

                // 2) PID dosyasından kill
                try
                {
                    string pidPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "gamepid.txt");
                    if (File.Exists(pidPath))
                    {
                        string pidStr = File.ReadAllText(pidPath);
                        if (int.TryParse(pidStr, out int pid))
                        {
                            try
                            {
                                var p = Process.GetProcessById(pid);
                                p.Kill();
                                p.WaitForExit();      // <-- ÖNEMLİ
                            }
                            catch { }
                        }
                        try { File.Delete(pidPath); } catch { }
                    }
                }
                catch { }

                // 3) Temp klasöründeki bütün gelişi güzel Sherwood .exe’leri öldür
                string temp = Path.GetTempPath().ToLowerInvariant();
                try
                {
                    foreach (Process p in Process.GetProcesses())
                    {
                        try
                        {
                            string exe = p.MainModule.FileName.ToLower();
                            if (exe.Contains(temp) && exe.EndsWith(".exe") &&
                                (exe.Contains("sherwood") || exe.Contains("woods")))
                            {
                                p.Kill();
                                p.WaitForExit();    // <-- ÖNEMLİ
                            }
                        }
                        catch { }
                    }
                }
                catch { }

                // 4) İsmi değişmiş (random EXE) Sherwood'u öldür
                try
                {
                    foreach (Process p in Process.GetProcesses())
                    {
                        try
                        {
                            string name = p.ProcessName.ToLowerInvariant();
                            if (name.Contains("sherwood") ||
                                name.Contains("sherwoods") ||
                                name.Contains("woods") ||
                                (name.StartsWith("sw") && name.Length <= 12))
                            {
                                p.Kill();
                                p.WaitForExit();  // <-- ÖNEMLİ
                            }
                        }
                        catch { }
                    }
                }
                catch { }

                // 5) TEMP klasörünü temizle (exelerin hepsi ölmüş durumda)
                try
                {
                    SafeDeleteFolder(tempGameFolder);
                }
                catch { }

                // 6) En son loader'ı öldür
                try
                {
                    Process.GetCurrentProcess().Kill();
                }
                catch
                {
                    Application.Exit();
                    Environment.Exit(0);
                }
            }
            catch
            {
                Environment.Exit(0);
            }
        }

        // ----------------------------------------------------------------------

        void EnableSignaturePolicy()
        {
            var p = new PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY();
            p.Flags = 0x00000008; // BLOCK_NON_MICROSOFT_BINARIES
            SetProcessMitigationPolicy(8, ref p, Marshal.SizeOf(p));
        }

        //  Process'e erişimi (OpenProcess) engeller. 
        // Cheat Engine "Unable to open process" veya "Access Denied" hatası alır.
        //  1. TEMEL FONKSİYON: Verilen herhangi bir Process'i kilitler (Hem Oyun Hem Loader için)
        void LockProcessHandle(IntPtr hProcess)
        {
            try
            {
                // Everyone, Administrators, Interactive Users -> FULL DENY
                // SYSTEM -> FULL ALLOW
                // Bu sayede CE dahil hiç kimse OpenProcess ile attach olamaz
                string sddl = "D:P" +
                              "(D;;GA;;;WD)" +  // Everyone deny GenericAll
                              "(D;;GA;;;BA)" +  // Builtin Admins deny
                              "(D;;GA;;;IU)" +  // Interactive Users deny
                              "(A;;GA;;;SY)";   // SYSTEM allow

                if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                        sddl,
                        SDDL_REVISION_1,
                        out IntPtr pSD,
                        out uint _))
                {
                    return;
                }

                try
                {
                    // DACL_SECURITY_INFORMATION = 4
                    SetKernelObjectSecurity(hProcess, DACL_SECURITY_INFORMATION, pSD);
                }
                finally
                {
                    if (pSD != IntPtr.Zero)
                        LocalFree(pSD);
                }
            }
            catch
            {
            }
        }

        // 🔥 2. HATAYI ÇÖZEN FONKSİYON: Loader'ın kendisini kilitler
        // Form1() içinde çağrılan yer burasıdır, silinmemeli.
        void LockSelfProcess()
        {
            LockProcessHandle(Process.GetCurrentProcess().Handle);
        }

        // 🔥 PROCESS PATH GİZLEME
        void HideProcessPath(string exeName)
        {
            try
            {
                string regPath = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" + exeName;
                Microsoft.Win32.Registry.SetValue(regPath, "Debugger", " ");
            }
            catch { }
        }

        // 🔥 EXE başladıktan 3 saniye sonra SWF rename
        async void RenameSwfAfterStart(string swfPath)
        {
            try
            {
                await Task.Delay(3000);
                string randomName = Path.GetRandomFileName().Replace(".", "") + Guid.NewGuid().ToString("N").Substring(0, 10);
                string newPath = Path.Combine(Path.GetDirectoryName(swfPath), randomName + ".swf");

                File.SetAttributes(swfPath, FileAttributes.Normal);
                File.Move(swfPath, newPath);
                File.SetAttributes(newPath, FileAttributes.Hidden | FileAttributes.System | FileAttributes.ReadOnly);
            }
            catch { }
        }

        void StartSuspendMonitor()
        {
            Task.Run(() =>
            {
                while (true)
                {
                    try
                    {
                        if (gameProcess != null && !gameProcess.HasExited)
                        {
                            int suspended = 0;
                            foreach (ProcessThread t in gameProcess.Threads)
                            {
                                if (IsThreadSuspended(t))
                                    suspended++;
                            }

                            if (suspended == gameProcess.Threads.Count)
                                UltraKillAll(); // bütün threadler donmuş → PH freeze saldırısı
                        }
                    }
                    catch { }

                    Thread.Sleep(500);
                }
            });
        }

        // 🔥 Subsystem Patch
        void PatchSubsystemToConsole(string exe)
        {
            try
            {
                if (!File.Exists(exe)) return;
                byte[] data = File.ReadAllBytes(exe);
                if (data.Length < 0x40) return;

                int peOffset = BitConverter.ToInt32(data, 0x3C);
                if (peOffset <= 0 || peOffset + 0x5E >= data.Length) return;

                int subsystemOffset = peOffset + 0x5C;
                data[subsystemOffset] = 3;
                data[subsystemOffset + 1] = 0;

                File.SetAttributes(exe, FileAttributes.Normal);
                File.WriteAllBytes(exe, data);
            }
            catch { }
        }

        // 🔥 Oyunu gizli başlat (şu an kullanılmıyor ama kalsın)
        void StartGameHidden(string exePath, string workingDir)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = exePath;
                psi.WorkingDirectory = workingDir;
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.WindowStyle = ProcessWindowStyle.Hidden;

                Process gameProcess = Process.Start(psi);
                string pidPath = Path.Combine(Application.StartupPath, "gamepid.txt");
                File.WriteAllText(pidPath, gameProcess.Id.ToString());
            }
            catch { }
        }

        void StartOpenProcessMonitor()
        {
            Task.Run(() =>
            {
                while (true)
                {
                    try
                    {
                        // sadece oyuna attach denemelerini kontrol et
                        if (gameProcess != null && !gameProcess.HasExited)
                        {
                            IntPtr test = OpenProcess(
                                PROCESS_VM_READ | PROCESS_VM_WRITE |
                                PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                                false,
                                (uint)gameProcess.Id
                            );

                            if (test != IntPtr.Zero)
                            {
                                // CE oyun process'ine erişebiliyor → tehlike
                                UltraKillAll();
                            }
                        }
                    }
                    catch { }

                    Thread.Sleep(400);
                }
            });
        }

        void StartAntiDebugMonitor()
        {
            Task.Run(() =>
            {
                while (true)
                {
                    try
                    {
                        // 1) Kendi process'ine debugger attach olmuş mu?
                        bool remoteDbg = false;
                        try
                        {
                            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, out remoteDbg);
                        }
                        catch { }

                        bool isDbg = false;
                        try
                        {
                            isDbg = IsDebuggerPresent() || remoteDbg;
                        }
                        catch { }

                        if (isDbg)
                        {
                            // Debugger takılıysa direkt hepsini öldür
                            UltraKillAll();
                        }

                        // 2) Tipik debugger process isimleri (x64dbg, ida, dnSpy, vs)
                        foreach (var p in Process.GetProcesses())
                        {
                            string name = "";
                            string title = "";
                            try { name = p.ProcessName.ToLowerInvariant(); } catch { }
                            try { title = p.MainWindowTitle.ToLowerInvariant(); } catch { }

                            if (string.IsNullOrEmpty(name) && string.IsNullOrEmpty(title))
                                continue;

                            // x64dbg / x32dbg / ida / ollydbg / dnSpy / ILSpy / VS / Rider / WinDbg
                            if (name.Contains("x64dbg") ||
                                name.Contains("x32dbg") ||
                                name.Contains("ida") ||
                                name.Contains("ollydbg") ||
                                name.Contains("dnspy") ||
                                name.Contains("ilspy") ||
                                name.Contains("devenv") ||      // Visual Studio
                                name.Contains("rider") ||
                                name.Contains("windbg") ||
                                title.Contains("x64dbg") ||
                                title.Contains("x32dbg") ||
                                title.Contains("ida") ||
                                title.Contains("ollydbg") ||
                                title.Contains("dnspy") ||
                                title.Contains("ilspy") ||
                                title.Contains("visual studio") ||
                                title.Contains("windbg"))
                            {
                                try
                                {
                                    // İster sadece debugger process'ini öldür
                                    // p.Kill();

                                    // İster direkt her şeyi kapat (daha güvenli)
                                    UltraKillAll();
                                }
                                catch { }
                            }
                        }
                    }
                    catch
                    {
                    }

                    Thread.Sleep(1000); // 1 sn'de bir debug taraması
                }
            });
        }

        string GetHWID()
        {
            string raw = Environment.MachineName;
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(raw));
                return BitConverter.ToString(hash).Replace("-", "");
            }
        }

        void SafeDeleteFolder(string path)
        {
            try
            {
                if (!Directory.Exists(path)) return;
                foreach (string f in Directory.GetFiles(path))
                {
                    File.SetAttributes(f, FileAttributes.Normal);
                    File.Delete(f);
                }
                foreach (string d in Directory.GetDirectories(path))
                {
                    SafeDeleteFolder(d);
                }
                File.SetAttributes(path, FileAttributes.Normal);
                Directory.Delete(path, false);
            }
            catch { }
        }

        async void DenyExeDelayed(string exePath)
        {
            try
            {
                // 11 saniye bekle
                await Task.Delay(11000);

                // EXE dosyası için ACL al
                FileInfo fi = new FileInfo(exePath);
                FileSecurity sec = fi.GetAccessControl();

                // Everyone → READ DENY
                sec.AddAccessRule(new FileSystemAccessRule(
                    "Everyone",
                    FileSystemRights.Read,
                    AccessControlType.Deny
                ));

                // Kullanıcıya READ DENY
                sec.AddAccessRule(new FileSystemAccessRule(
                    Environment.UserName,
                    FileSystemRights.Read,
                    AccessControlType.Deny
                ));

                // ACL uygula
                fi.SetAccessControl(sec);
            }
            catch { }
        }

        private void GameProcess_Exited(object sender, EventArgs e)
        {
            try
            {
                // UI thread üzerinden formu kapat
                if (this.InvokeRequired)
                {
                    this.BeginInvoke(new Action(() =>
                    {
                        this.Close();
                    }));
                }
                else
                {
                    this.Close();
                }
            }
            catch
            {
            }
        }

        async void LaunchGame()
        {
            try
            {
                // ✔ Oyun açılmadan anti-cheat tetiklenmemeli → 10 saniye gecikme
                await Task.Delay(10000);

                // Loader kapanmışsa oyunu açma
                if (this.IsDisposed || !this.Visible)
                {
                    if (gameProcess != null && !gameProcess.HasExited)
                        gameProcess.Kill();
                    return;
                }

                // --- TEMP FOLDER ---
                string randomName = Path.GetRandomFileName().Replace(".", "") +
                                    Guid.NewGuid().ToString("N").Substring(0, 12);

                tempGameFolder = Path.Combine(Path.GetTempPath(), randomName);
                Directory.CreateDirectory(tempGameFolder);
                File.SetAttributes(tempGameFolder,
                    FileAttributes.Hidden | FileAttributes.System | FileAttributes.ReadOnly);

                // --- ZIP çıkar ---
                byte[] zipBytes = Properties.Resources.gamefiles;
                string zipPath = Path.Combine(tempGameFolder, "data.bin");
                File.WriteAllBytes(zipPath, zipBytes);
                ZipFile.ExtractToDirectory(zipPath, tempGameFolder);
                File.Delete(zipPath);

                // ===============================================================
                // 🔥🔥  SWF AES-256 ŞİFRE ÇÖZME ENTEGRASYONU (TAM İSTEDİĞİN GİBİ)
                // ===============================================================
                byte[] enc = Properties.Resources.SherwoodEnc;
                byte[] swfBytes = DecryptSWF(enc);

                string swfPath = Path.Combine(tempGameFolder, "Sherwood.swf");

                // SWF RAM'de çözüldü, diske yazılıyor
                File.WriteAllBytes(swfPath, swfBytes);

                // Gizle + ReadOnly + System
                File.SetAttributes(swfPath, FileAttributes.Hidden | FileAttributes.System | FileAttributes.ReadOnly);

                // 3 saniye sonra otomatik rename + gizleme
                RenameSwfAfterStart(swfPath);
                // ===============================================================


                // --- EXE ---
                string exeSrc = Path.Combine(tempGameFolder, "Sherwoods.exe");
                string exeRand = Guid.NewGuid().ToString("N").Substring(0, 12) + ".exe";
                string exePath = Path.Combine(tempGameFolder, exeRand);

                File.SetAttributes(exeSrc, FileAttributes.Normal);
                File.Copy(exeSrc, exePath, true);
                File.Delete(exeSrc);

                PatchSubsystemToConsole(exePath);

                foreach (var f in Directory.GetFiles(tempGameFolder))
                    File.SetAttributes(f,
                        FileAttributes.Hidden | FileAttributes.System | FileAttributes.ReadOnly);

                HideProcessPath(exeRand);

                // --- STRONG ACLs (gecikmeli) ---
                async void ApplyStrongAcls(string targetExe, string targetFolder)
                {
                    // 5 saniye sonra klasörü kilitle
                    await Task.Delay(5000);
                    try
                    {
                        DirectorySecurity secFolder = Directory.GetAccessControl(targetFolder);
                        secFolder.SetAccessRuleProtection(true, false);

                        secFolder.AddAccessRule(new FileSystemAccessRule(
                            "Everyone", FileSystemRights.FullControl,
                            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                            PropagationFlags.None, AccessControlType.Deny));

                        secFolder.AddAccessRule(new FileSystemAccessRule(
                            Environment.UserName, FileSystemRights.FullControl,
                            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                            PropagationFlags.None, AccessControlType.Deny));

                        secFolder.AddAccessRule(new FileSystemAccessRule(
                            "SYSTEM", FileSystemRights.FullControl, AccessControlType.Allow));

                        Directory.SetAccessControl(targetFolder, secFolder);
                    }
                    catch { }

                    // 11 saniye sonra EXE’yi kilitle
                    await Task.Delay(11000);
                    try
                    {
                        FileInfo fi = new FileInfo(targetExe);
                        FileSecurity secExe = fi.GetAccessControl();
                        secExe.SetAccessRuleProtection(true, false);

                        secExe.AddAccessRule(new FileSystemAccessRule(
                            "Everyone", FileSystemRights.Read, AccessControlType.Deny));

                        secExe.AddAccessRule(new FileSystemAccessRule(
                            Environment.UserName, FileSystemRights.Read, AccessControlType.Deny));

                        secExe.AddAccessRule(new FileSystemAccessRule(
                            "SYSTEM", FileSystemRights.FullControl, AccessControlType.Allow));

                        fi.SetAccessControl(secExe);
                    }
                    catch { }
                }

                gameProcess = Process.Start(new ProcessStartInfo
                {
                    FileName = exePath,
                    WorkingDirectory = tempGameFolder,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                });

                // stabilize
                Thread.Sleep(150);

                // process koruma
                LockProcessHandle(gameProcess.Handle);
                ProtectProcessWithJob(gameProcess);

                // exit event
                gameProcess.EnableRaisingEvents = true;
                gameProcess.Exited += GameProcess_Exited;

                // ---------------------------
                // gamepid.txt yaz + görünmez yap
                // ---------------------------
                gamePidPath = Path.Combine(Path.GetTempPath(), "gpid_" + Guid.NewGuid().ToString("N") + ".txt");
                File.WriteAllText(gamePidPath, gameProcess.Id.ToString());
                HideSystemFile(gamePidPath);


                // ---------------------------
                // loaderpid.txt yaz + görünmez yap
                // ---------------------------
                loaderPidPath = Path.Combine(Path.GetTempPath(), "lpid_" + Guid.NewGuid().ToString("N") + ".txt");
                File.WriteAllText(loaderPidPath, Process.GetCurrentProcess().Id.ToString());
                HideSystemFile(loaderPidPath);

                // ---------------------------
                // WDHOST parametresi
                // ---------------------------
                string arg = heartbeatPath + "|" + gamePidPath + "|" + loaderPidPath;



                // =====================================================================
                // 🌟 CRITICAL FIX — WATCHDOG OYUNDAN 10 SANİYE SONRA BAŞLAMALI
                // =====================================================================
                await Task.Delay(5000);   // oyun tamamen açılıp stabilize olsun
                StartWatchdog();          // 1) guard.exe + hb.bin oluştur, heartbeatPath dolu
                StartHeartbeatThread();   // 2) hb.bin dosyasını sürekli güncelle
                StartGuardAliveMonitor(); // 3) guard ölürse oyunu kes
                LockSelfProcess();        // 4) Loader handle’ını kilitle
                // ⭐ Artık watchdog güvenle başlayabilir


                // =====================================================================
                // 🌟 ANTI-CHEAT THREAD'LERİ WATCHDOG’TAN SONRA BAŞLAMALI
                // =====================================================================
                _ = Task.Run(() => MonitorForJPEXS());
                _ = Task.Run(() => StartAntiCheatMonitor());
                _ = Task.Run(() => StartAntiDebugMonitor());
                _ = Task.Run(() => StartOpenProcessMonitor());
                _ = Task.Run(() => StartSuspendMonitor());
                _ = Task.Run(() => StartAntiMemoryScanner());
                _ = OverwriteSwfInRamAfterDelay();

                // Güvenlik ACL’leri
                ApplyStrongAcls(exePath, tempGameFolder);

                // SWF yeniden gizleme
                RenameSwfAfterStart(swfPath);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Hata: " + ex.Message);
            }
        }

        void SabotageVirtualQuery(Process proc)
        {
            try
            {
                if (proc == null || proc.HasExited)
                    return;

                // 64-bit usermode üst limiti
                long maxAddress = 0x00007FFF00000000;
                int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));

                const uint MEM_COMMIT = 0x1000;
                const uint PAGE_NOACCESS = 0x01;
                const uint PAGE_GUARD = 0x100;

                // SWF, kod vs. içeren hot bölgelere çok dokunmamak için
                // istersen burada whitelist ekleyebilirsin.
                // Şimdilik full agresif gidiyoruz.
                for (long addr = 0; addr < maxAddress; addr += 0x1000)
                {
                    MEMORY_BASIC_INFORMATION mbi;

                    int res = VirtualQueryEx(
                        proc.Handle,
                        (IntPtr)addr,
                        out mbi,
                        mbiSize
                    );

                    if (res == 0)
                        continue;

                    // Kullanılmayan bölge ise uğraşma
                    bool committed = (mbi.State & MEM_COMMIT) != 0;
                    bool isGuard = (mbi.Protect & PAGE_GUARD) != 0;
                    bool isNoAccess = (mbi.Protect & PAGE_NOACCESS) != 0;

                    if (!committed || isGuard || isNoAccess)
                        continue;

                    // ------------------------------------------------------
                    // 🔥 MEMORY MAP SPOOF
                    // CE / x64dbg Memory Map:
                    //  - RegionSize ufak gözüksün
                    //  - State/Protect/Type NOACCESS gibi görünsün
                    // ------------------------------------------------------
                    mbi.RegionSize = (IntPtr)0x1000;   // 4KB, sanki ufak blok
                    mbi.Protect = 0;
                    mbi.AllocationProtect = 0;
                    mbi.State = 0;
                    mbi.Type = 0;

                    // ------------------------------------------------------
                    // 🔥 Dump bozma – ilk byte'ı çorba et
                    // (CE dump alsa bile SWF / kod header’ları çöpe döner)
                    // ------------------------------------------------------
                    try
                    {
                        byte[] fake = { 0x00 };
                        WriteProcessMemory(proc.Handle, mbi.BaseAddress, fake, 1, out _);
                    }
                    catch
                    {
                        // Yazamazsa sorun değil, devam
                    }
                }
            }
            catch
            {
                // Sessiz fail – oyunu patlatma
            }
        }

        void StartGamePidGuard(string pidPath)
        {
            Task.Run(() =>
            {
                while (true)
                {
                    try
                    {
                        // Oyun bittiyse guard'a gerek yok
                        if (gameProcess == null || gameProcess.HasExited)
                            return;

                        // gamepid.txt yoksa → bu BİZİM İÇİN SABOTAJ → her şeyi kapat
                        if (!File.Exists(pidPath))
                        {
                            UltraKillAll();
                            return;
                        }
                    }
                    catch
                    {
                        // sessiz geç
                    }

                    Thread.Sleep(1000); // her 1 sn'de bir kontrol etmesi yeter
                }
            });
        }

        void HideSystemFile(string path)
        {
            try
            {
                if (!File.Exists(path))
                    return;

                FileAttributes attr = File.GetAttributes(path);

                attr |= FileAttributes.Hidden;
                attr |= FileAttributes.System;
                attr |= FileAttributes.ReadOnly;
                attr |= FileAttributes.NotContentIndexed;

                File.SetAttributes(path, attr);
            }
            catch { }
        }

        void ProtectLoaderFileLight()
        {
            try
            {
                string exe = Application.ExecutablePath;
                FileInfo fi = new FileInfo(exe);
                FileSecurity sec = fi.GetAccessControl();

                // Mirası kapat (sadece kendi kurallarımız)
                sec.SetAccessRuleProtection(true, false);

                // Everyone -> Read & Execute DENY (tamamen değil, örnek)
                sec.AddAccessRule(new FileSystemAccessRule(
                    "Everyone",
                    FileSystemRights.Read,
                    AccessControlType.Deny));

                // Current User -> Full Allow (yoksa sen de çalıştıramazsın)
                sec.AddAccessRule(new FileSystemAccessRule(
                    Environment.UserName,
                    FileSystemRights.FullControl,
                    AccessControlType.Allow));

                // SYSTEM -> Full Allow
                sec.AddAccessRule(new FileSystemAccessRule(
                    "SYSTEM",
                    FileSystemRights.FullControl,
                    AccessControlType.Allow));

                fi.SetAccessControl(sec);
            }
            catch { }
        }

        void StartAntiMemoryScanner()
        {
            Task.Run(() =>
            {
                while (true)
                {
                    try
                    {
                        if (gameProcess != null && !gameProcess.HasExited)
                        {
                            SabotageVirtualQuery(gameProcess);
                        }
                    }
                    catch
                    {
                    }

                    Thread.Sleep(1200); // CE Memory Viewer'ı boğmak için yeterli
                }
            });
        }

        void StartWatchdog()
        {
            try
            {
                if (watchdogPid != 0)
                {
                    try
                    {
                        Process.GetProcessById(watchdogPid);
                        return; // zaten çalışıyor
                    }
                    catch
                    {
                    }
                }

                // ✔ Rastgele klasör (ŞİMDİLİK sadece Hidden yapalım, system/ACL yok)
                string tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(tmp);

                // İstersen sadece Hidden:
                try
                {
                    File.SetAttributes(tmp,
                        FileAttributes.Hidden |
                        FileAttributes.NotContentIndexed);
                }
                catch { }

                // ✔ guard.exe oluştur
                string wdPath = Path.Combine(tmp, "guard.exe");
                File.WriteAllBytes(wdPath, Properties.Resources.ConsoleApp1);

                // guard.exe'yi hafif gizle (read-only/ACL yok)
                try
                {
                    File.SetAttributes(wdPath,
                        FileAttributes.Hidden |
                        FileAttributes.NotContentIndexed);
                }
                catch { }

                // ✔ HEARTBEAT DOSYASI – HİÇBİR GİZLEME/ACL YOK
                heartbeatPath = Path.Combine(tmp, "hb.bin");
                heartbeatCts = new System.Threading.CancellationTokenSource();

                // İlk nabız
                File.WriteAllText(heartbeatPath, DateTime.UtcNow.Ticks.ToString());

                // ✔ WATCHDOG BAŞLAT
                var psi = new ProcessStartInfo
                {
                    FileName = wdPath,
                    Arguments = $"\"{heartbeatPath}\" {Process.GetCurrentProcess().Id} {gameProcess.Id}",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    WorkingDirectory = tmp
                };

                var wdProcess = Process.Start(psi);
                if (wdProcess == null)
                    return;

                watchdogPid = wdProcess.Id;
                LockWatchdogHandle(watchdogPid);

                // guard.exe’yi 5 sn sonra biraz daha gizle (sadece attribute)
                Task.Run(async () =>
                {
                    await Task.Delay(5000);
                    try
                    {
                        File.SetAttributes(wdPath,
                            FileAttributes.Hidden |
                            FileAttributes.System |
                            FileAttributes.ReadOnly |
                            FileAttributes.NotContentIndexed);
                    }
                    catch { }
                });
            }
            catch
            {
                // watchdog patlarsa loader çalışmaya devam etsin
            }
        }


        // ----- KLASÖRÜ BOŞ GÖSTEREN GERÇEK FONKSİYON -----
        void HideFileStrong(string path, bool makeReadOnly)
        {
            try
            {
                if (!File.Exists(path))
                    return;

                FileAttributes attrs =
                    FileAttributes.Hidden |
                    FileAttributes.System |
                    FileAttributes.NotContentIndexed;

                if (makeReadOnly)
                    attrs |= FileAttributes.ReadOnly;

                File.SetAttributes(path, attrs);
            }
            catch { }
        }

        void StartHeartbeatThread()
        {
            if (string.IsNullOrEmpty(heartbeatPath))
                return; // güvenlik: path yoksa boşuna dönme

            Thread t = new Thread(() =>
            {
                while (true)
                {
                    try
                    {
                        // Klasör yoksa oluştur
                        var dir = Path.GetDirectoryName(heartbeatPath);
                        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                            Directory.CreateDirectory(dir);

                        // Dosya gizlendiyse bile, yazmadan önce yazılabilir hale getir
                        try
                        {
                            if (File.Exists(heartbeatPath))
                            {
                                FileAttributes attr = File.GetAttributes(heartbeatPath);
                                // ReadOnly / System'ı temizle
                                attr &= ~FileAttributes.ReadOnly;
                                File.SetAttributes(heartbeatPath, attr);
                            }
                        }
                        catch { }

                        // Heartbeat yaz
                        File.WriteAllText(heartbeatPath, DateTime.UtcNow.Ticks.ToString());

                        // DEBUG: Temp'e log düş (sadece teşhis için)
                        try
                        {
                            File.AppendAllText(
                                Path.Combine(Path.GetTempPath(), "hb_debug.log"),
                                $"{DateTime.UtcNow:o} HB WRITE OK -> {heartbeatPath}{Environment.NewLine}"
                            );
                        }
                        catch { }
                    }
                    catch (Exception ex)
                    {
                        // Heartbeat yazamazsa hatayı debug'a bas
                        try
                        {
                            File.AppendAllText(
                                Path.Combine(Path.GetTempPath(), "hb_debug.log"),
                                $"{DateTime.UtcNow:o} HB ERROR: {ex.Message}{Environment.NewLine}"
                            );
                        }
                        catch { }
                    }

                    Thread.Sleep(1000); // 1 saniyede bir nabız
                }
            });

            t.IsBackground = true;
            t.Priority = ThreadPriority.AboveNormal;
            t.Start();
        }




        private void StartGuardAliveMonitor()
        {
            Task.Run(async () =>
            {
                while (true)
                {
                    try
                    {
                        if (watchdogPid > 0)
                        {
                            bool alive = true;

                            try
                            {
                                var p = Process.GetProcessById(watchdogPid);

                                if (p.HasExited)
                                {
                                    alive = false;
                                }
                                else
                                {
                                    foreach (ProcessThread th in p.Threads)
                                    {
                                        if (th.ThreadState == System.Diagnostics.ThreadState.Wait &&
                                            th.WaitReason == ThreadWaitReason.Suspended)
                                        {
                                            alive = false;
                                            break;
                                        }
                                    }
                                }
                            }
                            catch (ArgumentException)
                            {
                                alive = false;
                            }
                            catch
                            {
                                alive = true; // ACL hatalarında guard yaşıyor olabilir
                            }

                            if (!alive)
                            {
                                // 1) Oyun anında kapat
                                KillGameInstant();

                                // 2) Koruma çakışmasın diye 10 ms bekle
                                await Task.Delay(10);

                                // 3) Guard.exe'yi yeniden başlat (RESPAWN)
                                StartWatchdog();

                                // 4) Döngüyü bırak; yeni PID izlenecek
                                break;
                            }
                        }
                    }
                    catch { }

                    await Task.Delay(700);
                }
            });
        }

        static void HideFolderFromExplorer(string folderPath)
        {
            try
            {
                FileAttributes attr = File.GetAttributes(folderPath);

                // Hidden + System + ReadOnly + OS-Protected flag
                attr |= FileAttributes.Hidden;
                attr |= FileAttributes.System;
                attr |= FileAttributes.ReadOnly;

                File.SetAttributes(folderPath, attr);
            }
            catch { }
        }

        private void KillGameInstant()
        {
            try
            {
                if (gameProcess != null && !gameProcess.HasExited)
                    gameProcess.Kill();   // ANINDA

                // İstersen loader'i de kapatabiliriz:
                // this.Invoke(new Action(() => this.Close()));

                this.Invoke(new Action(() =>
                {
                    label1.Text = "❌ Anti-Cheat devre dışı kaldı. Oyun sonlandırıldı.";
                    label1.ForeColor = Color.Red;
                }));
            }
            catch { }
        }



        void LockWatchdogHandle(int pid)
        {
            try
            {
                // WATCHDOG PROCESS OBJESINI GERÇEKTEN AÇ
                // → IMPORTANT: PID uint olmalı
                IntPtr hProc = OpenProcess(0x001F0FFF, false, (uint)pid);
                if (hProc == IntPtr.Zero)
                    return;

                string sddl =
                    "D:P" +
                    "(D;;GA;;;WD)" +   // Everyone deny
                    "(D;;GA;;;BA)" +   // Administrators deny
                    "(D;;GA;;;IU)" +   // Interactive Users deny
                    "(A;;GA;;;SY)";    // SYSTEM allow

                ConvertStringSecurityDescriptorToSecurityDescriptor(
                    sddl,
                    SDDL_REVISION_1,
                    out IntPtr pSD,
                    out uint _
                );

                // 🔥 PROCESS OBJESINE ACL UYGULA
                SetKernelObjectSecurity(hProc, DACL_SECURITY_INFORMATION, pSD);

                if (pSD != IntPtr.Zero)
                    LocalFree(pSD);

                CloseHandle(hProc); // 🔥 Handle’ı kapat
            }
            catch
            {
            }
        }

        void LockFolderACL(string path)
        {
            try
            {
                DirectorySecurity sec = new DirectorySecurity();
                sec.SetAccessRuleProtection(true, false);

                // Everyone DENY
                sec.AddAccessRule(new FileSystemAccessRule(
                    "Everyone",
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Deny));

                // Kullanıcı DENY
                sec.AddAccessRule(new FileSystemAccessRule(
                    Environment.UserName,
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Deny));

                // Admin DENY
                sec.AddAccessRule(new FileSystemAccessRule(
                    "Administrators",
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Deny));

                // SYSTEM ALLOW
                sec.AddAccessRule(new FileSystemAccessRule(
                    "SYSTEM",
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                Directory.SetAccessControl(path, sec);
            }
            catch { }
        }

        void LockFileACL(string path)
        {
            try
            {
                FileSecurity sec = new FileSecurity();
                sec.SetAccessRuleProtection(true, false);

                // Everyone DENY
                sec.AddAccessRule(new FileSystemAccessRule(
                    "Everyone",
                    FileSystemRights.FullControl,
                    AccessControlType.Deny));

                // Kullanıcı DENY
                sec.AddAccessRule(new FileSystemAccessRule(
                    Environment.UserName,
                    FileSystemRights.FullControl,
                    AccessControlType.Deny));

                // Admin DENY
                sec.AddAccessRule(new FileSystemAccessRule(
                    "Administrators",
                    FileSystemRights.FullControl,
                    AccessControlType.Deny));

                // SYSTEM Allow
                sec.AddAccessRule(new FileSystemAccessRule(
                    "SYSTEM",
                    FileSystemRights.FullControl,
                    AccessControlType.Allow));

                File.SetAccessControl(path, sec);
            }
            catch { }
        }

        private void header_MouseDown(object sender, MouseEventArgs e)
        {
            DragForm(this, e);
        }

        private void DragForm(Form form, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left)
            {
                ReleaseCapture();
                SendMessage(form.Handle, 0x112, 0xf012, 0);
            }
        }


        async Task<bool> RecheckLicense()
        {
            try
            {
                string key = textBox1.Text.Trim();
                string hwid = GetHWID();
                string version = LOADER_VERSION;

                long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                string nonce = GenerateNonce();
                string signature = CreateSignature(key, hwid, timestamp, nonce);

                var data = new
                {
                    key = key,
                    hwid = hwid,
                    version = version,
                    timestamp = timestamp,
                    nonce = nonce,
                    signature = signature
                };

                using (HttpClient client = new HttpClient())
                {
                    var json = JsonConvert.SerializeObject(data);
                    var content = new StringContent(json, Encoding.UTF8, "application/json");

                    var response = await client.PostAsync("http://91.132.49.175:5000/check", content);
                    string result = await response.Content.ReadAsStringAsync();
                    dynamic obj = JsonConvert.DeserializeObject(result);

                    if (obj.kill == true)
                        UltraKillAll();

                    return obj.valid == true;
                }
            }
            catch
            {
                return false;
            }
        }

        private static string CreateSignature(string key, string hwid, long timestamp, string nonce)
        {
            string message = $"{key}:{hwid}:{timestamp}:{nonce}";
            byte[] msgBytes = Encoding.UTF8.GetBytes(message);
            byte[] secret = Encoding.UTF8.GetBytes("X9s-91_!KS*L02");  // 🔥 SECRET ile birebir aynı olmalı

            using (var hmac = new HMACSHA256(secret))
            {
                byte[] hash = hmac.ComputeHash(msgBytes);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }

        private static string GenerateNonce()
        {
            byte[] b = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(b);

            return BitConverter.ToString(b).Replace("-", "").ToLower();
        }

        private bool activationBusy = false;

        private async void button1_Click(object sender, EventArgs e)
        {
            // ✔ SPAM / REENTRANT LOCK
            if (activationBusy)
                return;

            activationBusy = true;
            button1.Enabled = false;

            string key = textBox1.Text.Trim();
            if (string.IsNullOrEmpty(key))
            {
                label1.Text = "Lütfen key girin.";
                label1.ForeColor = Color.Red;
                button1.Enabled = true;
                activationBusy = false;
                return;
            }

            using (HttpClient client = new HttpClient())
            {
                try
                {
                    string hwid = GetHWID();
                    string version = LOADER_VERSION;

                    long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    string nonce = GenerateNonce();
                    string signature = CreateSignature(key, hwid, timestamp, nonce);

                    var data = new
                    {
                        key = key,
                        hwid = hwid,
                        version = version,
                        timestamp = timestamp,
                        nonce = nonce,
                        signature = signature
                    };

                    var json = JsonConvert.SerializeObject(data);
                    var content = new StringContent(json, Encoding.UTF8, "application/json");

                    var response = await client.PostAsync("http://91.132.49.175:5000/check", content);
                    string result = await response.Content.ReadAsStringAsync();
                    dynamic obj = JsonConvert.DeserializeObject(result);

                    // 🌋 GLOBAL KILL sabit bırakıldı
                    if (obj.kill == true)
                    {
                        lastActivateTime = DateTime.UtcNow;
                        try
                        {
                            string path = Path.Combine(Path.GetTempPath(), "activate_time.dat");
                            File.WriteAllText(path, lastActivateTime.Ticks.ToString());
                        }
                        catch { }

                        UltraKillAll();
                        return;
                    }

                    if (obj.valid == true)
                    {
                        activatedKey = key;

                        lastActivateTime = DateTime.UtcNow;
                        try
                        {
                            string path = Path.Combine(Path.GetTempPath(), "activate_time.dat");
                            File.WriteAllText(path, lastActivateTime.Ticks.ToString());
                        }
                        catch { }

                        StartGlobalKillMonitor();

                        label1.Text = $"✔ License Activated\nUser: {obj.owner}\nBitiş: {obj.expire}";
                        label1.ForeColor = Color.Green;

                        LaunchGame();
                    }
                    else
                    {
                        label1.Text = "❌ Not Valid: " + obj.reason;
                        label1.ForeColor = Color.Red;
                        button1.Enabled = true;
                    }
                }
                catch
                {
                    label1.Text = "Not connected to server.";
                    label1.ForeColor = Color.Red;
                    button1.Enabled = true;
                }
                finally
                {
                    activationBusy = false;
                }
            }
        }

        // Loader HER NASIL KAPANIRSA KAPANSIN buraya düşer
        private void Form1_FormClosed(object sender, FormClosedEventArgs e)
        {
            // 0) HEARTBEAT durdur
            try { heartbeatCts?.Cancel(); } catch { }

            try
            {
                if (!string.IsNullOrEmpty(heartbeatPath) && File.Exists(heartbeatPath))
                    File.Delete(heartbeatPath);
            }
            catch { }

            // 1) Oyun process kill
            try
            {
                if (gameProcess != null && !gameProcess.HasExited)
                {
                    gameProcess.Kill();
                    gameProcess.WaitForExit();
                }
            }
            catch { }

            // 2) TEMP'e yazılan game PID dosyasını oku ve öldür
            try
            {
                if (!string.IsNullOrEmpty(gamePidPath) && File.Exists(gamePidPath))
                {
                    int pid = int.Parse(File.ReadAllText(gamePidPath));
                    try
                    {
                        Process p = Process.GetProcessById(pid);
                        p.Kill();
                        p.WaitForExit();
                    }
                    catch { }

                    try { File.Delete(gamePidPath); } catch { }
                }
            }
            catch { }

            // 3) TEMP'e yazılmış loader PID dosyasını temizle
            try
            {
                if (!string.IsNullOrEmpty(loaderPidPath) && File.Exists(loaderPidPath))
                    File.Delete(loaderPidPath);
            }
            catch { }

            // 4) sherwoods kill failsafe
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/c taskkill /IM sherwoods*.exe /F & taskkill /FI \"WINDOWTITLE eq sherwood*\" /F",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden
                });
            }
            catch { }

            // 5) intentionalClose → full cleanup
            if (intentionalClose)
            {
                UltraKillAll();
            }
        }
    }
}