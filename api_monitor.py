# api_monitor.py - GELİŞMİŞ FRIDA API HOOKING SİSTEMİ
# Şüpheli işlemlerin Windows API çağrılarını kategorize ederek canlı yakalar.
# Desteklenen kategoriler: Injection, File, Network, Registry, Process, Anti-Analysis, Crypto
import time
import threading
import json
import os
from typing import Set, Dict, Optional
from datetime import datetime

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False


# =====================================================
# API TANIMLARI VE KATEGORİLER
# =====================================================
# Her hook'un severity seviyesi:
#   CRITICAL = Injection / Process Hollowing / AV Kill
#   HIGH     = File drop, network C2, credential theft
#   MEDIUM   = Registry modification, process creation
#   LOW      = Bilgi toplama, anti-analysis kontrol

API_HOOKS = [
    # === PROCESS INJECTION ===
    {"mod": "kernel32.dll", "func": "CreateRemoteThread",     "cat": "injection",    "sev": "CRITICAL", "type": "ansi"},
    {"mod": "ntdll.dll",    "func": "NtCreateThreadEx",       "cat": "injection",    "sev": "CRITICAL", "type": "ansi"},
    {"mod": "kernel32.dll", "func": "VirtualAllocEx",         "cat": "injection",    "sev": "CRITICAL", "type": "ansi"},
    {"mod": "kernel32.dll", "func": "VirtualAlloc",           "cat": "injection",    "sev": "HIGH",     "type": "ansi"},
    {"mod": "kernel32.dll", "func": "WriteProcessMemory",     "cat": "injection",    "sev": "CRITICAL", "type": "ansi"},
    {"mod": "ntdll.dll",    "func": "NtWriteVirtualMemory",   "cat": "injection",    "sev": "CRITICAL", "type": "ansi"},
    {"mod": "ntdll.dll",    "func": "NtMapViewOfSection",     "cat": "injection",    "sev": "HIGH",     "type": "ansi"},
    {"mod": "kernel32.dll", "func": "QueueUserAPC",           "cat": "injection",    "sev": "CRITICAL", "type": "ansi"},
    {"mod": "user32.dll",   "func": "SetWindowsHookExW",      "cat": "injection",    "sev": "HIGH",     "type": "unicode"},

    # === DLL LOADING ===
    {"mod": "kernel32.dll", "func": "LoadLibraryA",           "cat": "dll_load",     "sev": "MEDIUM",   "type": "ansi"},
    {"mod": "kernel32.dll", "func": "LoadLibraryW",           "cat": "dll_load",     "sev": "MEDIUM",   "type": "unicode"},
    {"mod": "kernel32.dll", "func": "LoadLibraryExW",         "cat": "dll_load",     "sev": "MEDIUM",   "type": "unicode"},

    # === PROCESS CREATION ===
    {"mod": "kernel32.dll", "func": "CreateProcessW",         "cat": "process",      "sev": "HIGH",     "type": "unicode"},
    {"mod": "kernel32.dll", "func": "CreateProcessA",         "cat": "process",      "sev": "HIGH",     "type": "ansi"},
    {"mod": "shell32.dll",  "func": "ShellExecuteW",          "cat": "process",      "sev": "HIGH",     "type": "unicode"},
    {"mod": "shell32.dll",  "func": "ShellExecuteExW",        "cat": "process",      "sev": "HIGH",     "type": "unicode"},
    {"mod": "kernel32.dll", "func": "WinExec",                "cat": "process",      "sev": "HIGH",     "type": "ansi"},
    {"mod": "kernel32.dll", "func": "ResumeThread",           "cat": "process",      "sev": "HIGH",     "type": "ansi"},

    # === FILE OPERATIONS ===
    {"mod": "kernel32.dll", "func": "CreateFileW",            "cat": "file",         "sev": "MEDIUM",   "type": "unicode"},
    {"mod": "kernel32.dll", "func": "DeleteFileW",            "cat": "file",         "sev": "HIGH",     "type": "unicode"},
    {"mod": "kernel32.dll", "func": "MoveFileExW",            "cat": "file",         "sev": "MEDIUM",   "type": "unicode"},
    {"mod": "kernel32.dll", "func": "CopyFileW",              "cat": "file",         "sev": "MEDIUM",   "type": "unicode"},

    # === NETWORK ===
    {"mod": "wininet.dll",  "func": "InternetOpenUrlW",       "cat": "network",      "sev": "HIGH",     "type": "unicode"},
    {"mod": "urlmon.dll",   "func": "URLDownloadToFileW",     "cat": "network",      "sev": "CRITICAL", "type": "unicode"},
    {"mod": "ws2_32.dll",   "func": "connect",                "cat": "network",      "sev": "MEDIUM",   "type": "ansi"},
    {"mod": "ws2_32.dll",   "func": "send",                   "cat": "network",      "sev": "LOW",      "type": "ansi"},
    {"mod": "winhttp.dll",  "func": "WinHttpConnect",         "cat": "network",      "sev": "MEDIUM",   "type": "unicode"},

    # === REGISTRY ===
    {"mod": "advapi32.dll", "func": "RegSetValueExW",         "cat": "registry",     "sev": "HIGH",     "type": "unicode"},
    {"mod": "advapi32.dll", "func": "RegCreateKeyExW",        "cat": "registry",     "sev": "MEDIUM",   "type": "unicode"},
    {"mod": "advapi32.dll", "func": "RegDeleteValueW",        "cat": "registry",     "sev": "HIGH",     "type": "unicode"},

    # === ANTI-ANALYSIS / EVASION ===
    {"mod": "kernel32.dll", "func": "IsDebuggerPresent",      "cat": "anti_analysis","sev": "LOW",      "type": "ansi"},
    {"mod": "kernel32.dll", "func": "CheckRemoteDebuggerPresent", "cat": "anti_analysis", "sev": "MEDIUM", "type": "ansi"},
    {"mod": "ntdll.dll",    "func": "NtQueryInformationProcess","cat": "anti_analysis","sev": "LOW",     "type": "ansi"},
    {"mod": "kernel32.dll", "func": "GetTickCount",           "cat": "anti_analysis","sev": "LOW",      "type": "ansi"},

    # === CREDENTIAL / CRYPTO ===
    {"mod": "crypt32.dll",  "func": "CryptUnprotectData",     "cat": "credential",   "sev": "CRITICAL", "type": "ansi"},
    {"mod": "advapi32.dll", "func": "CredEnumerateW",         "cat": "credential",   "sev": "HIGH",     "type": "unicode"},

    # === SERVICE MANIPULATION ===
    {"mod": "advapi32.dll", "func": "OpenServiceW",           "cat": "service",      "sev": "MEDIUM",   "type": "unicode"},
    {"mod": "advapi32.dll", "func": "StartServiceW",          "cat": "service",      "sev": "HIGH",     "type": "unicode"},

    # === AV/DEFENDER TAMPERING ===
    {"mod": "kernel32.dll", "func": "TerminateProcess",       "cat": "process_kill", "sev": "CRITICAL", "type": "ansi"},
]

# Kategori açıklamaları (Türkçe)
CATEGORY_LABELS = {
    "injection":     "💉 İşlem Enjeksiyonu",
    "dll_load":      "📦 DLL Yükleme",
    "process":       "🔄 Süreç Oluşturma",
    "file":          "📁 Dosya İşlemi",
    "network":       "🌐 Ağ İletişimi",
    "registry":      "🔑 Registry Değişikliği",
    "anti_analysis": "🕵️ Anti-Analiz",
    "credential":    "🔓 Kimlik Bilgisi Erişimi",
    "service":       "⚙️ Servis İşlemi",
    "process_kill":  "💀 Süreç Sonlandırma",
}


class ApiMonitor:
    """
    Gelişmiş Frida tabanlı dinamik analiz modülü.
    
    Yüksek riskli süreçlere attach olup 35+ Windows API'sini
    kategorize ederek yakalar. Process hollowing zincirlerini
    tespit eder ve severity bazlı loglama yapar.
    
    Desteklenen kategoriler:
    - Injection (CreateRemoteThread, VirtualAllocEx, WriteProcessMemory, ...)
    - Process (CreateProcessW, ShellExecuteW, ResumeThread, ...)
    - File (CreateFileW, DeleteFileW, MoveFileExW, ...)
    - Network (InternetOpenUrlW, URLDownloadToFileW, connect, ...)
    - Registry (RegSetValueExW, RegCreateKeyExW, ...)
    - Anti-Analysis (IsDebuggerPresent, NtQueryInformationProcess, ...)
    - Credential (CryptUnprotectData, CredEnumerateW, ...)
    - Service (OpenServiceW, StartServiceW)
    """

    def __init__(self, config=None, logger=None):
        from config import Config
        self.config = config or Config()
        self.logger = logger

        # Hook'lanmış PID'ler
        self.hooked_pids: Set[int] = set()
        self.lock = threading.Lock()

        # Aktif Frida oturumları (temiz kapatma için)
        self.sessions: Dict[int, object] = {}  # pid -> frida.Session

        # Process Hollowing zincir tespiti
        # pid -> {VirtualAllocEx: True, WriteProcessMemory: True, ResumeThread: True}
        self.hollowing_tracker: Dict[int, Dict[str, bool]] = {}

        # Her PID'in API çağrı istatistikleri
        self.api_stats: Dict[int, Dict[str, int]] = {}  # pid -> {api_name: count}

        # Config'den mi yoksa yerleşik tanımlardan mı hook listesi alalım
        if hasattr(self.config, 'api_monitor_hooks') and self.config.api_monitor_hooks:
            self.hook_defs = self.config.api_monitor_hooks
        else:
            self.hook_defs = API_HOOKS

        # Frida JS payload'ı oluştur
        self.js_payload = self._generate_payload()

    # =====================================================
    # FRIDA JAVASCRIPT PAYLOAD ÜRETİCİ
    # =====================================================
    def _generate_payload(self) -> str:
        """API tanımlarından dinamik Frida JavaScript payload'ı üretir."""
        hooks_json = json.dumps(self.hook_defs)

        return f"""
        // === ThreadDetector Frida Payload v3.0 ===

        function readUnicode(ptr) {{
            try {{ return ptr.readUtf16String(); }} catch(e) {{ return "[unreadable]"; }}
        }}

        function readAnsi(ptr) {{
            try {{ return ptr.readAnsiString(); }} catch(e) {{ return "[unreadable]"; }}
        }}

        function readStr(ptr, type) {{
            return type === 'unicode' ? readUnicode(ptr) : readAnsi(ptr);
        }}

        function ptrStr(ptr) {{
            return ptr ? ptr.toString() : "null";
        }}

        const hooks = {hooks_json};
        let hookCount = 0;

        hooks.forEach(function(api) {{
            let apiPtr = Module.findExportByName(api.mod, api.func);
            if (!apiPtr) return;

            try {{
                Interceptor.attach(apiPtr, {{
                    onEnter: function(args) {{
                        let data = {{}};

                        // === INJECTION ===
                        if (api.func === 'CreateRemoteThread' || api.func === 'NtCreateThreadEx') {{
                            data["hProcess"] = ptrStr(args[0]);
                            data["lpStartAddress"] = ptrStr(args[3]);
                        }}
                        else if (api.func === 'VirtualAllocEx') {{
                            data["hProcess"] = ptrStr(args[0]);
                            data["lpAddress"] = ptrStr(args[1]);
                            data["dwSize"] = args[2].toInt32();
                            data["flProtect"] = "0x" + args[4].toInt32().toString(16);
                        }}
                        else if (api.func === 'VirtualAlloc') {{
                            data["lpAddress"] = ptrStr(args[0]);
                            data["dwSize"] = args[1].toInt32();
                            data["flProtect"] = "0x" + args[3].toInt32().toString(16);
                        }}
                        else if (api.func === 'WriteProcessMemory' || api.func === 'NtWriteVirtualMemory') {{
                            data["hProcess"] = ptrStr(args[0]);
                            data["lpBaseAddress"] = ptrStr(args[1]);
                            data["nSize"] = args[3].toInt32();
                        }}
                        else if (api.func === 'QueueUserAPC') {{
                            data["pfnAPC"] = ptrStr(args[0]);
                            data["hThread"] = ptrStr(args[1]);
                        }}
                        else if (api.func === 'SetWindowsHookExW') {{
                            data["idHook"] = args[0].toInt32();
                            data["hMod"] = ptrStr(args[2]);
                            data["dwThreadId"] = args[3].toInt32();
                        }}

                        // === DLL LOADING ===
                        else if (api.func.includes('LoadLibrary')) {{
                            data["LibraryPath"] = readStr(args[0], api.type);
                        }}

                        // === PROCESS CREATION ===
                        else if (api.func === 'CreateProcessW' || api.func === 'CreateProcessA') {{
                            data["lpApplicationName"] = readStr(args[0], api.type);
                            data["lpCommandLine"] = readStr(args[1], api.type);
                            data["dwCreationFlags"] = "0x" + args[5].toInt32().toString(16);
                        }}
                        else if (api.func === 'ShellExecuteW' || api.func === 'ShellExecuteExW') {{
                            data["lpOperation"] = readUnicode(args[1]);
                            data["lpFile"] = readUnicode(args[2]);
                            data["lpParameters"] = readUnicode(args[3]);
                        }}
                        else if (api.func === 'WinExec') {{
                            data["lpCmdLine"] = readAnsi(args[0]);
                            data["uCmdShow"] = args[1].toInt32();
                        }}
                        else if (api.func === 'ResumeThread') {{
                            data["hThread"] = ptrStr(args[0]);
                        }}

                        // === FILE OPERATIONS ===
                        else if (api.func === 'CreateFileW') {{
                            data["lpFileName"] = readUnicode(args[0]);
                            data["dwDesiredAccess"] = "0x" + args[1].toInt32().toString(16);
                            data["dwCreationDisposition"] = args[4].toInt32();
                        }}
                        else if (api.func === 'DeleteFileW') {{
                            data["lpFileName"] = readUnicode(args[0]);
                        }}
                        else if (api.func === 'MoveFileExW') {{
                            data["lpExistingFileName"] = readUnicode(args[0]);
                            data["lpNewFileName"] = readUnicode(args[1]);
                        }}
                        else if (api.func === 'CopyFileW') {{
                            data["lpExistingFileName"] = readUnicode(args[0]);
                            data["lpNewFileName"] = readUnicode(args[1]);
                        }}

                        // === NETWORK ===
                        else if (api.func === 'InternetOpenUrlW') {{
                            data["lpszUrl"] = readUnicode(args[1]);
                        }}
                        else if (api.func === 'URLDownloadToFileW') {{
                            data["szURL"] = readUnicode(args[1]);
                            data["szFileName"] = readUnicode(args[2]);
                        }}
                        else if (api.func === 'connect') {{
                            // sockaddr_in yapısından IP:port çıkarma
                            try {{
                                let family = args[1].readU16();
                                if (family === 2) {{ // AF_INET
                                    let port = (args[1].add(2).readU8() << 8) | args[1].add(3).readU8();
                                    let ip = args[1].add(4).readU8() + "." +
                                             args[1].add(5).readU8() + "." +
                                             args[1].add(6).readU8() + "." +
                                             args[1].add(7).readU8();
                                    data["destination"] = ip + ":" + port;
                                }}
                            }} catch(e) {{
                                data["destination"] = "[parse_error]";
                            }}
                        }}
                        else if (api.func === 'send') {{
                            data["len"] = args[2].toInt32();
                        }}
                        else if (api.func === 'WinHttpConnect') {{
                            data["pswzServerName"] = readUnicode(args[1]);
                            data["nServerPort"] = args[2].toInt32();
                        }}

                        // === REGISTRY ===
                        else if (api.func === 'RegSetValueExW') {{
                            data["lpValueName"] = readUnicode(args[1]);
                            data["dwType"] = args[3].toInt32();
                            data["cbData"] = args[5].toInt32();
                        }}
                        else if (api.func === 'RegCreateKeyExW') {{
                            data["lpSubKey"] = readUnicode(args[1]);
                        }}
                        else if (api.func === 'RegDeleteValueW') {{
                            data["lpValueName"] = readUnicode(args[1]);
                        }}

                        // === SERVICE ===
                        else if (api.func === 'OpenServiceW' || api.func === 'StartServiceW') {{
                            data["lpServiceName"] = readUnicode(args[1]);
                        }}

                        // === PROCESS KILL ===
                        else if (api.func === 'TerminateProcess') {{
                            data["hProcess"] = ptrStr(args[0]);
                            data["uExitCode"] = args[1].toInt32();
                        }}

                        // === ANTI-ANALYSIS (argümansız) ===
                        // IsDebuggerPresent, GetTickCount vb. sadece çağrıldığını bilmek yeterli

                        send({{
                            api_name: api.func,
                            category: api.cat,
                            severity: api.sev,
                            arguments: data,
                            timestamp: Date.now()
                        }});
                    }}
                }});
                hookCount++;
            }} catch(e) {{
                // Hook başarısız — modül belleğe yüklenmemiş olabilir
            }}
        }});

        send({{
            api_name: "__hook_summary__",
            category: "system",
            severity: "INFO",
            arguments: {{ "total_hooks_installed": hookCount, "total_hooks_defined": hooks.length }},
            timestamp: Date.now()
        }});
        """

    # =====================================================
    # DURUM KONTROLÜ
    # =====================================================
    def is_available(self) -> bool:
        return FRIDA_AVAILABLE and self.config.api_monitor_aktif

    # =====================================================
    # PROCESS HOLLOWING ZİNCİR TESPİTİ
    # =====================================================
    def _check_hollowing_chain(self, pid: int, process_name: str, api_name: str):
        """
        Process Hollowing klasik zincirini izler:
        CreateProcess(SUSPENDED) → VirtualAllocEx → WriteProcessMemory → ResumeThread
        
        Bu 4 adımın aynı PID'den peş peşe gelmesi → hollowing tespiti.
        """
        hollowing_apis = {
            "CreateProcessW", "CreateProcessA",  # Adım 1
            "VirtualAllocEx",                     # Adım 2
            "WriteProcessMemory", "NtWriteVirtualMemory",  # Adım 3
            "ResumeThread",                       # Adım 4
        }

        if api_name not in hollowing_apis:
            return

        if pid not in self.hollowing_tracker:
            self.hollowing_tracker[pid] = {}

        self.hollowing_tracker[pid][api_name] = True
        chain = self.hollowing_tracker[pid]

        # CreateProcess + VirtualAllocEx + WriteProcessMemory + ResumeThread = HOLLOWING
        has_create = any(k in chain for k in ["CreateProcessW", "CreateProcessA"])
        has_alloc = "VirtualAllocEx" in chain
        has_write = any(k in chain for k in ["WriteProcessMemory", "NtWriteVirtualMemory"])
        has_resume = "ResumeThread" in chain

        if has_create and has_alloc and has_write and has_resume:
            alarm = (
                f"🚨 PROCESS HOLLOWING TESPİTİ: {process_name} (PID: {pid}) — "
                f"CreateProcess→VirtualAllocEx→WriteProcessMemory→ResumeThread zinciri tamamlandı!"
            )
            if self.logger:
                self.logger.log_api_call(pid, process_name, "PROCESS_HOLLOWING_CHAIN", 
                                          {"chain": list(chain.keys())})
                self.logger.log_monitor_alarm("api_monitor", alarm, "CRITICAL")
            else:
                print(f"[!!! CRITICAL] {alarm}")

            # Tracker'ı sıfırla
            self.hollowing_tracker[pid] = {}

    # =====================================================
    # MESAJ CALLBACK
    # =====================================================
    def _on_message(self, message, data, pid: int, process_name: str):
        """Frida scriptinden gelen JSON mesajlarını işleyen callback."""
        if message.get('type') == 'send':
            payload = message.get('payload', {})
            api_name = payload.get('api_name', 'UnknownAPI')
            category = payload.get('category', 'unknown')
            severity = payload.get('severity', 'LOW')
            args = payload.get('arguments', {})

            # Hook özet mesajı (ilk yüklemede)
            if api_name == "__hook_summary__":
                installed = args.get('total_hooks_installed', 0)
                defined = args.get('total_hooks_defined', 0)
                if self.logger:
                    self.logger.log_system(
                        f"Frida: {process_name} (PID:{pid}) — {installed}/{defined} hook aktif",
                        "INFO"
                    )
                return

            # API istatistik sayacı
            with self.lock:
                if pid not in self.api_stats:
                    self.api_stats[pid] = {}
                self.api_stats[pid][api_name] = self.api_stats[pid].get(api_name, 0) + 1

            # Process Hollowing zincir kontrolü
            self._check_hollowing_chain(pid, process_name, api_name)

            # Kategori etiketi
            cat_label = CATEGORY_LABELS.get(category, category)

            # Logger'a aktar
            if self.logger:
                self.logger.log_api_call(
                    pid, process_name, api_name, args,
                    return_val=f"[{severity}] {cat_label}"
                )
            else:
                print(f"[API] [{severity}] {cat_label} | {process_name}:{pid} → {api_name} {args}")

        elif message.get('type') == 'error':
            desc = message.get('description', 'Unknown error')
            if "unable to find" not in desc.lower():  # Modül bulunamadı hataları sessizce geç
                if self.logger:
                    self.logger.log_system(f"Frida script error in {process_name}: {desc}", "WARNING")

    # =====================================================
    # SÜREÇ BAĞLANTI (ATTACH)
    # =====================================================
    def _attach_thread(self, pid: int, process_name: str):
        """Asenkron olarak sürece bağlanıp scripti çalıştırır."""
        session = None
        try:
            device = frida.get_local_device()
            session = device.attach(pid)

            # Oturumu kaydet (detach için)
            with self.lock:
                self.sessions[pid] = session

            # Oturum koptuğunda temizlik
            def on_detached(reason):
                with self.lock:
                    self.hooked_pids.discard(pid)
                    self.sessions.pop(pid, None)
                if self.logger:
                    self.logger.log_system(
                        f"Frida detached from {process_name} (PID:{pid}): {reason}", "INFO"
                    )

            session.on('detached', on_detached)

            script = session.create_script(self.js_payload)
            script.on('message', lambda msg, data: self._on_message(msg, data, pid, process_name))
            script.load()

            if self.logger:
                self.logger.log_system(
                    f"API Monitor hooked: {process_name} (PID: {pid})", "INFO"
                )

        except frida.ProcessNotFoundError:
            if self.logger:
                self.logger.log_system(f"Process {pid} ended before hook.", "INFO")
            with self.lock:
                self.hooked_pids.discard(pid)
                self.sessions.pop(pid, None)
        except Exception as e:
            err = str(e).lower()
            if "access denied" in err or "not supported" in err or "unable to" in err:
                pass  # Sistem/AV süreci, Frida erişemiyor
            elif self.logger:
                self.logger.log_system(f"Frida hook error: {process_name} ({pid}): {e}", "WARNING")
            with self.lock:
                self.hooked_pids.discard(pid)
                self.sessions.pop(pid, None)

    # =====================================================
    # PUBLIC API
    # =====================================================
    def hook_process(self, pid: int, process_name: str):
        """İlgili PID için Frida dinlemesi başlatır."""
        if not self.is_available():
            return

        with self.lock:
            if pid in self.hooked_pids:
                return
            self.hooked_pids.add(pid)

        t = threading.Thread(target=self._attach_thread, args=(pid, process_name), daemon=True)
        t.start()

    def detach_all(self):
        """Tüm Frida oturumlarını temiz şekilde kapatır."""
        with self.lock:
            for pid, session in list(self.sessions.items()):
                try:
                    session.detach()
                except Exception:
                    pass
            self.sessions.clear()
            self.hooked_pids.clear()

    def get_stats(self) -> Dict:
        """Hook istatistiklerini döndürür."""
        with self.lock:
            return {
                "hooked_count": len(self.hooked_pids),
                "total_api_calls": sum(
                    sum(apis.values()) for apis in self.api_stats.values()
                ),
                "per_process": {
                    pid: dict(apis) for pid, apis in self.api_stats.items()
                },
                "hollowing_suspects": len(self.hollowing_tracker),
            }
