# config.py - MERKEZİ YAPILANDIRMA SİSTEMİ
from dataclasses import dataclass, field
from typing import List

@dataclass
class Config:
    """ThreadDetector projesi için merkezi yapılandırma."""

    # --- AI MODEL PARAMETRELERİ ---
    model_path: str = "sentinel_model.pkl"
    data_path: str = "normal_veri_havuzu.npy"
    ai_n_estimators: int = 200
    ai_contamination: float = 0.01
    ai_egitim_suresi: int = 20  # saniye
    ai_min_sample: int = 10

    # --- SÜREÇ İZLEME EŞİK DEĞERLERİ ---
    cpu_threshold: float = 30.0
    ram_threshold: float = 20.0
    disk_threshold: float = 5.0  # MB/s
    conn_threshold: int = 10
    risk_threshold: float = 50.0
    ai_anomaly_threshold: float = -0.15

    # --- YARA ---
    yara_kural_dosyasi: str = "thor-hacktools.yar"
    yara_timeout: int = 60
    yara_cache_limit: int = 5000

    # --- HONEYPOT ---
    honeypot_dosyasi: str = "gizli_sifreler_SAKIN_DOKUNMA.txt"

    # --- LOGLAMA ---
    log_dir: str = "logs"
    log_max_bytes: int = 10 * 1024 * 1024  # 10 MB
    log_backup_count: int = 5

    # --- AĞ SNIFFER ---
    sniffer_aktif: bool = True
    dns_analiz_aktif: bool = True
    c2_beacon_penceresi: int = 300  # saniye
    c2_min_tekrar: int = 5
    c2_tolerans: float = 2.0  # saniye

    yasakli_kelimeler: List[bytes] = field(default_factory=lambda: [
        b"UNION SELECT", b"SELECT * FROM",       # SQL Injection
        b"<script>", b"alert(",                   # XSS
        b"cmd.exe", b"powershell",               # RCE
        b"/etc/passwd", b"whoami",               # Linux Saldırıları
        b"eval(", b"base64_decode",              # Obfuscation
        b"User-Agent: sqlmap",                    # Hack Araçları
        b"User-Agent: Nikto",
        b"Hack", b"Hacked",
        b"DROP TABLE", b"INSERT INTO",           # SQL
        b"wget ", b"curl ",                       # İndirme
        b"nc -e", b"bash -i",                    # Reverse Shell
        b"/bin/sh", b"/bin/bash",
    ])

    # --- DOSYA SİSTEMİ İZLEME ---
    file_monitor_aktif: bool = True
    izlenen_dizinler: List[str] = field(default_factory=lambda: [
        "C:\\Windows\\System32",
        "C:\\Windows\\Temp",
    ])
    ransomware_esik: int = 10        # Bu kadar dosya kısa sürede değişirse alarm
    ransomware_pencere: int = 5      # saniye

    # --- REGISTRY İZLEME ---
    registry_monitor_aktif: bool = True

    # --- DLL İZLEME ---
    dll_monitor_aktif: bool = True
    dll_tarama_araligi: int = 10  # saniye

    # --- PROCESS İZLEME GENİŞLETİLMİŞ ---
    ignore_process_names: List[str] = field(default_factory=lambda: [
        "System Idle Process", "System", "Registry", "Memory Compression",
        "WmiPrvSE.exe", "svchost.exe", "MsMpEng.exe", "SearchApp.exe", "smss.exe",
        "csrss.exe", "wininit.exe", "winlogon.exe", "lsass.exe", "services.exe",
        "fontdrvhost.exe", "dwm.exe",
    ])

    # LOLBins - Living Off The Land Binaries (Meşru araçlar kötü amaçla kullanılabilir)
    lolbins_patterns: List[str] = field(default_factory=lambda: [
        "certutil", "bitsadmin", "wmic", "mshta", "regsvr32",
        "rundll32", "cscript", "wscript", "msbuild", "installutil",
        "regasm", "regsvcs", "msxsl", "ieexec",
    ])

    # --- DÖNGÜ ZAMANLAMA ---
    ana_dongu_bekleme: float = 0.5  # saniye

    # --- GENEL ---
    max_riskli_islem: int = 15
    debug_mode: bool = False

    def __repr__(self):
        return (
            f"Config(\n"
            f"  AI: estimators={self.ai_n_estimators}, contamination={self.ai_contamination}\n"
            f"  Thresholds: cpu={self.cpu_threshold}%, ram={self.ram_threshold}%, risk={self.risk_threshold}\n"
            f"  YARA: {self.yara_kural_dosyasi}\n"
            f"  Logging: dir={self.log_dir}, max={self.log_max_bytes // 1024 // 1024}MB\n"
            f")"
        )
