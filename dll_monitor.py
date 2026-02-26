# dll_monitor.py - DLL İNJECTION TESPİT SİSTEMİ
# Süreçlerin yüklediği DLL'lerdeki değişiklikleri izler
import psutil
import os
import time
import threading


class DLLMonitor:
    """
    Çalışan süreçlerin yüklü DLL listelerini izler.
    - Yeni DLL yüklendiğinde alarm verir
    - Temp dizinlerinden yüklenen şüpheli DLL'leri tespit eder
    - Unsigned veya bilinmeyen DLL'leri işaretler
    """

    # Şüpheli DLL yükleme dizinleri
    SUPHELI_DIZINLER = [
        "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
        "\\downloads\\", "\\desktop\\", "\\public\\",
        "\\users\\public\\",
    ]

    # İzlenmeyecek güvenli süreçler
    GUVENLI_ISLEMLER = {
        "System", "Registry", "smss.exe", "csrss.exe",
        "wininit.exe", "services.exe", "lsass.exe",
        "svchost.exe", "dwm.exe", "fontdrvhost.exe",
    }

    def __init__(self, config=None):
        from config import Config
        self.config = config or Config()
        self.calisiyor: bool = False
        self.thread: threading.Thread | None = None
        self.alarmlar: list[str] = []
        self.lock = threading.Lock()

        # pid -> set(dll_paths) — Bilinen DLL snapshot'ları
        self.dll_snapshot: dict[int, set[str]] = {}
        self.tarama_araligi: int = config.dll_tarama_araligi if config else 10

    def _process_dll_listesi(self, pid):
        """Bir sürecin yüklü DLL dosyalarını listeler."""
        dll_listesi = set()
        try:
            proc = psutil.Process(pid)
            # Windows'ta memory_maps DLL bilgisi verir
            for mapping in proc.memory_maps(grouped=True):
                path = mapping.path.lower()
                if path.endswith('.dll'):
                    dll_listesi.add(path)
        except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError, OSError):
            pass
        return dll_listesi

    def _dll_supheli_mi(self, dll_path):
        """Bir DLL'in şüpheli dizinden yüklenip yüklenmediğini kontrol eder."""
        dll_lower = dll_path.lower()
        
        # Whitelist kontrolü
        for w_path in self.config.whitelist_paths:
            if dll_lower.startswith(w_path.lower()):
                return False, ""

        for dizin in self.SUPHELI_DIZINLER:
            if dizin in dll_lower:
                return True, f"Şüpheli dizin: {dizin.strip(chr(92))}"

        # System32 veya SysWOW64 dışında olan DLL'ler
        if "\\windows\\system32\\" not in dll_lower and \
           "\\windows\\syswow64\\" not in dll_lower and \
           "\\program files" not in dll_lower and \
           "\\windows\\winsxs\\" not in dll_lower:
            return True, "Standart dışı dizin"

        return False, ""

    def _tarama_yap(self):
        """Tüm süreçleri tara ve DLL değişikliklerini tespit et."""
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']

                if name in self.config.ignore_process_names or pid <= 4:
                    continue

                guncel_dlls = self._process_dll_listesi(pid)
                if not guncel_dlls:
                    continue

                if pid in self.dll_snapshot:
                    onceki_dlls = self.dll_snapshot[pid]
                    yeni_dlls = guncel_dlls - onceki_dlls

                    for dll in yeni_dlls:
                        supheli, neden = self._dll_supheli_mi(dll)
                        if supheli:
                            alarm = (
                                f"DLL INJECTION ŞÜPHESİ: {name} (PID:{pid}) "
                                f"yeni DLL yükledi: {os.path.basename(dll)} [{neden}]"
                            )
                            with self.lock:
                                self.alarmlar.append(alarm)
                        elif self.config and self.config.debug_mode:
                            alarm = f"DLL YENİ: {name} (PID:{pid}) <- {os.path.basename(dll)}"
                            with self.lock:
                                self.alarmlar.append(alarm)

                self.dll_snapshot[pid] = guncel_dlls

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

        # Kapanmış süreçleri temizle
        mevcut_pidler = set(p.pid for p in psutil.process_iter())
        self.dll_snapshot = {k: v for k, v in self.dll_snapshot.items() if k in mevcut_pidler}

    def _izleme_dongusu(self):
        """Arka planda çalışan tarama döngüsü."""
        # İlk taramada snapshot al (alarm verme)
        self._tarama_yap()
        while self.calisiyor:
            time.sleep(self.tarama_araligi)
            self._tarama_yap()

    def baslat(self):
        """DLL izlemeyi arka planda başlat."""
        self.calisiyor = True
        self.thread = threading.Thread(target=self._izleme_dongusu, daemon=True)
        self.thread.start()
        print("[+] DLL Monitor Aktif")

    def durdur(self):
        self.calisiyor = False

    def alarmlari_getir(self):
        """Biriken alarmları döndür ve temizle."""
        with self.lock:
            if self.alarmlar:
                yedek = self.alarmlar[:]
                self.alarmlar.clear()
                return yedek
        return []
