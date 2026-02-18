# registry_monitor.py - WINDOWS REGISTRY İZLEYİCİ
# Autorun anahtarları, persistence mekanizmaları ve registry değişiklik tespiti
import os
import sys
import time
import threading
from typing import Any, Dict, List, Optional, Tuple


# Windows-only modül — platform kontrolü
WINREG_AVAILABLE = False
_winreg: Any = None

if sys.platform == "win32":
    try:
        import winreg as _winreg  # type: ignore[no-redef]
        WINREG_AVAILABLE = True
    except ImportError:
        pass


class RegistryMonitor:
    """
    Windows Registry'deki kritik anahtarları periyodik olarak izler.
    Autorun, Scheduled Tasks, Shell Extension gibi persistence
    mekanizmalarındaki değişiklikleri tespit eder.
    """

    def __init__(self, config: Any = None) -> None:
        self.config = config
        self.calisiyor: bool = False
        self.thread: Optional[threading.Thread] = None
        self.alarmlar: List[str] = []
        self.onceki_snapshot: Dict[str, Dict[str, str]] = {}
        self.lock = threading.Lock()

        # İzlenecek kritik registry anahtarları
        self._kritik_anahtarlar: List[Tuple[Any, str, str]] = []

        if WINREG_AVAILABLE and _winreg is not None:
            self._kritik_anahtarlar = [
                # CurrentUser Autorun
                (_winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
                (_winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
                # LocalMachine Autorun
                (_winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
                (_winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
                # Services
                (_winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services", "HKLM\\Services"),
                # Shell extensions
                (_winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", "HKCU\\ShellFolders"),
                # Image File Execution Options (Debugger persistence)
                (_winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "HKLM\\IFEO"),
            ]
            self._ilk_snapshot_al()
        else:
            print("[-] Registry Monitor: winreg modülü bulunamadı (sadece Windows'ta çalışır)")

    def _ilk_snapshot_al(self) -> None:
        """Başlangıçta mevcut registry durumunu kaydet."""
        for hive, yol, ad in self._kritik_anahtarlar:
            try:
                degerler = self._anahtar_oku(hive, yol)
                self.onceki_snapshot[ad] = degerler
            except Exception:
                self.onceki_snapshot[ad] = {}

    def _anahtar_oku(self, hive: Any, yol: str) -> Dict[str, str]:
        """Bir registry anahtarının tüm değerlerini okur."""
        if not WINREG_AVAILABLE or _winreg is None:
            return {}
        degerler: Dict[str, str] = {}
        try:
            key = _winreg.OpenKey(hive, yol, 0, _winreg.KEY_READ)  # type: ignore[union-attr]
            i = 0
            while True:
                try:
                    ad, veri, _tip = _winreg.EnumValue(key, i)  # type: ignore[union-attr]
                    degerler[ad] = str(veri)
                    i += 1
                except OSError:
                    break
            _winreg.CloseKey(key)  # type: ignore[union-attr]
        except (PermissionError, OSError):
            pass
        return degerler

    def _karsilastir_ve_alarm(self) -> None:
        """Mevcut durumu önceki snapshot ile karşılaştır."""
        for hive, yol, ad in self._kritik_anahtarlar:
            try:
                guncel = self._anahtar_oku(hive, yol)
                onceki = self.onceki_snapshot.get(ad, {})

                # Yeni eklenen değerler
                for key, val in guncel.items():
                    if key not in onceki:
                        alarm_msg = f"REGISTRY YENİ DEĞER: [{ad}] '{key}' = '{str(val)[:100]}'"
                        with self.lock:
                            self.alarmlar.append(alarm_msg)
                    elif onceki[key] != val:
                        alarm_msg = f"REGISTRY DEĞİŞİKLİK: [{ad}] '{key}' değiştirildi"
                        with self.lock:
                            self.alarmlar.append(alarm_msg)

                # Silinen değerler
                for key in onceki:
                    if key not in guncel:
                        alarm_msg = f"REGISTRY SİLİNDİ: [{ad}] '{key}' kaldırıldı"
                        with self.lock:
                            self.alarmlar.append(alarm_msg)

                self.onceki_snapshot[ad] = guncel
            except Exception:
                continue

    def _izleme_dongusu(self) -> None:
        """Arka planda çalışan izleme döngüsü."""
        while self.calisiyor:
            self._karsilastir_ve_alarm()
            time.sleep(5)  # 5 saniyede bir kontrol

    def baslat(self) -> None:
        """Registry izlemeyi arka planda başlat."""
        if not WINREG_AVAILABLE:
            return
        self.calisiyor = True
        self.thread = threading.Thread(target=self._izleme_dongusu, daemon=True)
        self.thread.start()  # type: ignore[union-attr]
        print("[+] Registry Monitor Aktif")

    def durdur(self) -> None:
        self.calisiyor = False

    def alarmlari_getir(self) -> List[str]:
        """Biriken alarmları döndür ve temizle."""
        with self.lock:
            if self.alarmlar:
                yedek = list(self.alarmlar)
                self.alarmlar.clear()
                return yedek
        return []
