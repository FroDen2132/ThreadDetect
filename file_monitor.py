# file_monitor.py - DOSYA SİSTEMİ İZLEYİCİ
# Ransomware tespiti, kritik dizin izleme, toplu dosya değişikliği algılama
import os
import time
import threading
from collections import defaultdict
from datetime import datetime


class FileMonitor:
    """
    Dosya sistemi değişikliklerini izleyen modül.
    - Kritik dizinlerdeki dosya oluşturma/silme/değiştirme olaylarını tespit eder
    - Ransomware kalıplarını algılar (toplu uzantı değişikliği, hızlı şifreleme)
    - Sensitive dizinleri izler (System32, Temp, AppData)
    
    Not: watchdog paketi mevcutsa onu kullanır, yoksa polling ile çalışır.
    """

    # Ransomware'lerin sıklıkla kullandığı uzantılar
    RANSOMWARE_UZANTILARI = {
        '.encrypted', '.locked', '.crypto', '.crypt', '.enc',
        '.pays', '.ransom', '.locky', '.cerber', '.zepto',
        '.odin', '.thor', '.aesir', '.zzzzz', '.micro',
        '.xxx', '.ttt', '.abc', '.xyz', '.aaa',
        '.ecc', '.ezz', '.exx', '.xtbl', '.crysis',
        '.onion', '.wallet', '.dharma', '.arena', '.java',
        '.bip', '.combo', '.gamma', '.heets', '.phobos',
        '.makop', '.STOP', '.djvu',
    }

    # Şüpheli dosya uzantıları (malware dropper)
    SUPHELI_UZANTILAR = {
        '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js',
        '.wsf', '.scr', '.pif', '.hta', '.dll',
    }

    def __init__(self, config=None):
        from config import Config
        self.config = config or Config()
        self.calisiyor = False
        self.thread = None
        self.alarmlar = []
        self.lock = threading.Lock()

        # İzlenen dizinler ve dosya durumları
        self.dizin_snapshot = {}   # dizin -> {dosya_adı: mtime}
        self.degisim_sayaci = defaultdict(int)   # zaman_penceresi -> değişiklik sayısı
        self.son_temizlik = time.time()

        # Watchdog kullanılabilir mi?
        self.watchdog_aktif = False
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
            self.watchdog_aktif = True
        except ImportError:
            pass

    def _snapshot_al(self, dizin):
        """Bir dizinin dosya durumunu kaydeder."""
        snapshot = {}
        try:
            if not os.path.exists(dizin):
                return snapshot
            for entry in os.scandir(dizin):
                try:
                    if entry.is_file():
                        snapshot[entry.path] = {
                            'mtime': entry.stat().st_mtime,
                            'size': entry.stat().st_size,
                            'ext': os.path.splitext(entry.name)[1].lower()
                        }
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            pass
        return snapshot

    def _ransomware_kontrol(self, yeni_dosyalar):
        """Toplu uzantı değişikliğini ransomware olarak tespit eder."""
        simdi = time.time()
        pencere_key = int(simdi / self.config.ransomware_pencere)

        ransomware_uzanti_sayisi = 0
        for dosya_info in yeni_dosyalar:
            ext = dosya_info.get('ext', '')
            if ext in self.RANSOMWARE_UZANTILARI:
                ransomware_uzanti_sayisi += 1

        self.degisim_sayaci[pencere_key] += len(yeni_dosyalar)

        # Ransomware tespiti
        if ransomware_uzanti_sayisi >= 3:
            return True, f"RANSOMWARE ŞÜPHESİ: {ransomware_uzanti_sayisi} dosya ransomware uzantısıyla oluşturuldu!"

        if self.degisim_sayaci[pencere_key] >= self.config.ransomware_esik:
            return True, f"RANSOMWARE ŞÜPHESİ: {self.config.ransomware_pencere}sn içinde {self.degisim_sayaci[pencere_key]} dosya değişikliği!"

        # Eski pencere kayıtlarını temizle
        if simdi - self.son_temizlik > 60:
            eski_anahtarlar = [k for k in self.degisim_sayaci if k < pencere_key - 10]
            for k in eski_anahtarlar:
                del self.degisim_sayaci[k]
            self.son_temizlik = simdi

        return False, ""

    def _dizin_karsilastir(self, dizin):
        """Dizinin mevcut ve önceki durumunu karşılaştırır."""
        # Whitelist kontrolü (dizin için)
        dizin_lower = dizin.lower()
        if any(dizin_lower.startswith(w.lower()) for w in self.config.whitelist_paths):
            return

        guncel = self._snapshot_al(dizin)
        onceki = self.dizin_snapshot.get(dizin, {})

        yeni_dosyalar = []
        silinen_dosyalar = []
        degisen_dosyalar = []

        # Yeni ve değişen dosyalar
        for dosya, info in guncel.items():
            if dosya not in onceki:
                yeni_dosyalar.append({'path': dosya, **info})
            elif onceki[dosya]['mtime'] != info['mtime']:
                degisen_dosyalar.append({'path': dosya, **info})

        # Silinen dosyalar
        for dosya in onceki:
            if dosya not in guncel:
                silinen_dosyalar.append({'path': dosya, **onceki[dosya]})

        self.dizin_snapshot[dizin] = guncel

        # Alarm üretimi
        with self.lock:
            # Şüpheli yeni dosyalar
            for d in yeni_dosyalar:
                ext = d.get('ext', '')
                # Whitelisted uzantı kontrolü
                if ext in self.config.whitelist_extensions:
                    continue
                
                if ext in self.SUPHELI_UZANTILAR:
                    self.alarmlar.append(
                        f"ŞÜPHELİ DOSYA OLUŞTURULDU: {d['path']} (Çalıştırılabilir dosya!)"
                    )

            # Toplu silme tespiti
            if len(silinen_dosyalar) > 5:
                self.alarmlar.append(
                    f"TOPLU SİLME TESPİTİ: {dizin} dizininde {len(silinen_dosyalar)} dosya silindi!"
                )

            # Ransomware kontrolü
            if yeni_dosyalar:
                ransomware, mesaj = self._ransomware_kontrol(yeni_dosyalar)
                if ransomware:
                    self.alarmlar.append(mesaj)

    def _watchdog_baslat(self):
        """Watchdog ile gerçek zamanlı izleme."""
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler

        monitor = self  # closure için referans

        class DosyaOlayHandler(FileSystemEventHandler):
            def on_created(self, event):
                if not event.is_directory:
                    ext = os.path.splitext(event.src_path)[1].lower()
                    
                    # Whitelist uzantı veya path kontrolü
                    if ext in monitor.config.whitelist_extensions:
                        return
                    if any(event.src_path.lower().startswith(w.lower()) for w in monitor.config.whitelist_paths):
                        return

                    if ext in FileMonitor.SUPHELI_UZANTILAR:
                        with monitor.lock:
                            monitor.alarmlar.append(
                                f"ŞÜPHELİ DOSYA OLUŞTURULDU: {event.src_path}"
                            )
                    if ext in FileMonitor.RANSOMWARE_UZANTILARI:
                        with monitor.lock:
                            monitor.alarmlar.append(
                                f"RANSOMWARE UZANTISI TESPİTİ: {event.src_path}"
                            )

            def on_deleted(self, event):
                if not event.is_directory:
                    # Whitelist kontrolü
                    if any(event.src_path.lower().startswith(w.lower()) for w in monitor.config.whitelist_paths):
                        return
                    with monitor.lock:
                        monitor.degisim_sayaci[int(time.time() / monitor.config.ransomware_pencere)] += 1

            def on_modified(self, event):
                if not event.is_directory:
                    # Whitelist kontrolü
                    if any(event.src_path.lower().startswith(w.lower()) for w in monitor.config.whitelist_paths):
                        return
                    with monitor.lock:
                        monitor.degisim_sayaci[int(time.time() / monitor.config.ransomware_pencere)] += 1

        observer = Observer()
        handler = DosyaOlayHandler()

        for dizin in self.config.izlenen_dizinler:
            if os.path.exists(dizin):
                try:
                    observer.schedule(handler, dizin, recursive=False)
                except Exception:
                    pass

        observer.start()
        try:
            while self.calisiyor:
                time.sleep(1)
        finally:
            observer.stop()
            observer.join()

    def _polling_baslat(self):
        """Watchdog yoksa polling ile izle."""
        # İlk snapshot
        for dizin in self.config.izlenen_dizinler:
            if os.path.exists(dizin):
                self.dizin_snapshot[dizin] = self._snapshot_al(dizin)

        while self.calisiyor:
            for dizin in self.config.izlenen_dizinler:
                if os.path.exists(dizin):
                    self._dizin_karsilastir(dizin)
            time.sleep(3)

    def baslat(self):
        """Dosya izlemeyi arka planda başlat."""
        self.calisiyor = True
        if self.watchdog_aktif:
            self.thread = threading.Thread(target=self._watchdog_baslat, daemon=True)
            print("[+] File Monitor Aktif (watchdog modu)")
        else:
            self.thread = threading.Thread(target=self._polling_baslat, daemon=True)
            print("[+] File Monitor Aktif (polling modu)")
        self.thread.start()

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
