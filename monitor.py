# monitor.py - GELİŞMİŞ SİSTEM GÖZLEMCİSİ
# Parent-Child Analizi + LOLBins + Process Lifetime + Genişletilmiş Risk Skoru
import psutil
import numpy as np
import os
import time
import yara
from collections import Counter


class SistemGozlemcisi:
    def __init__(self, config=None):
        from config import Config
        self.config = config or Config()

        self.proc_cache = {}
        self.last_net = psutil.net_io_counters()
        self.last_disk = psutil.disk_io_counters()

        # --- YARA ÖNBELLEĞİ ---
        self.taranan_pidler = set()

        # --- PROCESS LIFETIME İZLEME ---
        self.process_first_seen = {}   # pid -> timestamp
        self.process_thread_count = {} # pid -> son thread sayısı

        # --- YARA KURALLARINI YÜKLE ---
        self.kural_dosyasi = self.config.yara_kural_dosyasi
        self.yara_rules = None

        if os.path.exists(self.kural_dosyasi):
            print(f"[*] YARA Kuralları Yükleniyor: {self.kural_dosyasi} ...")
            try:
                self.yara_rules = yara.compile(filepath=self.kural_dosyasi)
                print("[+] YARA Kuralları Başarıyla Aktif Edildi!")
            except Exception as e:
                print(f"[-] YARA Yükleme Hatası: {e}")
        else:
            print(f"[-] '{self.kural_dosyasi}' bulunamadı! YARA pasif modda.")

        # --- HONEYPOT ---
        self.yem_dosyasi = self.config.honeypot_dosyasi
        self.yem_olustur()
        try:
            self.son_durum = os.path.getmtime(self.yem_dosyasi)
        except Exception:
            self.son_durum = 0

    # =====================================================
    # HONEYPOT
    # =====================================================
    def yem_olustur(self):
        if not os.path.exists(self.yem_dosyasi):
            try:
                with open(self.yem_dosyasi, "w") as f:
                    f.write(
                        "# CONFIDENTIAL CREDENTIALS FILE\n"
                        "# DO NOT DISTRIBUTE\n"
                        "ZARARLI_KOD_BURADA\n"
                        "Admin_User: administrator\n"
                        "Admin_Pass: P@ssw0rd!2026\n"
                        "DB_Host: 192.168.1.100\n"
                        "DB_Pass: root_secret_key\n"
                        "API_KEY: sk-live-abc123xyz789\n"
                    )
            except Exception:
                pass

    def tuzak_kontrol(self):
        if not os.path.exists(self.yem_dosyasi):
            self.yem_olustur()
            return True, "HONEYPOT DOSYASI SİLİNDİ! Bir süreç dosyayı silmiş olabilir."
        try:
            if os.path.getmtime(self.yem_dosyasi) != self.son_durum:
                self.son_durum = os.path.getmtime(self.yem_dosyasi)
                return True, "HONEYPOT DOSYASI DEĞİŞTİRİLDİ! Bir süreç dosyayı düzenledi."
        except Exception:
            pass
        return False, None

    # =====================================================
    # AĞ BİLGİSİ
    # =====================================================
    def pid_ag_bilgisi(self, pid):
        baglantilar = []
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.pid == pid:
                    if conn.raddr:
                        baglantilar.append(f"-> {conn.raddr.ip}:{conn.raddr.port}")
                    elif conn.status == 'LISTEN':
                        baglantilar.append(f"-> Port {conn.laddr.port} DİNLİYOR")
        except Exception:
            return ["Erişim Engellendi"]
        return baglantilar if baglantilar else ["Ağ Bağlantısı Yok"]

    # =====================================================
    # VERİ TOPLAMA (AI Feature Vector)
    # =====================================================
    def veri_topla(self):
        try:
            cpu = psutil.cpu_percent(interval=None)
            ram = psutil.virtual_memory().percent
            net_io = psutil.net_io_counters()
            net_usage = (net_io.bytes_sent + net_io.bytes_recv) - \
                        (self.last_net.bytes_sent + self.last_net.bytes_recv)
            self.last_net = net_io
            disk_io = psutil.disk_io_counters()
            disk_usage = (disk_io.write_bytes + disk_io.read_bytes) - \
                         (self.last_disk.write_bytes + self.last_disk.read_bytes)
            self.last_disk = disk_io
            return np.array([
                cpu, ram,
                disk_usage / 1024 / 1024,
                net_usage / 1024 / 1024,
                len(psutil.pids())
            ]).reshape(1, -1)
        except Exception:
            return np.array([0, 0, 0, 0, 0]).reshape(1, -1)

    # =====================================================
    # PARENT-CHILD PROCESS ANALİZİ
    # =====================================================
    def parent_bilgisi_getir(self, pid):
        """Bir sürecin üst süreç bilgisini getirir."""
        try:
            proc = psutil.Process(pid)
            parent = proc.parent()
            if parent:
                return {
                    'pid': parent.pid,
                    'name': parent.name(),
                    'exe': parent.exe() if parent.exe() else '',
                }
        except Exception:
            pass
        return None

    def sureç_agaci_risk(self, pid, name):
        """
        Parent-child ilişkisindeki anormallikleri analiz eder.
        Ör: word.exe -> cmd.exe -> powershell.exe  gibi zincirler şüphelidir.
        """
        risk = 0
        aciklamalar = []
        try:
            parent = self.parent_bilgisi_getir(pid)
            if parent:
                parent_name = parent['name'].lower()
                child_name = name.lower()

                # Office uygulamalarından shell açılması
                ofis_apps = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'msaccess.exe']
                shell_procs = ['cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe']

                if parent_name in ofis_apps and child_name in shell_procs:
                    risk += 500
                    aciklamalar.append(f"Office->Shell: {parent_name} -> {child_name}")

                # Explorer'dan beklenmeyen çocuk süreçler
                if parent_name == 'explorer.exe' and child_name in ['reg.exe', 'regedit.exe', 'net.exe']:
                    risk += 200
                    aciklamalar.append(f"Explorer->SysUtil: {child_name}")

                # Kendini farklı isimle çoğaltma (masquerade)
                if parent_name == child_name and parent['pid'] != pid:
                    risk += 100
                    aciklamalar.append(f"Self-spawn: {child_name}")

        except Exception:
            pass
        return risk, aciklamalar, parent if 'parent' in dir() else None

    # =====================================================
    # PROCESS LIFETIME TAKİBİ
    # =====================================================
    def process_lifetime_kontrol(self, pid):
        """
        Yeni başlayan süreçleri tespit eder.
        Çok kısa ömürlü süreçler şüpheli olabilir.
        """
        simdi = time.time()
        if pid not in self.process_first_seen:
            self.process_first_seen[pid] = simdi
            return True, 0  # Yeni süreç
        yas = simdi - self.process_first_seen[pid]
        return False, yas

    # =====================================================
    # THREAD INJECTION TESPİTİ
    # =====================================================
    def thread_degisim_kontrol(self, pid):
        """Thread sayısındaki ani değişimleri izler."""
        try:
            proc = psutil.Process(pid)
            thread_sayisi = proc.num_threads()
            eski = self.process_thread_count.get(pid, thread_sayisi)
            self.process_thread_count[pid] = thread_sayisi

            degisim = thread_sayisi - eski
            if degisim > 10:  # Ani 10+ thread artışı
                return True, degisim, thread_sayisi
        except Exception:
            pass
        return False, 0, 0

    # =====================================================
    # ŞÜPHELİ İŞLEM TESPİTİ (ANA FONKSİYON)
    # =====================================================
    def supheli_islemleri_getir(self, ai_motor=None, is_training=False):
        pid_baglanti_sayilari = Counter()
        try:
            for c in psutil.net_connections(kind='inet'):
                pid_baglanti_sayilari[c.pid] += 1
        except Exception:
            pass

        guncel_islemler = []
        process_egitim_verileri = []

        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent',
                                          'io_counters', 'exe', 'cmdline', 'num_threads']):
            try:
                p = proc.info
                pid = p['pid']
                name = p['name']
                exe_path = p['exe']
                cmd_line = " ".join(p['cmdline']) if p['cmdline'] else ""

                # --- GÜVENLİ LİSTEYİ ATLA (AMMA ENJEKSİYONU TAKİP ET) ---
                # İgnore listesinde olsa bile thread injection yiyip yemediğine bakalım.
                # Whitelisted bir process injection yediği an whitelist'ten çıkmalıdır!
                is_ignored = name in self.config.ignore_process_names
                thread_alarm, thread_degisim, thread_toplam = self.thread_degisim_kontrol(pid)
                
                if is_ignored and not thread_alarm:
                    # Gerçekten temiz ve ignore listesindeyse tamamen atla
                    if pid == 0 or pid == 4:
                        continue
                    # Cache'i güncellemek için devam ediyoruz ama analiz etmiyoruz
                    continue
                    
                if pid == 0 or pid == 4:
                    continue

                # --- WHITELIST KONTROLÜ ---
                is_whitelisted = False
                if exe_path:
                    exe_lower = exe_path.lower()
                    for w_path in self.config.whitelist_paths:
                        if exe_lower.startswith(w_path.lower()):
                            is_whitelisted = True
                            break
                            
                # Eğer ignore listesindeki bir program injection yemişse whitelist indirimini yak!
                if is_ignored and thread_alarm:
                    is_whitelisted = False

                # --- YARA TARAMASI ---
                yara_sonuc = []
                should_scan = ((pid not in self.taranan_pidler) or (p['cpu_percent'] > 80)) and not is_whitelisted

                if self.yara_rules and exe_path and should_scan:
                    try:
                        matches = self.yara_rules.match(exe_path, timeout=self.config.yara_timeout)
                        if matches:
                            yara_sonuc = [m.rule for m in matches]
                        if not yara_sonuc:
                            self.taranan_pidler.add(pid)
                    except (PermissionError, OSError):
                        pass
                    except yara.TimeoutError:
                        pass
                    except Exception:
                        pass

                # --- Disk Hızı ---
                io = p.get('io_counters', None)
                current_bytes = (io.write_bytes + io.read_bytes) if io else 0
                if pid in self.proc_cache:
                    delta_io = current_bytes - self.proc_cache[pid]
                else:
                    delta_io = 0
                self.proc_cache[pid] = current_bytes
                disk_mb_sn = (delta_io if delta_io > 0 else 0) / 1024 / 1024

                baglanti_sayisi = pid_baglanti_sayilari.get(pid, 0)

                # --- GENİŞLETİLMİŞ RİSK SKORU ---
                risk_puan: float = 0.0
                risk_detay: list[str] = []

                # Kaynak kullanımı
                risk_puan += p['cpu_percent'] * 1.0
                risk_puan += p['memory_percent'] * 0.5
                risk_puan += disk_mb_sn * 10
                risk_puan += baglanti_sayisi * 5

                # YARA
                if yara_sonuc:
                    risk_puan += 2000
                    risk_detay.append("YARA_MATCH")

                # LOLBins Analizi
                cmd_lower = cmd_line.lower()
                for lolbin in self.config.lolbins_patterns:
                    if lolbin in cmd_lower:
                        risk_puan += 400
                        risk_detay.append(f"LOLBIN:{lolbin}")
                        break

                # Şüpheli Komut Satırı Kalıpları
                if "powershell" in cmd_lower and ("-enc" in cmd_lower or "-encoded" in cmd_lower):
                    risk_puan += 500
                    risk_detay.append("ENCODED_PS")
                if "cmd.exe /c" in cmd_lower:
                    risk_puan += 300
                    risk_detay.append("CMD_EXEC")
                if "nc -l" in cmd_lower or "nc.exe -l" in cmd_lower:
                    risk_puan += 500
                    risk_detay.append("NETCAT_LISTENER")
                if "taskkill" in cmd_lower and ("defender" in cmd_lower or "msmpeng" in cmd_lower):
                    risk_puan += 800
                    risk_detay.append("AV_KILL_ATTEMPT")
                if "-nop" in cmd_lower and "-w hidden" in cmd_lower:
                    risk_puan += 600
                    risk_detay.append("HIDDEN_PS")
                if "invoke-expression" in cmd_lower or "iex " in cmd_lower:
                    risk_puan += 500
                    risk_detay.append("IEX_EXEC")
                if "downloadstring" in cmd_lower or "downloadfile" in cmd_lower:
                    risk_puan += 500
                    risk_detay.append("DOWNLOAD_EXEC")

                # Parent-Child Risk
                pc_risk, pc_aciklama, parent_info = self.sureç_agaci_risk(pid, name)
                risk_puan += pc_risk
                risk_detay.extend(pc_aciklama)

                # Process Lifetime
                yeni_mi, yas = self.process_lifetime_kontrol(pid)
                if yeni_mi and (p['cpu_percent'] > 10 or baglanti_sayisi > 3):
                    risk_puan += 100
                    risk_detay.append("NEW_PROCESS_ACTIVE")

                # Thread injection
                if thread_alarm:
                    risk_puan += 300
                    risk_detay.append(f"THREAD_SPIKE:+{thread_degisim}")
                    if is_ignored:
                        risk_puan += 500  # Güvenilir bir sürecin içine girilmeye çalışılması ekstra ceza
                        risk_detay.append(f"WHITELIST_INJECTION_ATTEMPT")

                # Whitelist indirimi
                if is_whitelisted:
                    risk_puan = risk_puan * 0.1  # %90 risk indirimi
                    risk_detay.append("WHITELISTED_PATH")

                # =================================================
                # SÜREÇ BAZLI YAPAY ZEKA (PROCESS-LEVEL AI)
                # =================================================
                # Thread bilgisini p nesnesinden veya kontrolden alalım
                thr_count = p.get('num_threads', thread_toplam if thread_toplam > 0 else 1)
                
                process_vektoru = np.array([[
                    float(p['cpu_percent']), 
                    float(p['memory_percent']), 
                    float(disk_mb_sn), 
                    float(baglanti_sayisi),
                    float(thr_count)
                ]])
                
                if is_training:
                    # Eğitim sırasında veriyi topla (Sadece efor sarfeden veya belirli yükü olan süreçler temiz modelimizi bozmasın diye hafif bir filtreleme de yapabiliriz ama isolation forest her şeyi alır)
                    process_egitim_verileri.append(process_vektoru)
                elif ai_motor and ai_motor.process_is_trained:
                    # Analiz sırasında modele sor
                    _, ai_proc_skor = ai_motor.process_analiz_et(process_vektoru)
                    
                    # Eğer AI anomali saptadıysa (skor negatifse) risk skoruna ciddi bir ceza kes
                    if ai_proc_skor < -0.1:
                        risk_puan += 80
                        risk_detay.append(f"AI_PROCESS_ANOMALY({ai_proc_skor:.2f})")
                    elif ai_proc_skor < -0.05:
                        risk_puan += 40
                        risk_detay.append(f"AI_PROCESS_SUSPICIOUS({ai_proc_skor:.2f})")

                guncel_islemler.append({
                    'pid': pid,
                    'name': name,
                    'cpu_percent': p['cpu_percent'],
                    'memory_percent': p['memory_percent'],
                    'disk_speed': disk_mb_sn,
                    'conn_count': baglanti_sayisi,
                    'risk_score': risk_puan,
                    'yara_matches': yara_sonuc,
                    'cmd_line': cmd_line,
                    'risk_detail': risk_detay,
                    'parent_info': parent_info,
                    'is_new': yeni_mi,
                    'process_age': yas,
                    'thread_count': thread_toplam,
                })
            except Exception:
                continue

        # Cache temizliği
        mevcut_pidler = set(p['pid'] for p in guncel_islemler)
        self.proc_cache = {k: v for k, v in self.proc_cache.items() if k in mevcut_pidler}
        # Lifetime cache temizliği
        self.process_first_seen = {k: v for k, v in self.process_first_seen.items() if k in mevcut_pidler}
        self.process_thread_count = {k: v for k, v in self.process_thread_count.items() if k in mevcut_pidler}

        if len(self.taranan_pidler) > self.config.yara_cache_limit:
            self.taranan_pidler.clear()

        guncel_islemler.sort(key=lambda x: float(x['risk_score']), reverse=True)
        
        if is_training:
            return process_egitim_verileri
        else:
            return guncel_islemler[:self.config.max_riskli_islem]