import psutil
import numpy as np
import os
import time
from collections import Counter

class SistemGozlemcisi:
    def __init__(self):
        self.proc_cache = {} 
        self.last_net = psutil.net_io_counters()
        self.last_disk = psutil.disk_io_counters()
        
        # Tuzak dosya kurulumu
        self.yem_dosyasi = "gizli_sifreler_SAKIN_DOKUNMA.txt"
        self.yem_olustur()
        try: self.son_durum = os.path.getmtime(self.yem_dosyasi)
        except: self.son_durum = 0

    def yem_olustur(self):
        if not os.path.exists(self.yem_dosyasi):
            try:
                with open(self.yem_dosyasi, "w") as f:
                    f.write("Bu dosya tuzaktir.\nUser: Admin\nPass: 1234")
            except: pass

    def tuzak_kontrol(self):
        if not os.path.exists(self.yem_dosyasi):
            self.yem_olustur()
            return True, "DOSYA SİLİNDİ!"
        try:
            if os.path.getmtime(self.yem_dosyasi) != self.son_durum:
                self.son_durum = os.path.getmtime(self.yem_dosyasi)
                return True, "DOSYA DEĞİŞTİRİLDİ!"
        except: pass
        return False, None

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
        except: return ["Erişim Engellendi"]
        return baglantilar if baglantilar else ["Ağ Bağlantısı Yok"]

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

            net_mb = net_usage / 1024 / 1024
            disk_mb = disk_usage / 1024 / 1024
            
            # PIDS sayısını da feature olarak ekleyelim
            return np.array([cpu, ram, disk_mb, net_mb, len(psutil.pids())]).reshape(1, -1)
        except:
            return np.array([0,0,0,0,0]).reshape(1, -1)

    def supheli_islemleri_getir(self):
        pid_baglanti_sayilari = Counter()
        try:
            for c in psutil.net_connections(kind='inet'):
                pid_baglanti_sayilari[c.pid] += 1
        except: pass

        guncel_islemler = []
        
        # --- İŞTE BURASI HAYAT KURTARAN FİLTRE ---
        IGNORE_NAMES = ["System Idle Process", "System", "Registry", "Memory Compression"]
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'io_counters']):
            try:
                p = proc.info
                pid = p['pid']
                name = p['name']

                # PID 0 (Idle) veya PID 4 (System) ise bu işlemi LİSTEYE ALMA
                if pid == 0 or pid == 4 or name in IGNORE_NAMES:
                    continue
                
                # Disk okuma/yazma hızı hesapla
                io = p.get('io_counters', None)
                current_bytes = (io.write_bytes + io.read_bytes) if io else 0
                
                if pid in self.proc_cache:
                    delta_io = current_bytes - self.proc_cache[pid]
                else:
                    delta_io = 0
                
                self.proc_cache[pid] = current_bytes
                if delta_io < 0: delta_io = 0 
                disk_mb_sn = delta_io / 1024 / 1024
                
                baglanti_sayisi = pid_baglanti_sayilari.get(pid, 0)
                
                # Risk Skoru: CPU + RAM + Disk Hızı + Ağ Bağlantısı
                risk_puan = p['cpu_percent'] + (p['memory_percent']*0.5) + (disk_mb_sn * 10) + (baglanti_sayisi * 5)

                guncel_islemler.append({
                    'pid': pid,
                    'name': name,
                    'cpu_percent': p['cpu_percent'],
                    'memory_percent': p['memory_percent'],
                    'disk_speed': disk_mb_sn,
                    'conn_count': baglanti_sayisi,
                    'risk_score': risk_puan
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Cache temizliği (kapanan programları listeden sil)
        mevcut_pidler = set(p['pid'] for p in guncel_islemler)
        self.proc_cache = {k:v for k,v in self.proc_cache.items() if k in mevcut_pidler}

        # En yüksek riskli 15 işlemi döndür
        guncel_islemler.sort(key=lambda x: x['risk_score'], reverse=True)
        return guncel_islemler[:15]