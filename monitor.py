# monitor.py - Gelişmiş Gözlemci (Disk ve Ağ Destekli)
import psutil
import numpy as np

class SistemGozlemcisi:
    def __init__(self):
        self.last_net = psutil.net_io_counters()
        
    def veri_topla(self):
        """AI için 5 boyutlu durum vektörü oluşturur"""
        # 1. CPU
        cpu = psutil.cpu_percent(interval=0.1)
        
        # 2. RAM
        ram = psutil.virtual_memory().percent
        
        # 3. Disk Aktivitesi (Genel)
        disk_io = psutil.disk_io_counters()
        # Okuma + Yazma işlem sayısı (Basit bir aktivite göstergesi)
        # Normalizasyon için logaritma kullanıyoruz (0-100 arasına sıkıştırmak için)
        disk_usage = (disk_io.read_count + disk_io.write_count) % 100 
        
        # 4. Ağ Aktivitesi (Genel)
        net_io = psutil.net_io_counters()
        # Paket trafiği değişimi
        sent = net_io.bytes_sent - self.last_net.bytes_sent
        recv = net_io.bytes_recv - self.last_net.bytes_recv
        self.last_net = net_io
        net_usage = (sent + recv) / 1024 / 1024 # MB cinsinden kabaca
        if net_usage > 100: net_usage = 100 # Tavan sınır
        
        # 5. En Yüksek PID (Process ID değişimi anomalisi için)
        pids = psutil.pids()
        pid_count = len(pids)

        return np.array([cpu, ram, disk_usage, net_usage, pid_count]).reshape(1, -1)

    def supheli_islemleri_getir(self):
        """
        Sistemi yoran işlemleri detaylı analiz eder.
        Artık Disk ve Ağ verisi de döndürüyor.
        """
        islemler = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'io_counters']):
            try:
                p_info = proc.info
                
                # Disk Yazma Verisini Al (Ransomware Tespiti İçin)
                io = p_info.get('io_counters', None)
                write_bytes = io.write_bytes if io else 0
                read_bytes = io.read_bytes if io else 0
                
                # Listeye ekle
                islemler.append({
                    'pid': p_info['pid'],
                    'name': p_info['name'],
                    'cpu_percent': p_info['cpu_percent'],
                    'memory_percent': p_info['memory_percent'],
                    'disk_write': write_bytes, # Toplam yazılan bayt
                    'disk_read': read_bytes
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # İşlemleri CPU kullanımına göre sırala ve ilk 3'ü döndür
        # Not: Gerçek bir ransomware dedektöründe 'disk_write' artış hızına göre sıralamak gerekir
        # ama basitlik adına CPU sıralamasını koruyoruz, çünkü şifreleme CPU da harcar.
        islemler.sort(key=lambda x: x['cpu_percent'], reverse=True)
        return islemler[:3]