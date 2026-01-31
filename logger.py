# logger.py - LOGLAMA SISTEMI
import logging
from datetime import datetime

class GuvenlikLogger:
    def __init__(self):
        self.logger = logging.getLogger("SecOpsLogger")
        self.logger.setLevel(logging.INFO)
        if self.logger.hasHandlers(): self.logger.handlers.clear()

        # UTF-8 Encoding ile dosyaya yazma
        file_handler = logging.FileHandler('guvenlik_loglari.txt', encoding='utf-8')
        formatter = logging.Formatter('%(message)s')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def log_threat(self, features, score, process_list, network_map=None):
        """Tehditleri ve ağ bilgilerini loglar."""
        try:
            if hasattr(features, 'shape') and len(features.shape) == 2:
                veri = features[0]
            elif isinstance(features, list) and len(features) == 1:
                 veri = features[0]
            else: veri = features
        except: veri = [0,0,0,0,0]

        cpu = veri[0] if len(veri)>0 else 0
        ram = veri[1] if len(veri)>1 else 0
        disk = veri[2] if len(veri)>2 else 0
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        msg = (
            f"==================================================\n"
            f"[!!!] GÜVENLİK UYARISI - TEHDİT DETAYI\n"
            f"==================================================\n"
            f"Tarih/Saat  : {timestamp}\n"
            f"Risk Skoru  : {score:.4f} (Negatif = Riskli)\n"
            f"Sistem      : CPU %{cpu:.1f} | RAM %{ram:.1f} | Disk {disk:.1f}\n"
            f"--------------------------------------------------\n"
            f"ŞÜPHELİ İŞLEM VE AĞ ANALİZİ:\n"
        )

        if process_list:
            for i, p in enumerate(process_list):
                pid = p['pid']
                mb_write = p.get('disk_write', 0) / 1024 / 1024
                
                # Ağ bilgilerini formatla
                net_info = "Veri Yok / Bağlantı Yok"
                if network_map and pid in network_map:
                    net_info = ", ".join(network_map[pid])

                msg += (f" {i+1}. {p['name']} (PID: {pid})\n"
                        f"    -> Kaynak: CPU %{p['cpu_percent']} | RAM %{p['memory_percent']:.1f}\n"
                        f"    -> Disk Yazma: {mb_write:.2f} MB\n"
                        f"    -> [AĞ BAĞLANTILARI]: {net_info}\n")
        
        msg += "==================================================\n"
        self.logger.info(msg)

    def log_normal(self, message):
        self.logger.info(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}")