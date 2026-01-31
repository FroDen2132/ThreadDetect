# logger.py (GÜNCELLENMİŞ VERSİYON)
import logging
import sys
from datetime import datetime

class GuvenlikLogger:
    def __init__(self, log_file="guvenlik_loglari.txt"):
        # Dosyaya yazarken UTF-8 kullanmasını söylüyoruz
        self.logger = logging.getLogger("GuvenlikLog")
        self.logger.setLevel(logging.INFO)
        
        # Eğer daha önce handler eklendiyse temizle (tekrarı önler)
        if self.logger.hasHandlers():
            self.logger.handlers.clear()

        # Dosya Ayarları (UTF-8 Encoding Eklendi)
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(file_handler)

        # Konsol Ayarları (Windows için encoding düzeltmesi gerekebilir)
        # Genellikle Python 3.7+ otomatik halleder ama emin olalım.
        self.console_enabled = True

    def log_normal(self, message):
        # Ekrana basarken flush=True ile anlık yazmasını sağlıyoruz
        print(f"\r[OK] {message}", end="", flush=True)

    def log_threat(self, features, score, top_processes):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        culprit = top_processes[0] if top_processes else {'name': 'Bilinmiyor', 'pid': 0, 'cpu_percent': 0}

        # Rapor metni
        rapor = (
            f"\n\n{'='*50}\n"
            f"[!!!] GÜVENLİK UYARISI - ANOMALİ TESPİT EDİLDİ\n"
            f"{'='*50}\n"
            f"Tarih/Saat  : {timestamp}\n"
            f"Risk Skoru  : {score:.4f}\n"
            f"--------------------------------------------------\n"
            f"SİSTEM DURUMU:\n"
            f" - CPU Yükü   : %{features[0]}\n"
            f" - RAM Yükü   : %{features[1]}\n"
            f" - Aktif İşlem: {features[4]} adet\n"
            f"--------------------------------------------------\n"
            f"ŞÜPHELİ AKTİVİTE KAYNAĞI:\n"
            f" 1. {culprit['name']} (PID: {culprit['pid']}) -> %{culprit['cpu_percent']} CPU\n"
            f"--------------------------------------------------\n"
            f"ÖNERİLEN AKSİYON: '{culprit['name']}' işlemini sonlandırın.\n"
            f"{'='*50}\n"
        )
        
        # Ekrana bas
        try:
            print(rapor)
        except UnicodeEncodeError:
            # Eğer terminal Türkçe desteklemiyorsa karakterleri düzeltip bas
            print(rapor.encode('ascii', 'replace').decode('ascii'))
            
        # Dosyaya kaydet
        self.logger.warning(rapor)