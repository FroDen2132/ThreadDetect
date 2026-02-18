# main.py - GELİŞMİŞ SİBER GÜVENLİK MERKEZİ
# AI + YARA + Sniffer + Monitor + Registry + DLL + File System
import time
import sys
import os
import signal
import argparse
import psutil

from config import Config
from monitor import SistemGozlemcisi
from ai_brain import YapayZekaMotoru
from logger import GuvenlikLogger
from sniffer import AgKoklayici
from registry_monitor import RegistryMonitor
from dll_monitor import DLLMonitor
from file_monitor import FileMonitor

# =====================================================
# RENK DESTEĞİ (colorama opsiyonel)
# =====================================================
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    RENK = True
except ImportError:
    RENK = False

    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = RESET = ""
        LIGHTRED_EX = LIGHTYELLOW_EX = LIGHTGREEN_EX = LIGHTCYAN_EX = ""

    class Style:
        BRIGHT = RESET_ALL = ""


# =====================================================
# YARDIMCI FONKSİYONLAR
# =====================================================
def banner():
    """Başlangıç banner'ı gösterir."""
    print(f"""{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ██████╗           ║
║   ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗██╔══██╗          ║
║      ██║   ███████║██████╔╝█████╗  ███████║██║  ██║          ║
║      ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║██║  ██║          ║
║      ██║   ██║  ██║██║  ██║███████╗██║  ██║██████╔╝          ║
║      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝           ║
║                                                              ║
║        ThreadDetector — AI Siber Tehdit Analiz Sistemi       ║
║             v2.0 — Full Spectrum Defense                     ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")


def set_high_priority():
    """İşlemi yüksek öncelik moduna alır."""
    try:
        p = psutil.Process(os.getpid())
        if os.name == 'nt':
            p.nice(psutil.HIGH_PRIORITY_CLASS)
        else:
            p.nice(-10)
    except Exception:
        pass


def renkli(metin, renk):
    """Renkli terminal çıktısı üretir."""
    return f"{renk}{metin}{Style.RESET_ALL}"


KENDI_PID = os.getpid()


# =====================================================
# ANA FONKSİYON
# =====================================================
def main():
    # CLI Argümanları
    parser = argparse.ArgumentParser(description="ThreadDetector — AI Siber Tehdit Analiz Sistemi")
    parser.add_argument('--auto', action='store_true', help='Menü göstermeden otomatik başlat')
    parser.add_argument('--retrain', action='store_true', help='Modeli sıfırla ve baştan eğit')
    parser.add_argument('--debug', action='store_true', help='Debug modu')
    args = parser.parse_args()

    banner()
    set_high_priority()

    # --- CONFIG ---
    config = Config()
    if args.debug:
        config.debug_mode = True

    # --- MODÜLLERİ BAŞLAT ---
    print(f"\n{Fore.CYAN}[*] Modüller Yükleniyor...{Style.RESET_ALL}")

    gozlemci = SistemGozlemcisi(config)
    beyin = YapayZekaMotoru(config)
    loglayici = GuvenlikLogger(config)
    koklayici = AgKoklayici(config)
    registry_mon = RegistryMonitor(config)
    dll_mon = DLLMonitor(config)
    dosya_mon = FileMonitor(config)

    print(f"\n{Fore.GREEN}{Style.BRIGHT}--- ThreadDetector v2.0 (PID: {KENDI_PID}) ---{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] MOD: FULL SPECTRUM{Style.RESET_ALL}")
    print(f"    Process + Network + AI + YARA + Registry + DLL + FileSystem\n")

    # Log sistemi başladığını kaydet
    loglayici.log_system("ThreadDetector v2.0 başlatıldı", "INFO", {
        "pid": KENDI_PID,
        "modules": ["monitor", "ai_brain", "sniffer", "registry", "dll", "file_monitor"]
    })

    # --- SNIFFER BAŞLAT ---
    if config.sniffer_aktif:
        print(f"{Fore.CYAN}[*] Ağ Koklayıcı (Sniffer) Başlatılıyor...{Style.RESET_ALL}")
        koklayici.thread_baslat()

    # --- REGISTRY MONITOR ---
    if config.registry_monitor_aktif:
        registry_mon.baslat()

    # --- DLL MONITOR ---
    if config.dll_monitor_aktif:
        dll_mon.baslat()

    # --- FILE MONITOR ---
    if config.file_monitor_aktif:
        dosya_mon.baslat()

    # --- EĞİTİM MENÜ ---
    if args.retrain:
        secim = '3'
    elif args.auto:
        secim = '1'
    else:
        print(f"\n{Fore.YELLOW}[?] Başlangıç Seçeneği{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}1.{Style.RESET_ALL} Hızlı Başlat (Kayıtlı modeli kullan)")
        print(f"  {Fore.WHITE}2.{Style.RESET_ALL} Eğitimi İyileştir (Mevcut modele yeni veri ekle)")
        print(f"  {Fore.WHITE}3.{Style.RESET_ALL} Sıfırla ve Baştan Eğit")
        secim = input(f"\n{Fore.CYAN}Seçiminiz (1/2/3): {Style.RESET_ALL}")

    if secim == '3':
        if os.path.exists(config.model_path):
            os.remove(config.model_path)
        if os.path.exists(config.data_path):
            os.remove(config.data_path)
        beyin = YapayZekaMotoru(config)
        secim = '2'

    if secim == '2' or not beyin.is_trained:
        egitim_suresi = config.ai_egitim_suresi
        print(f"\n{Fore.MAGENTA}[*] ORTAM ÖĞRENİLİYOR ({egitim_suresi} Sn)...{Style.RESET_ALL}")
        t_end = time.time() + egitim_suresi
        veri_havuzu = []

        # Cache ısıtma
        for _ in range(5):
            gozlemci.veri_topla()
            gozlemci.supheli_islemleri_getir()
            time.sleep(0.1)

        while time.time() < t_end:
            v = gozlemci.veri_topla()
            veri_havuzu.append(v)
            gozlemci.supheli_islemleri_getir()
            kalan = int(t_end - time.time())
            sys.stdout.write(f"\r{Fore.MAGENTA}[*] Veri: {len(veri_havuzu)} | Kalan: {kalan}sn   {Style.RESET_ALL}")
            sys.stdout.flush()
            time.sleep(0.2)

        beyin.egit(veri_havuzu)
        loglayici.log_system(f"AI model eğitimi tamamlandı ({len(veri_havuzu)} örnek)", "INFO")
    else:
        print(f"{Fore.GREEN}[+] AI Zekası Yüklendi.{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}{Style.BRIGHT}[*] GÖZLEM VE ANALİZ BAŞLADI{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─'*60}{Style.RESET_ALL}")

    # Graceful Shutdown
    kapatiliyor = False

    def sinyal_yakala(sig, frame):
        nonlocal kapatiliyor
        kapatiliyor = True

    signal.signal(signal.SIGINT, sinyal_yakala)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, sinyal_yakala)

    # =====================================================
    # ANA GÖZLEM DÖNGÜSÜ
    # =====================================================
    try:
        while not kapatiliyor:
            tehdit_var = False

            # =========================================
            # 1. AĞ İÇERİK ANALİZİ (SNIFFER)
            # =========================================
            ag_alarmlari = koklayici.alarmlari_getir()
            if ag_alarmlari:
                for alarm in ag_alarmlari:
                    print(f"\n{Fore.RED}[!!!] AĞ UYARISI: {alarm}{Style.RESET_ALL}")
                    loglayici.log_network(alarm, "WARNING")
                    loglayici.log_normal(f"NETWORK: {alarm}")
                tehdit_var = True

            # =========================================
            # 2. REGISTRY DEĞİŞİKLİK KONTROLÜ
            # =========================================
            reg_alarmlari = registry_mon.alarmlari_getir()
            if reg_alarmlari:
                for alarm in reg_alarmlari:
                    print(f"\n{Fore.RED}[!!!] REGISTRY UYARISI: {alarm}{Style.RESET_ALL}")
                    loglayici.log_monitor_alarm("registry", alarm, "CRITICAL")
                tehdit_var = True

            # =========================================
            # 3. DLL INJECTION KONTROLÜ
            # =========================================
            dll_alarmlari = dll_mon.alarmlari_getir()
            if dll_alarmlari:
                for alarm in dll_alarmlari:
                    print(f"\n{Fore.RED}[!!!] DLL UYARISI: {alarm}{Style.RESET_ALL}")
                    loglayici.log_monitor_alarm("dll", alarm, "CRITICAL")
                tehdit_var = True

            # =========================================
            # 4. DOSYA SİSTEMİ KONTROLÜ
            # =========================================
            dosya_alarmlari = dosya_mon.alarmlari_getir()
            if dosya_alarmlari:
                for alarm in dosya_alarmlari:
                    print(f"\n{Fore.LIGHTYELLOW_EX}[!!] DOSYA SİSTEMİ: {alarm}{Style.RESET_ALL}")
                    loglayici.log_monitor_alarm("filesystem", alarm, "WARNING")
                tehdit_var = True

            # =========================================
            # 5. TUZAK DOSYA KONTROLÜ (HONEYPOT)
            # =========================================
            alarm, msg = gozlemci.tuzak_kontrol()
            if alarm:
                print(f"\n{Fore.RED}{Style.BRIGHT}[!!!] KRİTİK ALARM: {msg}{Style.RESET_ALL}")
                loglayici.log_monitor_alarm("honeypot", msg, "CRITICAL")
                tehdit_var = True

            # =========================================
            # 6. AI SİSTEM ANALİZİ
            # =========================================
            veri = gozlemci.veri_topla()
            karar, skor = beyin.analiz_et(veri)
            if hasattr(skor, "__len__"):
                skor = skor[0]

            # =========================================
            # 7. İŞLEM (PROCESS) ANALİZİ
            # =========================================
            supheliler = gozlemci.supheli_islemleri_getir()
            en_riskli = [p for p in supheliler if p['pid'] != KENDI_PID]

            if en_riskli:
                hedef = en_riskli[0]
                risk_skoru = hedef['risk_score']
                yara_var = bool(hedef.get('yara_matches'))

                # HİBRİT KARAR: AI + Kural Tabanlı
                if skor < config.ai_anomaly_threshold or risk_skoru > config.risk_threshold or yara_var:
                    pid = hedef['pid']
                    ag_baglantisi = gozlemci.pid_ag_bilgisi(pid)
                    net_map = {pid: ag_baglantisi}

                    # === AI TEHDİT RAPORU ===
                    ai_rapor = beyin.tehdit_raporu_uret(
                        veri, skor, hedef, risk_skoru, ag_baglantisi
                    )
                    beyin.rapor_yazdir(ai_rapor)

                    # Risk detay etiketleri
                    risk_detay = hedef.get('risk_detail', [])
                    if risk_detay:
                        print(f"  {Fore.YELLOW}Risk Etiketleri: {', '.join(risk_detay)}{Style.RESET_ALL}")

                    # Yeni süreç uyarısı
                    if hedef.get('is_new'):
                        print(f"  {Fore.MAGENTA}⚡ YENİ BAŞLATILMIŞ SÜREÇ{Style.RESET_ALL}")

                    # LOG
                    loglayici.log_threat(veri, skor, [hedef], net_map, ai_rapor)
                    tehdit_var = True

            # =========================================
            # 8. NORMAL DURUM BİLDİRİMİ
            # =========================================
            if not tehdit_var:
                max_risk = en_riskli[0]['risk_score'] if en_riskli else 0

                # Durum rengi
                if skor < -0.05:
                    durum_renk = Fore.YELLOW
                    durum = "DİKKAT"
                else:
                    durum_renk = Fore.GREEN
                    durum = "STABİL"

                sys.stdout.write(
                    f"\r{durum_renk}[{durum}]{Style.RESET_ALL} "
                    f"AI: {skor:.2f} | "
                    f"Risk: {max_risk:.1f} | "
                    f"Sniffer: {len(ag_alarmlari if ag_alarmlari else [])} alarm   "
                )
                sys.stdout.flush()

            time.sleep(config.ana_dongu_bekleme)

    except Exception as e:
        print(f"\n{Fore.RED}[HATA] {e}{Style.RESET_ALL}")
        loglayici.log_system(f"Beklenmeyen hata: {e}", "CRITICAL")

    # =====================================================
    # GRACEFUL SHUTDOWN
    # =====================================================
    print(f"\n\n{Fore.YELLOW}[*] Kapatılıyor...{Style.RESET_ALL}")
    koklayici.durdur()
    registry_mon.durdur()
    dll_mon.durdur()
    dosya_mon.durdur()
    loglayici.log_system("ThreadDetector kapatıldı", "INFO")
    print(f"{Fore.GREEN}[+] Tüm modüller güvenle durduruldu.{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Loglar kaydedildi: {config.log_dir}/{Style.RESET_ALL}")


if __name__ == "__main__":
    main()