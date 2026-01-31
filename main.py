# main.py - HIBRIT ALGILAMA (Process Risk Öncelikli)
import time
import sys
import os
import psutil
from monitor import SistemGozlemcisi
from ai_brain import YapayZekaMotoru
from logger import GuvenlikLogger

# --- ARKA PLAN ÇALIŞMA AYARI ---
def set_high_priority():
    """İşlemi Windows'ta Yüksek Öncelik moduna alır"""
    try:
        p = psutil.Process(os.getpid())
        if os.name == 'nt': 
            p.nice(psutil.HIGH_PRIORITY_CLASS)
        else:
            p.nice(-10)
    except: pass

KENDI_PID = os.getpid()

def main():
    set_high_priority()
    gozlemci = SistemGozlemcisi()
    beyin = YapayZekaMotoru() 
    loglayici = GuvenlikLogger()

    print(f"--- AI SİBER TEHDİT ANALİZ SİSTEMİ (PID: {KENDI_PID}) ---")
    print("[!] MOD: HİBRİT (AI + Kural Tabanlı Kesin Tespit)")
    
    # --- MENÜ ---
    print("\n[?] Başlangıç Seçeneği")
    print("1. Hızlı Başlat")
    print("2. Eğitimi İyileştir")
    print("3. Sıfırla ve Baştan Eğit")
    secim = input("Seçiminiz (1/2/3): ")

    if secim == '3':
        if os.path.exists("sentinel_model.pkl"): os.remove("sentinel_model.pkl")
        if os.path.exists("normal_veri_havuzu.npy"): os.remove("normal_veri_havuzu.npy")
        beyin = YapayZekaMotoru()
        secim = '2'

    if secim == '2' or not beyin.is_trained:
        print("\n[*] ORTAM ÖĞRENİLİYOR (20 Sn)...")
        t_end = time.time() + 20
        veri_havuzu = []
        
        # Cache Isıtma
        for _ in range(5):
            gozlemci.veri_topla()
            gozlemci.supheli_islemleri_getir()
            time.sleep(0.1)
            
        while time.time() < t_end:
            v = gozlemci.veri_topla()
            veri_havuzu.append(v)
            gozlemci.supheli_islemleri_getir()
            sys.stdout.write(f"\r[*] Veri: {len(veri_havuzu)} ")
            sys.stdout.flush()
            time.sleep(0.2)
        beyin.egit(veri_havuzu)
        print("\n[+] Model Hazır.")
    else:
        print("[+] Zeka Yüklendi.")

    print("\n[*] GÖZLEM BAŞLADI...")
    print("-" * 60)
    
    try:
        while True:
            # 1. TUZAK KONTROL
            alarm, msg = gozlemci.tuzak_kontrol()
            if alarm:
                print(f"\n[!!!] KRİTİK ALARM: {msg}")
                loglayici.log_normal(f"KRİTİK: {msg}")

            # 2. VERİ TOPLAMA
            veri = gozlemci.veri_topla()
            karar, skor = beyin.analiz_et(veri)
            if hasattr(skor, "__len__"): skor = skor[0]

            # 3. İŞLEM ANALİZİ (Her döngüde kontrol et)
            supheliler = gozlemci.supheli_islemleri_getir()
            en_riskli = [p for p in supheliler if p['pid'] != KENDI_PID]
            
            tehdit_var = False
            hedef = None
            etiket = ""

            if en_riskli:
                hedef = en_riskli[0]
                risk_skoru = hedef['risk_score']

                # --- HİBRİT KARAR MEKANİZMASI ---
                # Durum A: AI genel sistemde anormallik sezdi (Skor < -0.15)
                # Durum B: Bir işlem çıldırmış (Risk Skoru > 50) -> SENİN DURUMUN BURASI
                
                if skor < -0.15 or risk_skoru > 50.0:
                    pid = hedef['pid']
                    ag_baglantisi = gozlemci.pid_ag_bilgisi(pid)
                    net_map = {pid: ag_baglantisi}
                    
                    tehditler = []
                    # Tehdit Etiketleri
                    if hedef['cpu_percent'] > 30: tehditler.append("YÜKSEK CPU")
                    if hedef['memory_percent'] > 20: tehditler.append("RAM ŞİŞİRME")
                    if hedef['disk_speed'] > 5.0: tehditler.append(f"DİSK ({hedef['disk_speed']:.1f} MB/s)")
                    
                    # Ağ Kontrolleri
                    if hedef['conn_count'] > 10: tehditler.append(f"ÇOKLU BAĞLANTI ({hedef['conn_count']})")
                    if ag_baglantisi != ["Ağ Bağlantısı Yok"] and hedef['conn_count'] > 0: 
                         if "AĞ AKTİVİTESİ" not in tehditler: tehditler.append("AĞ AKTİVİTESİ")

                    if not tehditler: tehditler.append("ANORMAL DAVRANIŞ")
                    etiket = " + ".join(tehditler)
                    
                    # Loglama Yap
                    tehdit_var = True
                    # Ekrana basarken satır atla (\n) ki silinmesin
                    print(f"\n[!] TESPİT: {hedef['name']} | {etiket} | Risk: {risk_skoru:.1f} | AI Güven: {skor:.2f}")
                    loglayici.log_threat(veri, skor, [hedef], net_map)
            
            # Eğer tehdit yoksa normal durum yazdır
            if not tehdit_var:
                sys.stdout.write(f"\r[OK] Sistem Normal | AI Güven: {skor:.2f} | Max Risk: {en_riskli[0]['risk_score'] if en_riskli else 0:.1f}   ")
                sys.stdout.flush()
            
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\nÇıkış.")
    except Exception as e:
        print(f"\n[HATA] {e}")

if __name__ == "__main__":
    main()