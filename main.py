# main.py - FINAL TAM SURUM (CPU + RAM + DISK RANSOMWARE KORUMASI)
import time
import psutil
import sys
import os
from monitor import SistemGozlemcisi
from ai_brain import YapayZekaMotoru
from logger import GuvenlikLogger

# --- GÜVENLİ LİSTE (WHITELIST) ---
# AI bu listedeki işlemleri şüpheli bulsa bile ASLA kapatmaz.
# Not: "Code.exe" VS Code'dur, geliştirme yaparken kapanmaması için ekledik.
GUVENLI_LISTE = [
    "explorer.exe", "svchost.exe", "system", "registry", 
    "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "winlogon.exe", "searchui.exe", "taskmgr.exe",
    "spoolsv.exe", "chrome.exe", "discord.exe", "firefox.exe", 
    "spotify.exe", "steam.exe", "code.exe", "conhost.exe",
]

# Programın kendi PID'sini (Kimlik No) öğreniyoruz (İntiharı önlemek için)
KENDI_PID = os.getpid()

def tehdidi_yok_et(pid, name):
    """Verilen PID'ye sahip işlemi sonlandırır."""
    
    # 1. Kural: KENDİNİ ASLA KAPATMA!
    if pid == KENDI_PID:
        print(f"\n[KORUMA] AI kendini kapatmaya çalıştı, engellendi. (PID: {pid})")
        return False

    # 2. Kural: Güvenli liste kontrolü
    if name.lower() in [x.lower() for x in GUVENLI_LISTE]:
        return False

    try:
        p = psutil.Process(pid)
        p.terminate() # Kibarca kapat
        # p.kill() # Eğer inatçı virüs ise bunu aktif et
        
        print(f"\n{'!'*50}")
        print(f"[!!!] MÜDAHALE EDİLDİ: {name} (PID: {pid}) SONLANDIRILDI!")
        print(f"{'!'*50}\n")
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        print(f"\n[!] HATA: {name} (PID: {pid}) kapatılamadı. Yönetici izni gerekebilir.")
    except Exception as e:
        print(f"\n[!] Beklenmeyen hata: {e}")
    return False

def main():
    # Windows'ta process öldürmek için Yönetici izni gerekebilir.
    gozlemci = SistemGozlemcisi()
    beyin = YapayZekaMotoru() 
    loglayici = GuvenlikLogger()

    print(f"--- AI GÜVENLİK SİSTEMİ BAŞLATILDI (PID: {KENDI_PID}) ---")

    # --- EĞİTİM VE BAŞLANGIÇ MENÜSÜ ---
    print("\n[?] AI Modu Seçimi")
    print("1. Hızlı Başlat (Mevcut Zekayı Kullan)")
    print("2. Eğitimi İyileştir (Mevcut Zekaya Yeni Veri Ekle)")
    print("3. Sıfırla ve Baştan Eğit (Hafızayı Temizle)")
    
    secim = input("Seçiminiz (1/2/3): ")

    # 3. Seçenek: Sıfırlama
    if secim == '3':
        print("[*] Hafıza siliniyor...")
        if os.path.exists("sentinel_model.pkl"): os.remove("sentinel_model.pkl")
        if os.path.exists("normal_veri_havuzu.npy"): os.remove("normal_veri_havuzu.npy")
        beyin = YapayZekaMotoru() # Beyni yeniden başlat
        secim = '2' # Mecburen eğitime yönlendir

    # Eğitim Modu (Seçim 2 veya Hiç Model Yoksa)
    if secim == '2' or not beyin.is_trained:
        print("\n[*] EĞİTİM MODU (45 Saniye)...")
        print("Lütfen bilgisayarı biraz YORUN (Video açın, dosya kopyalayın, müzik dinleyin).")
        print("Bu sayede AI, 'yoğun kullanımın' normal olduğunu öğrenecek.")
        
        egitim_suresi = 45
        veri_havuzu = []
        start_time = time.time()
        
        while time.time() - start_time < egitim_suresi:
            kalan = int(egitim_suresi - (time.time() - start_time))
            veri = gozlemci.veri_topla()
            veri_havuzu.append(veri)
            
            # İlerleme göstergesi
            sys.stdout.write(f"\r[*] Veri Toplanıyor: {len(veri_havuzu)} adet | Kalan: {kalan}sn ")
            sys.stdout.flush()
            time.sleep(0.1)
        
        print("\n")
        beyin.egit(veri_havuzu) 
    else:
        print("[+] Mevcut zeka yüklendi. Koruma başlıyor.")

    # --- KORUMA DÖNGÜSÜ (MAIN LOOP) ---
    print("\n[*] AKTİF KORUMA MODU DEVREDE. (Durdurmak için CTRL+C)")
    
    try:
        while True:
            # 1. Veri Al ve Analiz Et
            anlik_veri = gozlemci.veri_topla()
            karar, skor = beyin.analiz_et(anlik_veri)
            
            if karar == -1:
                # ANOMALİ TESPİT EDİLDİ
                supheli_islemler = gozlemci.supheli_islemleri_getir()
                
                # Log dosyasına yaz (Skoru -0.06'dan düşük olan ciddi tehditleri)
                if skor < -0.06: 
                     loglayici.log_threat(anlik_veri, skor, supheli_islemler)
                
                # --- GELİŞMİŞ AKSİYON VE MÜDAHALE MEKANİZMASI ---
                en_supheli = supheli_islemler[0] if supheli_islemler else None
                
                # PID 0 (Idle) ve PID 4 (System) hariç tutulur
                if en_supheli and en_supheli['pid'] not in [0, 4, KENDI_PID]:
                    
                    mudahale_sebebi = ""
                    
                    # KOŞUL 1: CPU SALDIRISI (Crypto Miner, Sonsuz Döngü)
                    # AI Anomali dedi (-0.1) VE CPU %85'i geçti
                    if skor < -0.1 and en_supheli['cpu_percent'] > 85:
                        mudahale_sebebi = "AŞIRI CPU KULLANIMI"

                    # KOŞUL 2: RAM SALDIRISI (Memory Leak)
                    # AI Anomali dedi (-0.1) VE İşlem tek başına RAM'in %30'undan fazlasını yedi
                    elif skor < -0.1 and en_supheli['memory_percent'] > 30:
                        mudahale_sebebi = "RAM SIZINTISI / ŞİŞİRME"

                    # KOŞUL 3: DISK / RANSOMWARE SALDIRISI
                    # AI Anomali dedi (-0.15 - Daha ciddi) VE İşlem 500 MB üzeri veri yazdı
                    elif skor < -0.15 and en_supheli.get('disk_write', 0) > 500 * 1024 * 1024:
                        mudahale_sebebi = "ANORMAL DİSK YAZMA (Ransomware Şüphesi)"

                    # KOŞUL 4: GENEL KRİTİK ANOMALİ
                    # CPU/RAM/Disk belirli sınırı geçmese bile AI çok eminse (-0.22)
                    elif skor < -0.22:
                        mudahale_sebebi = "TANIMLANAMAYAN KRİTİK DAVRANIŞ"

                    # EĞER BİR SEBEP BULUNDUYSA -> VUR
                    if mudahale_sebebi:
                        print(f"\n[AI TESPİTİ] {mudahale_sebebi} | Güven Skoru: {skor:.4f}")
                        basari = tehdidi_yok_et(en_supheli['pid'], en_supheli['name'])
                        
                        if basari:
                            loglayici.log_normal(f"TEHDİT ENGELLENDİ ({mudahale_sebebi}): {en_supheli['name']}\n")
                            # Sistem toparlansın diye biraz bekle
                            time.sleep(3)
            
            else:
                # NORMAL DURUM
                sys.stdout.write(f"\r[OK] Sistem Güvenli | Skor: {skor:.4f}   ")
                sys.stdout.flush()
            
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n[!] Sistem kullanıcı tarafından durduruldu.")

if __name__ == "__main__":
    main()