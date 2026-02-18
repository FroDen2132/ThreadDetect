# ai_brain.py - GELİŞMİŞ YAPAY ZEKA MOTORU (Tehdit Raporu + Adaptive Threshold)
import numpy as np
import os
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from datetime import datetime


class YapayZekaMotoru:
    def __init__(self, config=None):
        from config import Config
        self.config = config or Config()
        self.model_path = self.config.model_path
        self.data_path = self.config.data_path
        self.model = None
        self.is_trained = False
        self.feature_names = [
            "CPU (%)", "RAM (%)", "Disk I/O (MB/s)",
            "Ağ Trafiği (MB/s)", "Aktif İşlem Sayısı"
        ]
        self.modeli_yukle()

    # =====================================================
    # VERİ KAYDETME
    # =====================================================
    def veriyi_kaydet(self, yeni_veri_listesi):
        """Verileri boyut hatası olmadan kaydeder."""
        if not yeni_veri_listesi:
            return None

        try:
            yeni_veri = np.vstack(yeni_veri_listesi)
        except Exception as e:
            print(f"[HATA] Veri işleme hatası: {e}")
            return None

        if os.path.exists(self.data_path):
            try:
                eski_veri = np.load(self.data_path, allow_pickle=True)
                birlesmis_veri = np.vstack((eski_veri, yeni_veri))
            except Exception:
                birlesmis_veri = yeni_veri
        else:
            birlesmis_veri = yeni_veri

        np.save(self.data_path, birlesmis_veri)
        return birlesmis_veri

    # =====================================================
    # EĞİTİM
    # =====================================================
    def egit(self, veri_listesi):
        """AI modelini eğitir ve model kalite raporunu yazdırır."""
        print("[*] AI Veriyle Eğitiliyor...")
        tum_veri = self.veriyi_kaydet(veri_listesi)

        if tum_veri is None or len(tum_veri) < self.config.ai_min_sample:
            print(f"[!] Yetersiz veri ({len(tum_veri) if tum_veri is not None else 0}/{self.config.ai_min_sample}). Daha fazla süre çalıştırın.")
            return

        # Adaptive Contamination: Veri miktarına göre ayarla
        contamination = self.config.ai_contamination
        if len(tum_veri) > 500:
            contamination = max(0.005, contamination * 0.8)
        elif len(tum_veri) < 50:
            contamination = min(0.05, contamination * 1.5)

        self.model = Pipeline([
            ('scaler', StandardScaler()),
            ('model', IsolationForest(
                n_estimators=self.config.ai_n_estimators,
                contamination=contamination,
                random_state=42,
                max_features=1.0,
                bootstrap=True
            ))
        ])

        self.model.fit(tum_veri)
        joblib.dump(self.model, self.model_path)
        self.is_trained = True

        # === MODEL KALİTE RAPORU ===
        skorlar = self.model.decision_function(tum_veri)
        print(f"\n{'='*50}")
        print(f"  AI MODEL KALİTE RAPORU")
        print(f"{'='*50}")
        print(f"  Eğitim Verisi       : {len(tum_veri)} örnek")
        print(f"  Contamination       : {contamination:.4f}")
        print(f"  Özellik Sayısı      : {tum_veri.shape[1]}")
        print(f"  Ortalama Skor       : {np.mean(skorlar):.4f}")
        print(f"  Min Skor            : {np.min(skorlar):.4f}")
        print(f"  Max Skor            : {np.max(skorlar):.4f}")
        print(f"  Standart Sapma      : {np.std(skorlar):.4f}")
        print(f"{'='*50}")
        print(f"[+] Yeni Model Kaydedildi: {self.model_path}")

    # =====================================================
    # MODEL YÜKLEME
    # =====================================================
    def modeli_yukle(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                self.is_trained = True
            except Exception:
                self.is_trained = False
        else:
            self.is_trained = False

    # =====================================================
    # ANALİZ
    # =====================================================
    def analiz_et(self, veri_vektoru):
        """Veriyi analiz eder, tahmin ve skor döner."""
        if not self.is_trained or self.model is None:
            return 1, 0.0
        try:
            tahmin = self.model.predict(veri_vektoru)
            skor = self.model.decision_function(veri_vektoru)
            return tahmin[0], skor[0]
        except Exception:
            return 1, 0.0

    # =====================================================
    # TEHTİT SEVİYESİ BELİRLEME
    # =====================================================
    def tehdit_seviyesi_belirle(self, ai_skor, risk_skoru, yara_var=False):
        """AI skoru ve risk skoruna göre tehdit seviyesi belirler."""
        if yara_var or risk_skoru > 2000:
            return "KRİTİK", "🔴"
        elif ai_skor < -0.3 or risk_skoru > 200:
            return "YÜKSEK", "🟠"
        elif ai_skor < -0.15 or risk_skoru > 50:
            return "ORTA", "🟡"
        elif ai_skor < -0.05 or risk_skoru > 20:
            return "DÜŞÜK", "🔵"
        else:
            return "GÜVENLİ", "🟢"

    # =====================================================
    # AI TEHDİT RAPORU ÜRETİCİ
    # =====================================================
    def tehdit_raporu_uret(self, veri_vektoru, ai_skor, islem_bilgisi, risk_skoru=0, ag_bilgisi=None):
        """
        Tespit edilen tehdidi analiz edip insan-okunabilir Türkçe rapor üretir.
        Feature importance analizi yaparak hangi metriğin anomaliyi tetiklediğini belirler.
        """
        seviye, ikon = self.tehdit_seviyesi_belirle(ai_skor, risk_skoru,
                                                      bool(islem_bilgisi.get('yara_matches')))

        # Feature Importance Analizi
        anomali_nedenleri = []
        if hasattr(veri_vektoru, '__len__') and len(veri_vektoru.flatten()) >= 5:
            degerler = veri_vektoru.flatten()
            feature_analizleri = [
                (degerler[0], 25.0, "CPU", f"CPU kullanımı %{degerler[0]:.1f} — normalin üzerinde işlemci yükü"),
                (degerler[1], 40.0, "RAM", f"RAM kullanımı %{degerler[1]:.1f} — yüksek bellek tüketimi"),
                (degerler[2], 5.0, "Disk", f"Disk I/O {degerler[2]:.1f} MB/s — yoğun disk aktivitesi"),
                (degerler[3], 2.0, "Ağ", f"Ağ trafiği {degerler[3]:.1f} MB/s — olağandışı veri transferi"),
            ]
            for deger, esik, ad, aciklama in feature_analizleri:
                if deger > esik:
                    anomali_nedenleri.append(aciklama)

        # İşlem bazlı analizler
        if islem_bilgisi.get('cpu_percent', 0) > self.config.cpu_threshold:
            anomali_nedenleri.append(
                f"İşlem CPU: %{islem_bilgisi['cpu_percent']:.1f} — tek başına yüksek işlemci kullanımı"
            )
        if islem_bilgisi.get('conn_count', 0) > self.config.conn_threshold:
            anomali_nedenleri.append(
                f"Bağlantı sayısı: {islem_bilgisi['conn_count']} — çok sayıda ağ bağlantısı"
            )
        if islem_bilgisi.get('disk_speed', 0) > self.config.disk_threshold:
            anomali_nedenleri.append(
                f"Disk hızı: {islem_bilgisi['disk_speed']:.1f} MB/s — şüpheli disk aktivitesi"
            )
        if islem_bilgisi.get('yara_matches'):
            anomali_nedenleri.append(
                f"YARA İmza Eşleşmesi: {', '.join(islem_bilgisi['yara_matches'])} — bilinen zararlı yazılım imzası!"
            )

        # Komut satırı analizi
        cmd = islem_bilgisi.get('cmd_line', '').lower()
        if cmd:
            for pattern in self.config.lolbins_patterns:
                if pattern in cmd:
                    anomali_nedenleri.append(f"LOLBin kullanımı: '{pattern}' — meşru araç kötüye kullanılıyor olabilir")
                    break

        # Önerilen aksiyon
        if seviye == "KRİTİK":
            aksiyon = "🛑 DERHAL DURDUR — İşlemi sonlandırın ve forensic analiz başlatın"
        elif seviye == "YÜKSEK":
            aksiyon = "⚠️ KARANTİNA — İşlemi izole edin ve detaylı inceleme yapın"
        elif seviye == "ORTA":
            aksiyon = "🔍 ARAŞTIR — İşlemi yakından izleyin ve davranış loglarını inceleyin"
        else:
            aksiyon = "👁️ İZLE — Kayıt altına alın ve gözlemlemeye devam edin"

        # Anomali neden bulunamadıysa
        if not anomali_nedenleri:
            anomali_nedenleri.append("AI modeli genel sistem davranışında anomali tespit etti (spesifik neden belirlenemedi)")

        # Rapor oluştur
        rapor = {
            "zaman": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "seviye": seviye,
            "ikon": ikon,
            "islem": {
                "ad": islem_bilgisi.get('name', 'Bilinmiyor'),
                "pid": islem_bilgisi.get('pid', 0),
                "cmd": islem_bilgisi.get('cmd_line', ''),
            },
            "ai_skor": round(ai_skor, 4),
            "risk_skoru": round(risk_skoru, 1),
            "anomali_nedenleri": anomali_nedenleri,
            "onerilen_aksiyon": aksiyon,
            "ag_bilgisi": ag_bilgisi or [],
            "parent_bilgisi": islem_bilgisi.get('parent_info', None),
        }

        return rapor

    def rapor_yazdir(self, rapor):
        """AI tehdit raporunu terminale formatlanmış şekilde yazdırır."""
        print(f"\n{'='*60}")
        print(f"  {rapor['ikon']} AI TEHDİT RAPORU — {rapor['seviye']}")
        print(f"{'='*60}")
        print(f"  Zaman          : {rapor['zaman']}")
        print(f"  İşlem          : {rapor['islem']['ad']} (PID: {rapor['islem']['pid']})")
        if rapor['islem']['cmd']:
            cmd = rapor['islem']['cmd']
            if len(cmd) > 80:
                cmd = cmd[:80] + "..."
            print(f"  Komut          : {cmd}")
        print(f"  AI Skoru       : {rapor['ai_skor']}")
        print(f"  Risk Skoru     : {rapor['risk_skoru']}")

        if rapor.get('parent_bilgisi'):
            p = rapor['parent_bilgisi']
            print(f"  Üst İşlem      : {p.get('name', '?')} (PID: {p.get('pid', '?')})")

        print(f"\n  📋 ANOMALİ NEDENLERİ:")
        for i, neden in enumerate(rapor['anomali_nedenleri'], 1):
            print(f"     {i}. {neden}")

        if rapor['ag_bilgisi'] and rapor['ag_bilgisi'] != ["Ağ Bağlantısı Yok"]:
            print(f"\n  🌐 AĞ BAĞLANTILARI:")
            for bag in rapor['ag_bilgisi'][:5]:
                print(f"     • {bag}")
            if len(rapor['ag_bilgisi']) > 5:
                print(f"     ... ve {len(rapor['ag_bilgisi'])-5} bağlantı daha")

        print(f"\n  📌 ÖNERİLEN AKSİYON:")
        print(f"     {rapor['onerilen_aksiyon']}")
        print(f"{'='*60}")