# ai_brain.py - YAPAY ZEKA MOTORU
import numpy as np
import os
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

class YapayZekaMotoru:
    def __init__(self):
        self.model_path = "sentinel_model.pkl"
        self.data_path = "normal_veri_havuzu.npy"
        self.model = None
        self.is_trained = False
        self.modeli_yukle()

    def veriyi_kaydet(self, yeni_veri_listesi):
        """Verileri boyut hatası olmadan kaydeder"""
        if not yeni_veri_listesi: return None
            
        try:
            # Listeyi dikey olarak birleştir (Flatten)
            yeni_veri = np.vstack(yeni_veri_listesi)
        except Exception as e:
            print(f"[HATA] Veri işleme hatası: {e}")
            return None

        if os.path.exists(self.data_path):
            try:
                eski_veri = np.load(self.data_path, allow_pickle=True)
                birlesmis_veri = np.vstack((eski_veri, yeni_veri))
            except:
                birlesmis_veri = yeni_veri
        else:
            birlesmis_veri = yeni_veri
            
        np.save(self.data_path, birlesmis_veri)
        return birlesmis_veri

    def egit(self, veri_listesi):
        print("[*] AI Veriyle Eğitiliyor...")
        tum_veri = self.veriyi_kaydet(veri_listesi)
        
        if tum_veri is None or len(tum_veri) < 10:
            print("[!] Yetersiz veri. Eğitim için daha fazla süre çalıştırın.")
            return

        self.model = Pipeline([
            ('scaler', StandardScaler()),
            ('model', IsolationForest(n_estimators=200, contamination=0.01, random_state=42))
        ])
        
        self.model.fit(tum_veri)
        joblib.dump(self.model, self.model_path)
        self.is_trained = True
        print(f"[+] Yeni Model Kaydedildi.")

    def modeli_yukle(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                self.is_trained = True
            except: self.is_trained = False
        else: self.is_trained = False

    def analiz_et(self, veri_vektoru):
        if not self.is_trained or self.model is None:
            return 1, 0.0 # Model yoksa güvenli say
        try:
            tahmin = self.model.predict(veri_vektoru)
            skor = self.model.decision_function(veri_vektoru)
            return tahmin[0], skor[0]
        except:
            return 1, 0.0