# ai_brain.py - BIRIKIMLI OGRENME SURUMU
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import numpy as np
import joblib
import os

class YapayZekaMotoru:
    def __init__(self, model_path="sentinel_model.pkl", data_path="normal_veri_havuzu.npy"):
        self.model_path = model_path
        self.data_path = data_path # Ham verilerin saklanacağı yer
        self.is_trained = False
        
        self.pipeline = Pipeline([
            ('scaler', StandardScaler()), 
            ('model', IsolationForest(
                n_estimators=200,
                contamination=0.01, # %1 hata payı
                max_samples='auto', 
                random_state=42,
                n_jobs=-1
            ))
        ])

        self._modeli_yukle()

    def veriyi_kaydet(self, yeni_veri_listesi):
        """
        Yeni toplanan normal verileri eskilerin üstüne ekler ve diske yazar.
        """
        yeni_veri = np.array(yeni_veri_listesi)
        
        if os.path.exists(self.data_path):
            eski_veri = np.load(self.data_path, allow_pickle=True)
            # Eski ve yeniyi birleştir (Concatenate)
            birlesmis_veri = np.vstack((eski_veri, yeni_veri))
        else:
            birlesmis_veri = yeni_veri
            
        # Diske kaydet (.npy formatı hızlıdır)
        np.save(self.data_path, birlesmis_veri)
        print(f"[+] Veri havuzu güncellendi. Toplam örneklem: {len(birlesmis_veri)}")
        return birlesmis_veri

    def egit(self, yeni_veri_listesi=None):
        """
        Hem eski hem yeni veriyi kullanarak modeli 'Re-Train' yapar.
        """
        # 1. Verileri Birleştir ve Kaydet
        if yeni_veri_listesi:
            tum_veri = self.veriyi_kaydet(yeni_veri_listesi)
        elif os.path.exists(self.data_path):
            tum_veri = np.load(self.data_path, allow_pickle=True)
        else:
            print("[!] Hata: Eğitilecek veri bulunamadı.")
            return

        # Yetersiz veri kontrolü
        if len(tum_veri) < 50:
            print(f"[!] Yetersiz veri ({len(tum_veri)}). Eğitim iptal.")
            return

        print(f"[*] AI Genişletilmiş Veriyle Eğitiliyor... ({len(tum_veri)} kayıt)")
        
        # 2. Eğit
        self.pipeline.fit(tum_veri)
        self.is_trained = True
        
        # 3. Modeli Kaydet
        joblib.dump(self.pipeline, self.model_path)
        print("[+] Yeni Beyin (Model) kaydedildi.")

    def analiz_et(self, live_data):
        if not self.is_trained:
            return 1, 0.0

        data_point = np.array(live_data).reshape(1, -1)
        try:
            prediction = self.pipeline.predict(data_point)
            score = self.pipeline.decision_function(data_point)
            return prediction[0], score[0]
        except:
            return 1, 0.0

    def _modeli_yukle(self):
        if os.path.exists(self.model_path):
            try:
                self.pipeline = joblib.load(self.model_path)
                self.is_trained = True
                print("[+] Kayıtlı zeka aktif.")
            except:
                pass