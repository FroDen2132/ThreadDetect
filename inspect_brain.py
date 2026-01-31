import numpy as np
import joblib
import os
import matplotlib.pyplot as plt

def incele():
    data_path = "normal_veri_havuzu.npy"
    model_path = "sentinel_model.pkl"

    print("--- AI BEYİN ANALİZ RAPORU ---\n")

    # 1. VERİ HAVUZUNU İNCELE
    if os.path.exists(data_path):
        try:
            # Veriyi yükle
            data = np.load(data_path, allow_pickle=True)
            adet, ozellik_sayisi = data.shape
            
            print(f"[+] Veri Havuzu Yüklendi: '{data_path}'")
            print(f"    - Toplam Örneklem Sayısı: {adet}")
            print(f"    - İzlenen Özellik Sayısı: {ozellik_sayisi} (CPU, RAM, Disk, Ağ, PID)")
            
            # Sütunlar: 0:CPU, 1:RAM, 2:Disk, 3:Ağ, 4:PID
            avg_cpu = np.mean(data[:, 0])
            max_cpu = np.max(data[:, 0])
            avg_ram = np.mean(data[:, 1])
            max_ram = np.max(data[:, 1])
            
            print(f"\n[i] 'NORMAL' KABUL EDİLEN DEĞERLER:")
            print(f"    - Ortalama CPU Kullanımı : %{avg_cpu:.2f}")
            print(f"    - En Yüksek CPU (Normal): %{max_cpu:.2f}")
            print(f"    - Ortalama RAM Kullanımı : %{avg_ram:.2f}")
            print(f"    - En Yüksek RAM (Normal): %{max_ram:.2f}")
            
            # Grafik Çiz (Görselleştirme)
            plt.figure(figsize=(12, 5))
            plt.plot(data[:, 0], label='CPU %', color='blue', alpha=0.7)
            plt.plot(data[:, 1], label='RAM %', color='orange', alpha=0.7)
            plt.title(f"AI'ın Öğrendiği Normal Davranış Grafiği ({adet} Örnek)")
            plt.xlabel("Zaman (Örneklem)")
            plt.ylabel("Kullanım (%)")
            plt.legend()
            plt.grid(True, alpha=0.3)
            print("\n[+] Grafik oluşturuluyor... (Pencere açılacak)")
            plt.show()

        except Exception as e:
            print(f"[-] Veri okunurken hata: {e}")
    else:
        print(f"[-] '{data_path}' dosyası bulunamadı. Henüz eğitim yapılmamış.")

    # 2. MODELİ İNCELE
    print("\n--------------------------------")
    if os.path.exists(model_path):
        try:
            model = joblib.load(model_path)
            print(f"[+] Model Dosyası Yüklendi: '{model_path}'")
            print(f"    - Model Tipi: {type(model).__name__}")
            # Pipeline içindeki asıl modeli al
            if hasattr(model, 'steps'):
                real_model = model.named_steps['model']
                print(f"    - Algoritma: IsolationForest")
                print(f"    - Ağaç Sayısı (Estimators): {real_model.n_estimators}")
                print(f"    - Kirlilik Oranı (Contamination): {real_model.contamination}")
                print("    - Durum: Model sağlıklı görünüyor.")
        except Exception as e:
            print(f"[-] Model bozuk veya uyumsuz: {e}")
    else:
        print(f"[-] '{model_path}' bulunamadı.")

if __name__ == "__main__":
    incele()