# inspect_brain.py - GELİŞMİŞ AI BEYİN ANALİZ RAPORU
import numpy as np
import joblib
import os


def incele():
    data_path = "normal_veri_havuzu.npy"
    model_path = "sentinel_model.pkl"

    print("╔══════════════════════════════════════════════╗")
    print("║         AI BEYİN ANALİZ RAPORU               ║")
    print("╚══════════════════════════════════════════════╝\n")

    feature_names = ["CPU (%)", "RAM (%)", "Disk I/O (MB/s)", "Ağ (MB/s)", "İşlem Sayısı"]

    # ==========================================
    # 1. VERİ HAVUZUNU İNCELE
    # ==========================================
    if os.path.exists(data_path):
        try:
            data = np.load(data_path, allow_pickle=True)
            adet, ozellik_sayisi = data.shape

            print(f"[+] Veri Havuzu: '{data_path}'")
            print(f"    Toplam Örneklem : {adet}")
            print(f"    Özellik Sayısı  : {ozellik_sayisi}")

            print(f"\n{'─'*50}")
            print(f"  'NORMAL' KABUL EDİLEN DEĞERLER:")
            print(f"{'─'*50}")
            print(f"  {'Özellik':<20} {'Ort':>8} {'Min':>8} {'Max':>8} {'Std':>8}")
            print(f"  {'─'*44}")

            for i in range(min(ozellik_sayisi, len(feature_names))):
                col = data[:, i]
                print(f"  {feature_names[i]:<20} {np.mean(col):>8.2f} {np.min(col):>8.2f} {np.max(col):>8.2f} {np.std(col):>8.2f}")

            # Grafik Çizimi (matplotlib opsiyonel)
            try:
                import matplotlib.pyplot as plt
                fig, axes = plt.subplots(2, 2, figsize=(14, 8))
                fig.suptitle(f"AI'ın Öğrendiği Normal Davranış ({adet} Örnek)", fontsize=14)

                # CPU
                axes[0, 0].plot(data[:, 0], color='#2196F3', alpha=0.8, linewidth=0.8)
                axes[0, 0].set_title("CPU Kullanımı (%)")
                axes[0, 0].fill_between(range(adet), data[:, 0], alpha=0.3, color='#2196F3')
                axes[0, 0].grid(True, alpha=0.3)

                # RAM
                axes[0, 1].plot(data[:, 1], color='#FF9800', alpha=0.8, linewidth=0.8)
                axes[0, 1].set_title("RAM Kullanımı (%)")
                axes[0, 1].fill_between(range(adet), data[:, 1], alpha=0.3, color='#FF9800')
                axes[0, 1].grid(True, alpha=0.3)

                # Disk
                axes[1, 0].plot(data[:, 2], color='#4CAF50', alpha=0.8, linewidth=0.8)
                axes[1, 0].set_title("Disk I/O (MB/s)")
                axes[1, 0].fill_between(range(adet), data[:, 2], alpha=0.3, color='#4CAF50')
                axes[1, 0].grid(True, alpha=0.3)

                # Ağ
                axes[1, 1].plot(data[:, 3], color='#F44336', alpha=0.8, linewidth=0.8)
                axes[1, 1].set_title("Ağ Trafiği (MB/s)")
                axes[1, 1].fill_between(range(adet), data[:, 3], alpha=0.3, color='#F44336')
                axes[1, 1].grid(True, alpha=0.3)

                plt.tight_layout()
                print("\n[+] Grafik oluşturuluyor...")
                plt.show()
            except ImportError:
                print("\n[i] matplotlib yüklü değil, grafik atlanıyor.")

        except Exception as e:
            print(f"[-] Veri okunurken hata: {e}")
    else:
        print(f"[-] '{data_path}' bulunamadı. Henüz eğitim yapılmamış.")

    # ==========================================
    # 2. MODELİ İNCELE
    # ==========================================
    print(f"\n{'─'*50}")
    if os.path.exists(model_path):
        try:
            model = joblib.load(model_path)
            print(f"[+] Model: '{model_path}'")
            print(f"    Tip      : {type(model).__name__}")

            if hasattr(model, 'steps'):
                real_model = model.named_steps['model']
                scaler = model.named_steps['scaler']
                print(f"    Algoritma  : IsolationForest")
                print(f"    Ağaç Sayısı: {real_model.n_estimators}")
                print(f"    Kirlilik   : {real_model.contamination}")
                print(f"    Max Feat.  : {real_model.max_features}")

                if hasattr(scaler, 'mean_') and scaler.mean_ is not None:
                    print(f"\n  Scaler Ortalamaları:")
                    for i, m in enumerate(scaler.mean_):
                        fname = feature_names[i] if i < len(feature_names) else f"Feature_{i}"
                        print(f"    {fname:<20}: mean={m:.4f}, std={scaler.scale_[i]:.4f}")

                # Anomali testi
                if os.path.exists(data_path):
                    data = np.load(data_path, allow_pickle=True)
                    scores = model.decision_function(data)
                    predictions = model.predict(data)
                    anomali_sayisi = np.sum(predictions == -1)
                    print(f"\n  Anomali Testi (Eğitim Verisi Üzerinde):")
                    print(f"    Normal  : {np.sum(predictions == 1)}")
                    print(f"    Anomali : {anomali_sayisi}")
                    print(f"    Oran    : %{(anomali_sayisi/len(predictions))*100:.2f}")

                print(f"\n    Durum: ✅ Model sağlıklı görünüyor.")
        except Exception as e:
            print(f"[-] Model bozuk veya uyumsuz: {e}")
    else:
        print(f"[-] '{model_path}' bulunamadı.")


if __name__ == "__main__":
    incele()