# sniffer.py - GELİŞMİŞ AĞ ANALİZ SİSTEMİ
# DNS Analizi + C2 Beacon Tespiti + Genişletilmiş İçerik İmzaları + Port Anomali
from scapy.all import sniff, IP, TCP, UDP, Raw, DNS, DNSQR
import threading
import time
import math
from collections import defaultdict


class AgKoklayici:
    """
    Gelişmiş ağ paket analizi modülü.
    - Derin paket içerik taraması (DPI)
    - DNS sorgu analizi (DGA tespiti, şüpheli domain)
    - C2 Beacon tespiti (periyodik bağlantılar)
    - Port anomali tespiti
    """

    def __init__(self, config=None):
        from config import Config
        self.config = config or Config()

        self.tehditler = []
        self.calisiyor = False
        self.thread = None
        self.lock = threading.Lock()

        # C2 Beacon Tespiti için bağlantı zamanlaması
        self.baglanti_zamanlari = defaultdict(list)  # ip -> [timestamp listesi]

        # DNS sorgu geçmişi
        self.dns_sorgu_sayilari = defaultdict(int)   # domain -> sorgu sayısı

        # Port istatistikleri
        self.port_sayilari = defaultdict(int)         # port -> kullanım sayısı

    # =====================================================
    # ENTROPY HESAPLAMA (DGA Tespiti için)
    # =====================================================
    @staticmethod
    def entropy_hesapla(metin):
        """Shannon entropy hesaplar. Yüksek entropy = rastgele oluşturulmuş olabilir."""
        if not metin:
            return 0
        freqs = defaultdict(int)
        for c in metin:
            freqs[c] += 1
        length = len(metin)
        entropy = -sum((count / length) * math.log2(count / length) for count in freqs.values())
        return entropy

    # =====================================================
    # DNS ANALİZİ
    # =====================================================
    def dns_analiz(self, paket):
        """DNS sorgularını analiz eder, DGA ve şüpheli domainleri tespit eder."""
        try:
            if paket.haslayer(DNS) and paket.haslayer(DNSQR):
                sorgu = paket[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')

                # TLD'yi ayır
                parcalar = sorgu.split('.')
                if len(parcalar) < 2:
                    return

                # İsim kısmı (TLD hariç)
                domain_adi = parcalar[0] if len(parcalar) == 2 else '.'.join(parcalar[:-2])

                # DGA Tespiti: Yüksek entropy + uzun isim
                ent = self.entropy_hesapla(domain_adi)
                if ent > 3.5 and len(domain_adi) > 12:
                    kaynak = paket[IP].src if paket.haslayer(IP) else "?"
                    with self.lock:
                        self.tehditler.append(
                            f"DGA ŞÜPHESİ (DNS): '{sorgu}' entropy={ent:.2f} | Kaynak: {kaynak}"
                        )

                # Sorgu sayısını takip et
                self.dns_sorgu_sayilari[sorgu] += 1

                # Çok fazla alt domain sorgusu (DNS Tunneling belirtisi)
                if len(parcalar) > 4:
                    with self.lock:
                        self.tehditler.append(
                            f"DNS TÜNELİ ŞÜPHESİ: '{sorgu}' — çok sayıda alt domain seviyesi"
                        )
        except Exception:
            pass

    # =====================================================
    # C2 BEACON TESPİTİ
    # =====================================================
    def c2_beacon_kontrol(self, paket):
        """
        Belirli IP'lere düzenli aralıklarla giden bağlantıları tespit eder.
        C2 sunucularına beacon gönderimi genellikle sabit aralıklarla olur.
        """
        try:
            if paket.haslayer(IP) and paket.haslayer(TCP):
                hedef_ip = paket[IP].dst
                simdi = time.time()

                # Sadece SYN paketleri (yeni bağlantılar)
                if paket[TCP].flags & 0x02:  # SYN flag
                    self.baglanti_zamanlari[hedef_ip].append(simdi)

                    # Son N dakikayı tut
                    pencere = self.config.c2_beacon_penceresi
                    self.baglanti_zamanlari[hedef_ip] = [
                        t for t in self.baglanti_zamanlari[hedef_ip]
                        if simdi - t < pencere
                    ]

                    zamanlar = self.baglanti_zamanlari[hedef_ip]
                    if len(zamanlar) >= self.config.c2_min_tekrar:
                        # Aralıkları hesapla
                        araliklar = [zamanlar[i+1] - zamanlar[i] for i in range(len(zamanlar)-1)]
                        if araliklar:
                            ort_aralik = sum(araliklar) / len(araliklar)
                            # Standart sapma düşükse → periyodik bağlantı
                            if len(araliklar) >= 3:
                                variance = sum((a - ort_aralik)**2 for a in araliklar) / len(araliklar)
                                std_dev = variance ** 0.5
                                if std_dev < self.config.c2_tolerans and ort_aralik > 1:
                                    with self.lock:
                                        self.tehditler.append(
                                            f"C2 BEACON TESPİTİ: {hedef_ip} — "
                                            f"her ~{ort_aralik:.1f}sn ({len(zamanlar)} bağlantı, sapma: {std_dev:.2f})"
                                        )
                                    # Tekrar alarm vermemek için temizle
                                    self.baglanti_zamanlari[hedef_ip].clear()
        except Exception:
            pass

    # =====================================================
    # PORT ANOMALİ TESPİTİ
    # =====================================================
    def port_anomali_kontrol(self, paket):
        """Yaygın olmayan portlarda iletişimi tespit eder."""
        try:
            if paket.haslayer(TCP) and paket.haslayer(IP):
                dst_port = paket[TCP].dport
                self.port_sayilari[dst_port] += 1

                # Bilinen portlar dışındaki trafik
                bilinen_portlar = {
                    20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587,
                    993, 995, 3306, 3389, 5432, 5900, 8080, 8443
                }

                # Yüksek portlarda (>10000) ilk kez trafik gözlemlenirse
                if dst_port > 10000 and dst_port not in bilinen_portlar:
                    if self.port_sayilari[dst_port] == 1:
                        hedef_ip = paket[IP].dst
                        kaynak_ip = paket[IP].src
                        with self.lock:
                            self.tehditler.append(
                                f"PORT ANOMALİ: {kaynak_ip} -> {hedef_ip}:{dst_port} — alışılmadık port"
                            )
        except Exception:
            pass

    # =====================================================
    # DERİN PAKET ANALİZİ
    # =====================================================
    def paket_analiz(self, paket):
        """Her geçen paketin kapsamlı analizini yapar."""
        try:
            # DNS Analizi
            if paket.haslayer(DNS):
                self.dns_analiz(paket)

            # C2 Beacon Kontrolü
            self.c2_beacon_kontrol(paket)

            # Port Anomali Kontrolü
            self.port_anomali_kontrol(paket)

            # İçerik Analizi (DPI)
            if paket.haslayer(Raw):
                veri = paket[Raw].load

                for kelime in self.config.yasakli_kelimeler:
                    if kelime.lower() in veri.lower():
                        kaynak_ip = paket[IP].src if paket.haslayer(IP) else "Bilinmiyor"
                        hedef_ip = paket[IP].dst if paket.haslayer(IP) else "Bilinmiyor"
                        port = ""
                        if paket.haslayer(TCP):
                            port = f":{paket[TCP].dport}"
                        elif paket.haslayer(UDP):
                            port = f":{paket[UDP].dport}"

                        log_mesaji = (
                            f"İÇERİK TESPİTİ: '{kelime.decode('utf-8', errors='ignore')}' "
                            f"| {kaynak_ip} -> {hedef_ip}{port}"
                        )
                        with self.lock:
                            self.tehditler.append(log_mesaji)
                        return
        except Exception:
            pass

    def baslat(self):
        """Arka planda dinlemeyi başlatır."""
        self.calisiyor = True
        try:
            sniff(prn=self.paket_analiz, store=0,
                  stop_filter=lambda x: not self.calisiyor)
        except Exception as e:
            with self.lock:
                self.tehditler.append(f"Sniffer Hatası: {e}")

    def thread_baslat(self):
        """Main.py'yi dondurmamak için ayrı kanalda çalıştır."""
        self.thread = threading.Thread(target=self.baslat)
        self.thread.daemon = True
        self.thread.start()

    def alarmlari_getir(self):
        """Biriken alarmları ana programa verir ve temizler."""
        with self.lock:
            if self.tehditler:
                yedek = self.tehditler[:]
                self.tehditler.clear()
                return yedek
        return []

    def durdur(self):
        self.calisiyor = False

    def istatistik_getir(self):
        """Sniffer istatistiklerini döndürür."""
        return {
            'izlenen_ip_sayisi': len(self.baglanti_zamanlari),
            'dns_sorgu_sayisi': sum(self.dns_sorgu_sayilari.values()),
            'benzersiz_domain': len(self.dns_sorgu_sayilari),
            'aktif_port_sayisi': len(self.port_sayilari),
        }