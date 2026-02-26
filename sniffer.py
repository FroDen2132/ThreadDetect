# sniffer.py - GELİŞMİŞ AĞ ANALİZ SİSTEMİ
# DNS Analizi + C2 Beacon Tespiti + Genişletilmiş İçerik İmzaları + Port Anomali
from scapy.all import sniff, IP, TCP, UDP, Raw, DNS, DNSQR
import threading
import time
import math
import psutil
from collections import defaultdict


class AgKoklayici:
    """
    Gelişmiş ağ paket analizi modülü.
    - Derin paket içerik taraması (DPI)
    - DNS sorgu analizi (DGA tespiti, şüpheli domain)
    - C2 Beacon tespiti (periyodik bağlantılar)
    - Port anomali tespiti (browser false-positive filtrelemeli)
    """

    # Bilinen güvenli portlar — standart servisler
    BILINEN_PORTLAR = {
        20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 143,
        443, 465, 587, 993, 995,
        # Veritabanı
        1433, 1521, 3306, 5432, 6379, 27017,
        # Uzak masaüstü / VNC
        3389, 5900, 5938,
        # Web sunucu alternatifleri
        8000, 8080, 8443, 8888,
        # Cloudflare / CDN yüksek portları
        2053, 2083, 2087, 2096,
    }

    # Tarayıcı (browser) süreç isimleri — bu süreçlerin yüksek port
    # trafiği normal kabul edilir (QUIC, HTTP/3, CDN alt-svc vb.)
    BROWSER_ISIMLERI = {
        "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe",
        "brave.exe", "vivaldi.exe", "iexplore.exe",
        "chromium.exe", "safari.exe", "arc.exe",
        # İlgili yardımcı süreçler
        "chrome", "msedge", "firefox", "opera", "brave",
    }

    # Windows Ephemeral port aralığı (49152–65535)
    EPHEMERAL_ALT = 49152
    EPHEMERAL_UST = 65535

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

        # Port anomali rate-limiting: son alarm zamanı
        self._port_alarm_zamanlari: dict[tuple[str, int], float] = {}
        self._PORT_ALARM_COOLDOWN = 60   # aynı ip:port çifti için 60sn cooldown

        # UDP/QUIC izleme
        self.udp_port_sayilari: dict[int, int] = {}  # port -> kullanım sayısı
        self._udp_alarm_zamanlari: dict[tuple[str, int], float] = {}

        # Browser PID cache (periyodik güncellenir)
        self._browser_pidler: set[int] = set()
        self._browser_cache_zamani: float = 0.0
        self._BROWSER_CACHE_TTL = 15  # 15 saniyede bir güncelle

    # =====================================================
    # BROWSER PID CACHE
    # =====================================================
    def _browser_pidleri_guncelle(self):
        """Çalışan browser süreçlerinin PID'lerini cache'e alır."""
        simdi = time.time()
        if simdi - self._browser_cache_zamani < self._BROWSER_CACHE_TTL:
            return  # Cache hâlâ geçerli

        yeni_pidler = set()
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    isim = proc.info['name']
                    if isim and isim.lower() in self.BROWSER_ISIMLERI:
                        yeni_pidler.add(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

        self._browser_pidler = yeni_pidler
        self._browser_cache_zamani = simdi

    def _baglanti_browserdan_mi(self, paket):
        """Paketin browser sürecinden gelip gelmediğini kontrol eder."""
        self._browser_pidleri_guncelle()

        if not self._browser_pidler:
            return False

        try:
            if paket.haslayer(IP) and paket.haslayer(TCP):
                src_ip = paket[IP].src
                src_port = paket[TCP].sport

                for conn in psutil.net_connections(kind='inet'):
                    if (conn.pid in self._browser_pidler and
                        conn.laddr and
                        conn.laddr.port == src_port):
                        return True
        except Exception:
            pass
        return False

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
    # PORT ANOMALİ TESPİTİ (Browser-Aware)
    # =====================================================
    def port_anomali_kontrol(self, paket):
        """
        Yaygın olmayan portlardaki iletişimi tespit eder.
        
        False Positive Önleme Katmanları:
        1. Bilinen güvenli portlara giden trafik filtrelenir
        2. Sadece SYN (yeni bağlantı) paketleri incelenir
        3. Ephemeral port aralığı (49152-65535) sadece hedef olarak filtrelenir
        4. Browser süreçlerinden gelen trafik muaf tutulur
        5. Aynı ip:port çifti için cooldown uygulanır
        """
        try:
            if not (paket.haslayer(TCP) and paket.haslayer(IP)):
                return

            dst_port = paket[TCP].dport
            src_port = paket[TCP].sport
            hedef_ip = paket[IP].dst
            kaynak_ip = paket[IP].src

            self.port_sayilari[dst_port] += 1

            # KATMAN 1: Bilinen güvenli portlara giden trafik → normal
            if dst_port in self.BILINEN_PORTLAR:
                return

            # KATMAN 2: Sadece SYN paketlerini değerlendir
            # ACK, SYN-ACK, FIN gibi paketler zaten mevcut bağlantıların parçası
            if not (paket[TCP].flags & 0x02):  # SYN flag yoksa atla
                return

            # KATMAN 3: Eğer hedef port Windows ephemeral aralığındaysa
            # bu genellikle response trafiğidir, atla
            if self.EPHEMERAL_ALT <= dst_port <= self.EPHEMERAL_UST:
                return

            # KATMAN 4: Düşük portlar zaten bilinen portlar setinde;
            # 1024-10000 arasındaki portlar çoğunlukla bilinen servislerdir
            if dst_port <= 10000:
                return

            # KATMAN 5: Browser sürecinden geliyorsa → false positive, atla
            if self._baglanti_browserdan_mi(paket):
                return

            # KATMAN 6: Rate limiting — aynı hedef ip:port için cooldown
            simdi = time.time()
            anahtar = (hedef_ip, dst_port)
            son_alarm = self._port_alarm_zamanlari.get(anahtar, 0)
            if simdi - son_alarm < self._PORT_ALARM_COOLDOWN:
                return  # Cooldown süresi içinde, tekrar alarm verme

            # İlk kez görülen port & tüm filtreleri geçti → ALARM
            if self.port_sayilari[dst_port] <= 3:  # Nadir kullanılan port
                self._port_alarm_zamanlari[anahtar] = simdi
                with self.lock:
                    self.tehditler.append(
                        f"PORT ANOMALİ: {kaynak_ip}:{src_port} -> {hedef_ip}:{dst_port} "
                        f"— Alışılmadık port (SYN, non-browser)"
                    )

        except Exception:
            pass

    # =====================================================
    # UDP / QUIC ANOMALİ TESPİTİ
    # =====================================================
    def udp_anomali_kontrol(self, paket):
        """
        UDP trafiğinde anomali tespiti.
        QUIC (UDP 443) normaldir, ancak bilinmeyen yüksek portlara
        UDP trafiği C2 tüneli veya veri sızdırma (exfiltration) olabilir.
        """
        try:
            if not (paket.haslayer(UDP) and paket.haslayer(IP)):
                return

            dst_port = paket[UDP].dport
            hedef_ip = paket[IP].dst
            kaynak_ip = paket[IP].src

            # DNS (53) ve QUIC (443) normal
            if dst_port in (53, 443, 80, 123, 67, 68):
                return

            # Bilinen güvenli portlar
            if dst_port in self.BILINEN_PORTLAR:
                return

            # Ephemeral port aralığı atla
            if self.EPHEMERAL_ALT <= dst_port <= self.EPHEMERAL_UST:
                return

            # Düşük portlar atla
            if dst_port <= 10000:
                return

            # Browser trafiği atla
            if self._baglanti_browserdan_mi(paket):
                return

            # Rate limiting
            simdi = time.time()
            anahtar = (hedef_ip, dst_port)
            son_alarm = self._udp_alarm_zamanlari.get(anahtar, 0.0)
            if simdi - son_alarm < self._PORT_ALARM_COOLDOWN:
                return

            # UDP port sayacı
            self.udp_port_sayilari[dst_port] = self.udp_port_sayilari.get(dst_port, 0) + 1

            if self.udp_port_sayilari[dst_port] <= 3:
                self._udp_alarm_zamanlari[anahtar] = simdi
                with self.lock:
                    self.tehditler.append(
                        f"UDP ANOMALİ: {kaynak_ip} -> {hedef_ip}:{dst_port} "
                        f"— Alışılmadık UDP port (QUIC/C2 tüneli şüphesi)"
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

            # Port Anomali Kontrolü (TCP)
            self.port_anomali_kontrol(paket)

            # UDP/QUIC Anomali Kontrolü
            self.udp_anomali_kontrol(paket)

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
            'browser_pid_sayisi': len(self._browser_pidler),
        }