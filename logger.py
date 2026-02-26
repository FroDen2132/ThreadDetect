# logger.py - GELİŞMİŞ LOGLAMA SİSTEMİ
# JSON Format + Severity Seviyeleri + Log Rotasyonu + Ayrı Log Dosyaları
import logging
import logging.handlers
import json
import os
from datetime import datetime


class GuvenlikLogger:
    """
    Yapılandırılmış JSON loglama sistemi.
    - Ayrı log dosyaları: threats.json, network.json, system.json
    - Log rotasyonu (boyut tabanlı)
    - Severity seviyeleri: INFO, WARNING, CRITICAL, ALERT
    - AI rapor entegrasyonu
    """

    def __init__(self, config=None):
        from config import Config
        self.config = config or Config()

        # Log dizinini oluştur
        self.log_dir = self.config.log_dir
        os.makedirs(self.log_dir, exist_ok=True)

        # Logger'ları kur
        self.threat_logger = self._logger_olustur("threats", "threats.json")
        self.network_logger = self._logger_olustur("network", "network.json")
        self.system_logger = self._logger_olustur("system", "system.json")

        # Eski format uyumu için ana logger
        self.legacy_logger = self._logger_olustur("legacy", "guvenlik_loglari.txt", json_format=False)

    def _logger_olustur(self, ad, dosya_adi, json_format=True):
        """Rotasyonlu bir logger oluşturur."""
        logger = logging.getLogger(f"ThreadDetector_{ad}")
        logger.setLevel(logging.DEBUG)
        if logger.hasHandlers():
            logger.handlers.clear()

        dosya_yolu = os.path.join(self.log_dir, dosya_adi)
        handler = logging.handlers.RotatingFileHandler(
            dosya_yolu,
            maxBytes=self.config.log_max_bytes,
            backupCount=self.config.log_backup_count,
            encoding='utf-8'
        )

        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def _json_log(self, logger, seviye, kategori, veri):
        """JSON formatında log kaydı oluşturur."""
        kayit = {
            "timestamp": datetime.now().isoformat(),
            "severity": seviye,
            "category": kategori,
            **veri
        }
        logger.info(json.dumps(kayit, ensure_ascii=False, default=str))

    # =====================================================
    # TEHDİT LOGLAMA
    # =====================================================
    def log_threat(self, features, score, process_list, network_map=None, ai_rapor=None):
        """Tehditleri detaylı JSON formatında loglar."""
        # Feature vektörünü çıkar
        try:
            if hasattr(features, 'shape') and len(features.shape) == 2:
                veri = features[0]
            elif isinstance(features, list) and len(features) == 1:
                veri = features[0]
            else:
                veri = features
        except Exception:
            veri = [0, 0, 0, 0, 0]

        cpu = float(veri[0]) if len(veri) > 0 else 0
        ram = float(veri[1]) if len(veri) > 1 else 0
        disk = float(veri[2]) if len(veri) > 2 else 0
        net = float(veri[3]) if len(veri) > 3 else 0
        pids = float(veri[4]) if len(veri) > 4 else 0

        # Tehdit Kategorisi Belirleme Lojikleri
        def categorize_threat_tags(tags: list[str]) -> list[str]:
            categories = set()
            for tag in tags:
                if "CMD_EXEC" in tag or "IEX_EXEC" in tag or "DOWNLOAD_EXEC" in tag:
                    categories.add("Execution")
                if "LOLBIN:" in tag or "HIDDEN_PS" in tag or "ENCODED_PS" in tag:
                    categories.add("Defense Evasion")
                if "AV_KILL_ATTEMPT" in tag:
                    categories.add("Defense Evasion (AV Kill)")
                if "NETCAT_LISTENER" in tag:
                    categories.add("Command and Control")
                if "THREAD_SPIKE" in tag:
                    categories.add("Process Injection / Evasion")
                if "RANSOMWARE" in tag.upper():
                    categories.add("Impact (Ransomware)")
            # Eğer kategorize edilemeyen tag'ler varsa ama YARA vb varsa
            if not categories and any("YARA" in tag for tag in tags):
                categories.add("Malware Inference")
            return list(categories)

        # İşlem listesini hazırla
        islem_listesi = []
        genel_kategoriler = set()
        if process_list:
            for p in process_list:
                pid = p['pid']
                net_info = "Bağlantı Yok"
                if network_map and pid in network_map:
                    net_info = network_map[pid]
                
                risk_detay_listesi = p.get('risk_detail', [])
                process_kategoriler = categorize_threat_tags(risk_detay_listesi)
                genel_kategoriler.update(process_kategoriler)

                islem_listesi.append({
                    "pid": pid,
                    "name": p.get('name', '?'),
                    "cpu_percent": p.get('cpu_percent', 0),
                    "memory_percent": p.get('memory_percent', 0),
                    "disk_speed": p.get('disk_speed', 0),
                    "conn_count": p.get('conn_count', 0),
                    "risk_score": p.get('risk_score', 0),
                    "yara_matches": p.get('yara_matches', []),
                    "cmd_line": p.get('cmd_line', ''),
                    "risk_detail": risk_detay_listesi,
                    "threat_categories": process_kategoriler,
                    "parent_info": p.get('parent_info'),
                    "network": net_info,
                })

        # Severity belirle
        if ai_rapor:
            seviye = ai_rapor.get('seviye', 'WARNING')
        elif any(p.get('yara_matches') for p in (process_list or [])):
            seviye = "CRITICAL"
        elif score < -0.3:
            seviye = "CRITICAL"
        elif score < -0.15:
            seviye = "WARNING"
        else:
            seviye = "INFO"

        veri_dict = {
            "ai_score": float(score),
            "overall_threat_categories": list(genel_kategoriler),
            "system_metrics": {
                "cpu_percent": cpu,
                "ram_percent": ram,
                "disk_io_mb": disk,
                "net_io_mb": net,
                "active_processes": pids,
            },
            "suspicious_processes": islem_listesi,
        }

        # AI raporu varsa ekle
        if ai_rapor:
            veri_dict["ai_analysis"] = {
                "threat_level": ai_rapor.get('seviye', '?'),
                "anomaly_reasons": ai_rapor.get('anomali_nedenleri', []),
                "recommended_action": ai_rapor.get('onerilen_aksiyon', ''),
            }

        self._json_log(self.threat_logger, seviye, "THREAT_DETECTION", veri_dict)

        # Eski format uyumu
        self._legacy_threat_log(cpu, ram, disk, score, process_list, network_map, ai_rapor)

    def _legacy_threat_log(self, cpu, ram, disk, score, process_list, network_map, ai_rapor):
        """Eski format uyumlu (okunabilir) log."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        msg = (
            f"{'='*60}\n"
            f"[!!!] GÜVENLİK UYARISI — TEHDİT TESPİTİ\n"
            f"{'='*60}\n"
            f"Tarih/Saat  : {timestamp}\n"
            f"AI Skoru    : {score:.4f} (Negatif = Riskli)\n"
            f"Sistem      : CPU %{cpu:.1f} | RAM %{ram:.1f} | Disk {disk:.1f} MB/s\n"
        )

        if ai_rapor:
            seviye = ai_rapor.get('seviye', '?')
            msg += f"Tehdit Sev. : {seviye}\n"

        msg += f"{'-'*60}\nŞÜPHELİ İŞLEM ANALİZİ:\n"

        if process_list:
            for i, p in enumerate(process_list):
                pid = p['pid']
                net_info = "Veri Yok / Bağlantı Yok"
                if network_map and pid in network_map:
                    net_info = ", ".join(network_map[pid]) if isinstance(network_map[pid], list) else str(network_map[pid])

                msg += (
                    f" {i+1}. {p['name']} (PID: {pid})\n"
                    f"    -> Kaynak: CPU %{p.get('cpu_percent', 0)} | RAM %{p.get('memory_percent', 0):.1f}\n"
                    f"    -> Disk: {p.get('disk_speed', 0):.2f} MB/s | Bağlantı: {p.get('conn_count', 0)}\n"
                    f"    -> Risk: {p.get('risk_score', 0):.1f} | Etiketler: {', '.join(p.get('risk_detail', []))}\n"
                    f"    -> [KATEGORİ]: {', '.join(p.get('threat_categories', [])) if p.get('threat_categories') else 'Bilinmiyor'}\n"
                    f"    -> [AĞ]: {net_info}\n"
                )

                if p.get('yara_matches'):
                    msg += f"    -> [YARA]: {', '.join(p['yara_matches'])}\n"
                if p.get('cmd_line'):
                    cmd = p['cmd_line']
                    if len(cmd) > 120:
                        cmd = cmd[:120] + "..."
                    msg += f"    -> [CMD]: {cmd}\n"
                if p.get('parent_info'):
                    par = p['parent_info']
                    msg += f"    -> [PARENT]: {par.get('name', '?')} (PID: {par.get('pid', '?')})\n"

        if ai_rapor and ai_rapor.get('anomali_nedenleri'):
            msg += f"\nAI ANALİZİ:\n"
            for neden in ai_rapor['anomali_nedenleri']:
                msg += f"  • {neden}\n"
            msg += f"  ÖNERİ: {ai_rapor.get('onerilen_aksiyon', '-')}\n"

        msg += f"{'='*60}\n"
        self.legacy_logger.info(msg)

    # =====================================================
    # AĞ LOGLAMA
    # =====================================================
    def log_network(self, mesaj, seviye="WARNING", detay=None):
        """Ağ olaylarını loglar."""
        veri = {"message": mesaj}
        if detay:
            veri["details"] = detay
        self._json_log(self.network_logger, seviye, "NETWORK_EVENT", veri)

    # =====================================================
    # SİSTEM LOGLAMA
    # =====================================================
    def log_system(self, mesaj, seviye="INFO", detay=None):
        """Sistem olaylarını loglar."""
        veri = {"message": mesaj}
        if detay:
            veri["details"] = detay
        self._json_log(self.system_logger, seviye, "SYSTEM_EVENT", veri)

    # =====================================================
    # GENEL LOG (Uyumluluk)
    # =====================================================
    def log_normal(self, message):
        """Eski format uyumlu basit log."""
        self.legacy_logger.info(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}")

    # =====================================================
    # MODÜL ALARMLARI LOGLAMA
    # =====================================================
    # =====================================================
    # API İZLEME LOGLAMA (FRIDA)
    # =====================================================
    def log_api_call(self, pid: int, process_name: str, api_name: str, args: dict, return_val: str = ""):
        """Süreçlerin Windows API çağrı detaylarını loglar."""
        veri = {
            "pid": pid,
            "process_name": process_name,
            "api": api_name,
            "arguments": args,
            "return_value": return_val
        }
        self._json_log(self.threat_logger, "WARNING", "API_MONITOR", veri)
        # Detayları okunabilir log dosyasına da kısa biçimde yaz
        args_str = ", ".join(f"{k}='{v}'" for k, v in args.items())
        msg = f"[*] API_CALL [{process_name}:{pid}] -> {api_name}({args_str})"
        if return_val:
            msg += f" => {return_val}"
        self.legacy_logger.info(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

    # =====================================================
    # MODÜL ALARMLARI LOGLAMA
    # =====================================================
    def log_monitor_alarm(self, kaynak, mesaj, seviye="WARNING"):
        """Registry, DLL, File monitor alarmlarını loglar."""
        veri = {
            "source": kaynak,
            "message": mesaj,
        }
        self._json_log(self.system_logger, seviye, f"MONITOR_ALERT_{kaynak.upper()}", veri)
        self.legacy_logger.info(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [{kaynak.upper()}] {mesaj}")

    # =====================================================
    # OTURUM ÖZET RAPORU
    # =====================================================
    def generate_summary(self, oturum_suresi: float = 0) -> dict:
        """
        JSON log dosyalarını okuyarak oturum özet raporu üretir.
        Kapatılırken main.py tarafından çağrılır.
        """
        ozet = {
            "oturum_suresi_sn": round(oturum_suresi, 1),
            "toplam_tehdit": 0,
            "ag_alarm": 0,
            "registry_alarm": 0,
            "dll_alarm": 0,
            "dosya_alarm": 0,
            "api_call": 0,
            "en_yuksek_seviye": "INFO",
        }

        seviye_oncelik = {"INFO": 0, "WARNING": 1, "CRITICAL": 2, "KRİTİK": 3}

        # Threat loglarını say
        threat_path = os.path.join(self.log_dir, "threats.json")
        if os.path.exists(threat_path):
            try:
                with open(threat_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            cat = entry.get("category", "")
                            sev = entry.get("severity", "INFO")

                            if cat == "THREAT_DETECTION":
                                ozet["toplam_tehdit"] += 1
                            elif cat == "API_MONITOR":
                                ozet["api_call"] += 1

                            if seviye_oncelik.get(sev, 0) > seviye_oncelik.get(ozet["en_yuksek_seviye"], 0):
                                ozet["en_yuksek_seviye"] = sev
                        except json.JSONDecodeError:
                            continue
            except Exception:
                pass

        # Network loglarını say
        network_path = os.path.join(self.log_dir, "network.json")
        if os.path.exists(network_path):
            try:
                with open(network_path, 'r', encoding='utf-8') as f:
                    ozet["ag_alarm"] = sum(1 for line in f if line.strip())
            except Exception:
                pass

        # System loglarından modül alarmlarını say
        system_path = os.path.join(self.log_dir, "system.json")
        if os.path.exists(system_path):
            try:
                with open(system_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            cat = entry.get("category", "")
                            if "REGISTRY" in cat:
                                ozet["registry_alarm"] += 1
                            elif "DLL" in cat:
                                ozet["dll_alarm"] += 1
                            elif "FILESYSTEM" in cat:
                                ozet["dosya_alarm"] += 1
                        except json.JSONDecodeError:
                            continue
            except Exception:
                pass

        # Özet raporu da logla
        self._json_log(self.system_logger, "INFO", "SESSION_SUMMARY", ozet)

        return ozet