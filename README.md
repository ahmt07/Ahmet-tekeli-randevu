
# Ahmet Tekeli Erkek Kuaförü — Randevu Sistemi

Flask + SQLite ile geliştirilmiş, **berber bazlı çakışma engelleme** yapan çok kullanıcılı randevu sistemi.
- Aynı anda bir berber için ikinci randevu **engellenir** (veritabanı `UniqueConstraint`).
- Farklı berberler aynı saatlere randevu alabilir.
- Müşteri kayıt/giriş, randevu alma, iptal ve tarih/saat değişimi.
- Admin panel: hizmetler, berberler, çalışma saatleri/slot ayarları, raporlar.

## Hızlı Kurulum (Windows/Mac/Linux)
```bash
cd ahmet_tekeli_berber_randevu
bash run.sh  # ilk kurulum ve çalıştırma
# ilk çalıştırmada yeni bir terminalde aşağıyı bir kez çalıştır:
source .venv/bin/activate
export FLASK_APP=app.app
flask initdb
```

Ardından tarayıcıdan `http://localhost:5000` açın.

### İlk girişler
- **Admin:** `admin@ahmet-tekeli.com` / `admin123`
- **Berber:** `aziz@ahmet-tekeli.com` / `berber123`

> Güvenlik için ilk girişten sonra şifreleri değiştirin ve `.env` dosyasına özel `SECRET_KEY` yazın.

## Özelleştirme
`.env` (örnek `.env.example`):
```
BUSINESS_OPEN_HOUR=9
BUSINESS_CLOSE_HOUR=21
APPT_SLOT_MINUTES=30
CANCEL_LIMIT_HOURS=2
```

## Notlar
- Telegram/WhatsApp bildirim kancaları için `app/static/js/app.js` içine veya `/book` sonrası mail/sms entegrasyonu eklenebilir.
- Prod için bir WSGI sunucusu (gunicorn) ve gerçek bir DB (PostgreSQL) önerilir.
- Veritabanındaki benzersiz kısıt (`uq_barber_start`) çifte rezervasyonu **fiziksel olarak** engeller.
