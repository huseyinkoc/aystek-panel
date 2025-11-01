# KWBsite

## Proje Hakkında
KWBsite, **çok dilli içerik yönetimi** ve **RESTful API** özelliklerini bir araya getiren bir web uygulamasıdır. Proje, kullanıcıların tercihlerine uygun olarak farklı dillerde içerik sunmayı ve esnek bir içerik yönetim sistemi sağlamayı amaçlar.

## Özellikler
- **Çok Dilli Destek**
  - Kullanıcıların tercih ettikleri dilde içerik sunma.
  - Dil ve slug tabanlı içerik yönetimi.
- **Dinamik İçerik Yönetimi**
  - İçerik kategorilere ve etiketlere ayrılabilir.
  - Yayınlama tarihi planlama ve taslak oluşturma özellikleri.
- **API Özellikleri**
  - RESTful API ile içeriklere erişim.
  - Dil bazlı filtreleme ve sorgulama.
- **Kullanıcı Yönetimi**
  - Rol tabanlı erişim kontrolü (RBAC).
  - Şifre sıfırlama ve hesap doğrulama.
- **SEO ve Sosyal Medya Desteği**
  - Meta etiket yönetimi.
  - Open Graph protokolü ile sosyal medya paylaşım desteği.

## Kurulum
### Gereksinimler
- Go 1.19+
- MongoDB 5.0+
- Gin Web Framework

### Adımlar
1. **Proje Deposu Kopyalama:**
   ```bash
   git clone https://github.com/huseyinkoc/kwbsite.git
   cd kwbsite
   ```

2. **Bağımlılıkları Yükleme:**
   ```bash
   go mod tidy
   ```

3. **Ortam Değişkenlerini Ayarlama:**
   `.env` dosyasını oluşturun ve aşağıdaki gibi düzenleyin:
   ```env
   DB_URI=mongodb://localhost:27017
   DB_NAME=kwbsite
   PORT=8080
   ```

4. **Uygulamayı Çalıştırma:**
   ```bash
   go run main.go
   ```

5. **API'yi Test Etme:**
   Varsayılan olarak API, `http://localhost:8080` adresinde çalışır.

## Proje Yapısı
```plaintext
kwbsite/
├── configs/          # Yapılandırma dosyaları
├── controllers/      # API denetleyicileri
├── middlewares/      # Middleware katmanı
├── models/           # Veri modelleri
├── routes/           # Rota tanımları
├── services/         # İş mantığı ve servisler
├── utils/            # Yardımcı araçlar
├── main.go           # Uygulamanın başlangıç dosyası
└── go.mod            # Go modül dosyası
```

## API Belgeleri
### Genel Endpointler
- **GET /admin/posts/:lang/:slug**
  - **Açıklama:** Belirtilen dil ve slug'a göre içeriği getirir.
  - **Parametreler:**
    - `lang`: İçerik dili (ör. `tr`, `en`)
    - `slug`: İçeriğin benzersiz URL parçası

- **POST /admin/posts/create**
  - **Açıklama:** Yeni bir içerik oluşturur.
  - **Gerekli Roller:** `admin`, `editor`

### Örnek İstek
#### GET /admin/posts/tr/teknolojinin-gelecegi
**Yanıt:**
```json
{
  "data": {
    "title": "Teknolojinin Geleceği",
    "content": "Yapay zeka, IoT ve blockchain dünyayı nasıl şekillendiriyor.",
    "slug": "teknolojinin-gelecegi"
  }
}
```

## Katkıda Bulunma
Katkıda bulunmak isterseniz, lütfen bir "Pull Request" gönderin veya "Issue" açarak önerilerinizi paylaşın.

## Lisans
Bu proje MIT Lisansı ile lisanslanmıştır. Daha fazla bilgi için `LICENSE` dosyasını inceleyin.

---

Projenin hedeflerini gerçekleştirmek için sürekli geliştirme devam etmektedir. Katkılarınız ve geri bildirimleriniz bizi daha ileriye taşır!

