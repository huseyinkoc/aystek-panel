# API: Posts

## 1. POST /posts
Yeni bir gönderi oluşturur.

### İstek Parametreleri:
- `localizations` (JSON Object): Çok dilli içerik bilgileri (Zorunlu)
- `status` (String): Gönderi durumu (`draft`, `published`) (Zorunlu)
- `category_ids` (Array): Kategori kimlikleri (Opsiyonel)
- `tag_ids` (Array): Etiket kimlikleri (Opsiyonel)
- `publish_date` (String): ISO 8601 formatında yayın tarihi (Opsiyonel)
- `meta_tags` (JSON Object): SEO bilgileri (Opsiyonel)

#### Örnek İstek:
{
    "localizations": {
        "en": {"title": "Test Post", "content": "This is a test content"},
        "tr": {"title": "Deneme Gönderisi", "content": "Bu bir deneme içeriğidir"}
    },
    "status": "draft",
    "category_ids": ["605c72ff0d17369ad2435c9c"],
    "tag_ids": ["605c72ff0d17369ad2435c9c"],
    "publish_date": "2024-12-31T12:00:00Z",
    "meta_tags": {
        "en": {"title": "SEO Title", "description": "SEO Description", "keywords": ["post", "test", "api"]}
    }
}

#### Yanıt:
Başarılı:
{
    "message": "Post created successfully",
    "post_id": "605c72ff0d17369ad2435c9c"
}

Hata:
{
    "error": "Invalid category ID format"
}

---

## 2. GET /posts
Tüm gönderileri listeler.

#### Yanıt:
Başarılı:
[
    {
        "id": "605c72ff0d17369ad2435c9c",
        "localizations": {"en": {"title": "Test Post", "content": "This is a test content"}},
        "status": "draft",
        "category_ids": ["605c72ff0d17369ad2435c9c"],
        "tag_ids": ["605c72ff0d17369ad2435c9c"],
        "publish_date": "2024-12-31T12:00:00Z",
        "created_at": "2024-12-24T10:00:00Z",
        "updated_at": "2024-12-24T11:00:00Z"
    }
]

---

## 3. GET /posts/{id}
Belirtilen ID ile gönderiyi getirir.

### İstek Parametreleri:
- `id` (String): Gönderi kimliği (Zorunlu)

#### Yanıt:
Başarılı:
{
    "id": "605c72ff0d17369ad2435c9c",
    "localizations": {"en": {"title": "Test Post", "content": "This is a test content"}},
    "status": "draft",
    "category_ids": ["605c72ff0d17369ad2435c9c"],
    "tag_ids": ["605c72ff0d17369ad2435c9c"],
    "publish_date": "2024-12-31T12:00:00Z",
    "created_at": "2024-12-24T10:00:00Z",
    "updated_at": "2024-12-24T11:00:00Z"
}

Hata:
{
    "error": "Post not found"
}

---

## 4. PUT /posts/{id}
Belirtilen ID'ye sahip gönderiyi günceller.

### İstek Parametreleri:
- `id` (String): Gönderi kimliği (Zorunlu)
- `localizations`, `status`, `category_ids`, `tag_ids`, `publish_date`, `meta_tags` (Opsiyonel)

#### Örnek İstek:
{
    "status": "published",
    "publish_date": "2024-12-31T12:00:00Z"
}

#### Yanıt:
Başarılı:
{
    "message": "Post updated successfully"
}

Hata:
{
    "error": "Post not found"
}

---

## 5. DELETE /posts/{id}
Belirtilen ID'ye sahip gönderiyi siler.

### İstek Parametreleri:
- `id` (String): Gönderi kimliği (Zorunlu)

#### Yanıt:
Başarılı:
{
    "message": "Post deleted successfully"
}

Hata:
{
    "error": "Post not found"
}
