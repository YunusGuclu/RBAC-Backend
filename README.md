# 🔐 RBAC Backend API (Role-Based Access Control)

Bu proje, **kullanıcıların sistem içerisindeki yetkilerinin rol, modül ve fonksiyon bazlı olarak yönetilmesini sağlayan**,  
**modern, ölçeklenebilir ve kurumsal düzeyde bir RBAC (Role-Based Access Control) altyapısının geliştirilmesini** kapsamaktadır.

Proje;  
kullanıcı yönetimi, rol yönetimi, yetkilendirme, JWT tabanlı kimlik doğrulama ve merkezi admin kontrolünü  
**tek bir backend API altında toplamayı hedeflemektedir.**

---

## 🎯 Projenin Amacı

Bu projenin temel amacı:

- Kurumsal projelerde ihtiyaç duyulan **güvenli ve esnek yetkilendirme altyapısını oluşturmak**
- Kullanıcıların sistemde yalnızca **yetkili oldukları alanlara erişmesini sağlamak**
- **Rol – Modül – Fonksiyon bazlı fine-grained (ince taneli) erişim kontrolü sunmak**
- Geliştirilen yapıyı **tekrar kullanılabilir, modüler ve taşınabilir bir Accounts / RBAC API** haline getirmek

Bu yapı farklı projelere doğrudan entegre edilebilir.

---
## 🚀 Projenin Kapsamı

Bu backend API aşağıdaki ihtiyaçları tek bir sistem altında toplamayı hedefler:

- Kullanıcı yönetimi (kayıt, giriş, kullanıcı bilgileri)
- Rol yönetimi
- Modül & fonksiyon bazlı yetkilendirme
- JWT tabanlı kimlik doğrulama
- Admin panel operasyonları için güçlü API altyapısı
- Merkezi log izleme (Loki + Grafana)
- Swagger / ReDoc API dokümantasyonu

---

## 🧠 RBAC Yapısının Temel Mantığı

Sistem 4 ana kavram üzerine kuruludur:

- **User (Kullanıcı)**
- **Role (Rol)**
- **Module (Modül)**
- **Function (Fonksiyon)**

Yetkilendirme zinciri:

User → Role → Module → Function


Bu yapı sayesinde:

- Bir rolün hangi modülde hangi işlemleri yapabileceği net şekilde tanımlanır
- Kullanıcıya rol atanmasıyla tüm yetkiler otomatik kazanılır
- Sistem yüksek seviyede güvenlik ve kontrol sağlar

---

## 🧩 Sistem Mimarisi (Özet)

- Backend tamamen **REST API** olarak tasarlanmıştır
- Frontend ile **JWT token tabanlı iletişim** kurulur
- Authentication & Authorization süreçleri uçtan uca çalışır
- Sistem bağımsız olarak **Accounts / RBAC API** şeklinde farklı projelere entegre edilebilir

---

## 🛠️ Kullanılan Teknolojiler

### Backend

- **Python 3.11**
- **Django 5.x**
- **Django REST Framework**
- **PostgreSQL**

### Authentication & Security

- `djangorestframework-simplejwt`
  - Access Token
  - Refresh Token
  - Token Blacklist

### API Dokümantasyonu

- **drf-spectacular**
  - OpenAPI
  - Swagger UI
  - ReDoc


### Loglama & İzleme

- **Loki**
- **Grafana**
- Docker tabanlı log izleme mimarisi

### Diğer

- CORS / CSRF: `django-cors-headers`
- Ortam değişkenleri: `.env`
- Paket yönetimi: **Poetry**

---

## 📘 API Dokümantasyonu

Projede **DRF Spectacular** kullanılarak:

- Swagger UI
- ReDoc
- OpenAPI 3 standardı

tam uyumlu olacak şekilde API dokümantasyonu oluşturulmuştur.

#### Swagger
<img width="782" height="451" alt="image" src="https://github.com/user-attachments/assets/368485f1-aadc-419d-9923-27dea2b4efb8" />

#### Redoc
<img width="783" height="451" alt="image" src="https://github.com/user-attachments/assets/c9d95cf1-44d1-4509-9167-11ed7cf49942" />


### Bu sayede:

- API’ler net ve anlaşılır hale gelir
- Frontend–Backend uyumu sağlanır
- Kurumsal ve profesyonel API sunumu elde edilir
- Yeni geliştiriciler projeye hızlı adapte olabilir

---

## 📊 Loki & Grafana Log İzleme Sistemi

### 🔹 Loki Nedir?

Loki, Grafana ekosisteminin bir parçası olan modern bir log toplama sistemidir.

- Logların yalnızca **label (metadata)** bilgisi indekslenir
- Yüksek performans sağlar
- Düşük disk kullanımı sunar
- Yatay ölçeklenebilir yapıdadır

RBAC sisteminde tüm Django logları merkezi olarak Loki’ye gönderilmektedir.

### 🔹 Grafana Nedir?

Grafana, Loki’den gelen logları:

- Dashboard üzerinde görüntülemek
- Log analizi yapmak
- Logları tablo veya liste halinde sunmak
- API hatalarını anlık izlemek
- Sistem davranışlarını analiz etmek

amacıyla kullanılmaktadır.

<img width="950" height="493" alt="image" src="https://github.com/user-attachments/assets/15e3c23e-7207-4648-8d05-c8a4662fa1ed" />


### Sağlanan Avantajlar

- API hataları anlık izlenir
- Error / Warn / Info vb. log dağılımları takip edilir
- Loglar tablo veya liste halinde görüntülenir
- Loglar zamansal olarak izlenir.
- Performans problemleri trend analizleriyle fark edilir
- Sistem davranışları net şekilde analiz edilir

> ⚙️ Loki ve Grafana Docker üzerinde çalışmaktadır.

---

## 🔗 Frontend Repository

Frontend uygulaması bu backend API ile entegre çalışmaktadır.

👉 **Frontend Repo:**  
🔗 https://github.com/YunusGuclu/RBAC-Frontend

---

## ✅ Proje Özeti

- ✔ JWT tabanlı güvenli kimlik doğrulama
- ✔ Fine-grained RBAC yetkilendirme
- ✔ Swagger & ReDoc API dokümantasyonu
- ✔ Merkezi log izleme (Loki + Grafana)
- ✔ Kurumsal mimariye uygun yapı
- ✔ Tekrar kullanılabilir Accounts / RBAC API

---
## ✅ Projenin Çalıştırılması

poetry run python manage.py runserver
veya
python manage.py runserver

📌 Bu proje, **kurumsal sistemlerde kullanıcı ve yetkilendirme yönetimi için profesyonel bir temel altyapı** sunmaktadır.
