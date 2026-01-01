# Secrets yönetimi — SF projesi

Bu doküman, proje için Docker Secrets kullanımını ve yerel geliştirici akışını açıklar.

Hedeflenen secret'lar
- `SECRET_KEY` (Flask CSRF/sessions)
- `POSTGRES_PASSWORD` (Postgres DB kullanıcı parolası)
- `REDIS_PASSWORD` (Redis erişim parolası)
- `MAIL_PASSWORD` (SMTP parolası)
- `GOOGLE_CLIENT_SECRET` (Google OAuth)

Yerel geliştirme (basit ve hızlı):

1. `deploy/secrets` dizinini oluşturun:

```bash
mkdir -p deploy/secrets
```

2. Gerekli secret dosyalarını oluşturun (örnek):

```bash
echo -n "$(openssl rand -hex 32)" > deploy/secrets/secret_key.txt
echo -n "your_postgres_password"     > deploy/secrets/postgres_password.txt
echo -n "your_redis_password"        > deploy/secrets/redis_password.txt
echo -n "your_mail_password"         > deploy/secrets/mail_password.txt
echo -n "your_google_client_secret"  > deploy/secrets/google_client_secret.txt
chmod 600 deploy/secrets/*.txt
```

3. `docker compose` ile ayağa kaldırın:

```bash
docker compose up --build -d
```

4. Çalıştığını doğrulayın:

```bash
docker compose logs -f web
docker compose exec web printenv SECRET_KEY
```

Not: proje kökünde `docker-compose.yml` içinde `secrets:` tanımları `file: ./deploy/secrets/<name>.txt` olarak işaretlenmiştir; bu dosyalar Compose tarafından okunur.

Swarm veya prod ortamı (opsiyonel)
- Eğer Docker Swarm kullanıyorsanız `docker secret create` kullanın:

```bash
docker secret create secret_key deploy/secrets/secret_key.txt
docker secret create postgres_password deploy/secrets/postgres_password.txt
```

- Kubernetes veya bir secret manager kullanıyorsanız (Vault, AWS Secrets Manager vb.), ilgili çözüme göre secret'ları sağlayın ve container ortamına mount edin.

`POSTGRES_PASSWORD` ve diğer kritik parolaların rotasyonu
- Secret'ı değiştirip yeni dosya/secret oluşturduktan sonra ilgili servisi yeniden başlatın:

```bash
docker compose up -d --force-recreate --no-deps web
```

Gizlilik ve kaynak kontrolü
- `deploy/secrets/` dizini `.gitignore` içine eklendi — **gerçek secret dosyalarını asla** versiyon kontrolüne göndermeyin.
- Bu repoda `deploy/SECRETS.md` bir rehberdir; gerçek secret yönetimi için bir gizli yönetim çözümü kullanılmasını öneririz.

`.env` ile birlikte kullanım
- Geliştirme sırasında `.env` dosyanızda test değerleri kalabilir; üretimde ise `.env` içindeki gerçek parolaları kaldırın ve yalnızca Docker Secrets kullanın.

Ek notlar
- `docker/docker-entrypoint.sh` image içinde `/run/secrets/*` dosyalarını okuyup environment değişkenlerine çevirir. Bu sayede uygulama mevcut yapı ile secrets'tan yararlanır.
