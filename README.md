# Rust Certbot

Современная реализация Certbot на языке Rust для автоматизированного управления SSL-сертификатами с высокой производительностью и безопасностью памяти.

## 🚀 Основные возможности

### 🔐 Автоматизированная генерация и обновление SSL-сертификатов
- **Автоматическое получение** SSL-сертификатов для доменов
- **Интеллектуальное обновление** сертификатов до истечения срока действия
- **Планировщик задач** для регулярных проверок и обновлений
- **Валидация доменов** через HTTP-01 и DNS-01 challenges

### 🌐 Поддержка ACME-провайдеров
- **Let's Encrypt** - бесплатные SSL-сертификаты
- **ZeroSSL** - альтернативный ACME-провайдер
- **Собственные ACME-серверы** - поддержка корпоративных решений
- **Staging/Production окружения** - безопасное тестирование

### ⚡ Веб-сервер интеграция на Rust/Actix
- **Высокопроизводительный веб-сервер** на базе Actix-web
- **HTTP challenge handler** для ACME-валидации
- **Webhook поддержка** для интеграции с внешними системами
- **Мониторинг и логирование** в реальном времени

### 🔄 Прокси для интеграции сервисов
- **Reverse proxy** для перенаправления трафика
- **Load balancing** между несколькими сервисами
- **SSL termination** с автоматическим обновлением сертификатов
- **Health checks** для мониторинга доступности сервисов
- **Graceful reload** без прерывания работы

## 🛠 Технические преимущества

- **Память без GC** - предсказуемая производительность
- **Zero-cost abstractions** - минимальные накладные расходы
- **Thread safety** - безопасная многопоточность
- **Cross-platform** - поддержка Linux, Windows, macOS
- **Single binary** - простота развертывания

## 📦 Установка

```bash
# Клонирование репозитория
git clone https://github.com/vv198x/rust-certbot.git
cd rust-certbot

# Сборка проекта
cargo build --release

# Установка
cargo install --path .
```

## 🚀 Быстрый старт

```bash
# Создание конфигурации
rust-certbot init

# Получение сертификата для домена
rust-certbot cert --domain example.com

# Запуск веб-сервера с автоматическим обновлением
rust-certbot serve --config config.toml
```

## ⚙️ Конфигурация

```toml
[server]
port = 8080
host = "0.0.0.0"

[acme]
provider = "lets-encrypt"
email = "admin@example.com"
staging = false

[domains]
example.com = { 
    webroot = "/var/www/html",
    proxy = "http://localhost:3000"
}

[proxy]
enabled = true
upstream = "http://localhost:3000"
ssl_termination = true
```

## 🌐 Nginx‑подобный конфиг и шаги

Этот проект включает пример Nginx‑подобного конфига `config/simple.conf`. Он предназначен как референс и может быть подключён к реальному Nginx.

### Шаги
- **Создайте каталоги**:
```bash
mkdir -p ./web/letsencrypt ./cert/<domain>
```
- **Заполните даты обновления сертификатов** в `config/simple.conf` через `map` (одна дата на домен):
```nginx
map $host $cert_renewal_date {
    default "-";
    your-domain.com "2025-01-31";
    example.com "2025-02-15";
}
```
- **Подключите конфиг к Nginx**: добавьте include внутри `http {}`, чтобы директива `map` была в корректном контексте (в файле также есть `server {}`):
```nginx
http {
    include /absolute/path/to/rust-certbot/config/simple.conf;
}
```
- **Проверьте и примените конфиг**:
```bash
nginx -t && nginx -s reload
```

### Что делает примерный конфиг
- Обрабатывает HTTP‑01 challenge: `location /.well-known/acme-challenge/ { root ./web/letsencrypt; }`
- Отдаёт заголовок с датой обновления: `add_header X-Cert-Renewal $cert_renewal_date always;`
- Проксирует сервис по пути `/service` → `http://localhost:3000`
- Отдаёт статические файлы из `./web`

### Примечания
- **Пути**: убедитесь, что пути в `config/simple.conf` (например, `./web`) согласованы с тем, как вы монтируете директории в контейнере/на хосте. В `config.toml` каталог сертификатов задан как `/etc/rust-certbot/certs` — при необходимости приведите к одному пути или используйте bind‑mount.
- **Дубли доменов**: все домены из `server_name` должны иметь запись в `map`.
- Если вы не используете Nginx, рассматривайте `config/simple.conf` как образец — основная конфигурация приложения берётся из `config.toml`.

## 🔧 Разработка

```bash
# Запуск тестов
cargo test

# Проверка кода
cargo clippy

# Форматирование
cargo fmt

# Документация
cargo doc --open
```

## 📄 Лицензия

Этот проект распространяется под лицензией MIT - подробности в файле [LICENSE](LICENSE).

MIT License - одна из самых разрешительных лицензий с открытым исходным кодом, позволяющая:
- Коммерческое использование
- Модификацию
- Распространение
- Приватное использование
- Без гарантий

## 🤝 Участие в разработке

Мы приветствуем вклад в развитие проекта! Пожалуйста, создавайте Pull Request или открывайте Issues.

### Как внести вклад:
1. Форкните репозиторий
2. Создайте ветку для новой функции (`git checkout -b feature/amazing-feature`)
3. Зафиксируйте изменения (`git commit -m 'Add amazing feature'`)
4. Отправьте в ветку (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

## 📊 Статус проекта

Проект находится в активной разработке. Текущие приоритеты:

- [ ] ACME-клиент
- [ ] Веб-сервер интеграция 
- [ ] Прокси функциональность
- [ ] Тесты и документация


## 🔗 Ссылки

- [Документация](https://docs.rs/rust-certbot)
- [Issues](https://github.com/vv198x/rust-certbot/issues)
- [Discussions](https://github.com/vv198x/rust-certbot/discussions)