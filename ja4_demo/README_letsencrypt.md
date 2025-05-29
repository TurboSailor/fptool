# 🔐 JA4 Fingerprint Server with Let's Encrypt

Полностью автономный JA4 сервер с автоматическими Let's Encrypt сертификатами. **Nginx больше не нужен!**

## 🚀 Ключевые преимущества

- ✅ **Автоматические SSL сертификаты** - Let's Encrypt autocert
- ✅ **Без nginx зависимостей** - все в одном Go бинарнике  
- ✅ **HTTP → HTTPS редирект** встроенный
- ✅ **Валидные сертификаты** - браузеры не будут ругаться
- ✅ **Автообновление сертификатов** каждые 90 дней
- ✅ **Production ready** с systemd service

## 📋 Требования

1. **Домен** с настроенными A/AAAA записями на ваш сервер
2. **Порты 80 и 443** свободны (nginx нужно остановить)
3. **Go 1.21+** для сборки
4. **Root доступ** для запуска на стандартных портах

## 🛠 Быстрый деплой

```bash
cd ja4_demo

# Остановите nginx если запущен
sudo systemctl stop nginx
sudo systemctl disable nginx

# Запустите деплой
sudo DOMAIN=ja4.yourdomain.com EMAIL=admin@yourdomain.com ./deploy_letsencrypt.sh
```

Скрипт автоматически:
- Соберет Go приложение с зависимостями
- Создаст systemd service
- Запустит сервер на портах 80/443
- Получит Let's Encrypt сертификаты при первом запросе

## 🔧 Ручная настройка

### 1. Сборка

```bash
cp go_letsencrypt.mod go.mod
go mod tidy
go build -o ja4-server main_with_letsencrypt.go
```

### 2. Запуск

```bash
sudo DOMAIN=ja4.yourdomain.com EMAIL=admin@yourdomain.com ./ja4-server
```

### 3. Systemd service

```bash
# Отредактируйте домен и email в ja4-server.service
sudo cp ja4-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ja4-server
sudo systemctl start ja4-server
```

## 📊 API Endpoints

```bash
# Получить JA4 фингерпринт
curl https://ja4.yourdomain.com/ja4

# Просмотр базы данных
curl https://ja4.yourdomain.com/database

# Экспорт в JSON
curl https://ja4.yourdomain.com/export -o database.json

# Информация о сервере
curl https://ja4.yourdomain.com/
```

## 🔍 Мониторинг

```bash
# Статус сервиса
sudo systemctl status ja4-server

# Логи в реальном времени
sudo journalctl -u ja4-server -f

# Проверка сертификатов
echo | openssl s_client -servername ja4.yourdomain.com -connect ja4.yourdomain.com:443 2>/dev/null | openssl x509 -noout -dates
```

## 📁 Структура файлов

```
ja4_demo/
├── main_with_letsencrypt.go  # Основной сервер с Let's Encrypt
├── go_letsencrypt.mod        # Go модуль с crypto/acme зависимостью  
├── deploy_letsencrypt.sh     # Скрипт автоматического деплоя
├── ja4-server.service        # Systemd service конфигурация
├── ja4_database.json         # База данных (создается автоматически)
└── certs-cache/              # Кеш Let's Encrypt сертификатов
```

## 🔒 Безопасность

- **Автоматическое обновление** сертификатов каждые 60 дней
- **HTTPS Strict Transport Security** можно добавить
- **Host validation** - только указанный домен
- **Rate limiting** по Let's Encrypt квотам (5 дубликатов/неделю)

## 🆚 Сравнение с nginx версией

| Параметр | Nginx версия | Let's Encrypt версия |
|----------|-------------|---------------------|
| Зависимости | nginx + manual certs | только Go |
| Сертификаты | самоподписанные | Let's Encrypt автоматические |
| Браузер | ошибки SSL | доверенные сертификаты |
| Обновление | ручное | автоматическое |
| Конфигурация | nginx.conf + Go | только Go |
| Порты | 8443 + proxy | 80, 443 напрямую |

## 🔄 Миграция с nginx версии

```bash
# 1. Остановите старую версию
sudo systemctl stop nginx
sudo systemctl stop your-old-ja4-service

# 2. Запустите новую версию
sudo DOMAIN=your-domain.com EMAIL=your-email@domain.com ./deploy_letsencrypt.sh

# 3. Проверьте работу
curl https://your-domain.com/ja4
```

## 🐛 Troubleshooting

### Ошибка "port already in use"
```bash
# Найдите процесс
sudo ss -tuln | grep ":443"
sudo lsof -i :443

# Остановите nginx/apache
sudo systemctl stop nginx apache2
```

### Let's Encrypt лимиты
- **5 дубликатов в неделю** на домен
- **50 доменов в неделю** на аккаунт  
- Используйте staging для тестов: добавьте `DirectoryURL: autocert.DefaultACMEDirectory`

### Логи сертификатов
```bash
# Логи autocert
sudo journalctl -u ja4-server | grep -i "cert\|acme\|autocert"

# Кеш сертификатов
ls -la certs-cache/
```

## 🎯 Production checklist

- [ ] Домен настроен и доступен
- [ ] Firewall открыт для 80, 443
- [ ] Email для Let's Encrypt валидный
- [ ] Мониторинг systemd сервиса настроен
- [ ] Backup базы данных автоматизирован
- [ ] Логи ротируются

**Результат: Zero-dependency JA4 сервер с валидными SSL сертификатами!** 🎉 