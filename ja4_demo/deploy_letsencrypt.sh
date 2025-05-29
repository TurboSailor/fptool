#!/bin/bash

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🔐 JA4 Server with Let's Encrypt Deployment${NC}"
echo

# Проверяем что мы root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}" 
   exit 1
fi

# Проверяем переменные окружения
if [[ -z "$DOMAIN" ]]; then
    echo -e "${YELLOW}Enter your domain (e.g., ja4.yourdomain.com):${NC}"
    read -r DOMAIN
    export DOMAIN
fi

if [[ -z "$EMAIL" ]]; then
    echo -e "${YELLOW}Enter your email for Let's Encrypt:${NC}"
    read -r EMAIL
    export EMAIL
fi

echo -e "${GREEN}Domain: $DOMAIN${NC}"
echo -e "${GREEN}Email: $EMAIL${NC}"
echo

# Остановим nginx если запущен
if systemctl is-active --quiet nginx; then
    echo -e "${YELLOW}Stopping nginx...${NC}"
    systemctl stop nginx
fi

# Остановим старый сервис если есть
if systemctl is-active --quiet ja4-server; then
    echo -e "${YELLOW}Stopping old ja4-server...${NC}"
    systemctl stop ja4-server
fi

# Проверяем что порты свободны
if ss -tuln | grep -q ":80\s"; then
    echo -e "${RED}Port 80 is busy. Please stop the service using it.${NC}"
    exit 1
fi

if ss -tuln | grep -q ":443\s"; then
    echo -e "${RED}Port 443 is busy. Please stop the service using it.${NC}"
    exit 1
fi

# Копируем go.mod
echo -e "${GREEN}Setting up Go module...${NC}"
cp go_letsencrypt.mod go.mod

# Инициализируем модуль и скачиваем зависимости
go mod tidy

# Собираем проект
echo -e "${GREEN}Building JA4 server...${NC}"
go build -o ja4-server main_with_letsencrypt.go

# Создаем директорию для кеша сертификатов
mkdir -p certs-cache
chmod 700 certs-cache

# Обновляем systemd service
echo -e "${GREEN}Installing systemd service...${NC}"
sed "s/DOMAIN=ja4.yourdomain.com/DOMAIN=$DOMAIN/g; s/EMAIL=admin@yourdomain.com/EMAIL=$EMAIL/g" ja4-server.service > /tmp/ja4-server.service
cp /tmp/ja4-server.service /etc/systemd/system/
systemctl daemon-reload

# Запускаем сервис
echo -e "${GREEN}Starting ja4-server...${NC}"
systemctl enable ja4-server
systemctl start ja4-server

# Проверяем статус
sleep 2
if systemctl is-active --quiet ja4-server; then
    echo -e "${GREEN}✅ JA4 server started successfully!${NC}"
else
    echo -e "${RED}❌ Failed to start ja4-server${NC}"
    echo "Checking logs:"
    journalctl -u ja4-server --no-pager -n 20
    exit 1
fi

echo
echo -e "${GREEN}🎉 Deployment completed!${NC}"
echo
echo -e "${GREEN}Endpoints:${NC}"
echo -e "  https://$DOMAIN/ja4 - получить JA4 fingerprint"
echo -e "  https://$DOMAIN/database - просмотр базы данных"
echo -e "  https://$DOMAIN/export - экспорт базы в JSON"
echo -e "  https://$DOMAIN/ - информация о сервере"
echo
echo -e "${YELLOW}Useful commands:${NC}"
echo -e "  systemctl status ja4-server  - статус сервиса"
echo -e "  journalctl -u ja4-server -f  - логи в реальном времени"
echo -e "  systemctl restart ja4-server - перезапуск"
echo
echo -e "${GREEN}Let's Encrypt certificates will be automatically obtained on first HTTPS request${NC}"
echo -e "${GREEN}HTTP -> HTTPS redirect is enabled${NC}"
echo -e "${GREEN}Nginx is NO LONGER NEEDED - everything handled by Go server${NC}" 