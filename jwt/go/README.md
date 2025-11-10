# JWT Go API Server

Приложение для экспериментов с JWT токенами на языке Go. Реализует сервер для управления JWT токенами с возможностью их создания, валидации, отзыва и отслеживания использования.

## Архитектура приложения

### Структура данных

- **Token** - представляет JWT токен с метаданными (ID, статус отзыва, временные метки, IP клиента, User-Agent)
- **TokenUsage** - представляет событие использования токена (ID, токен ID, временная метка, IP, User-Agent, HTTP метод, статус)

### Слой базы данных

Используется SQLite с двумя основными таблицами:

1. **tokens** - хранит информацию о токенах:

   - `id` (TEXT PRIMARY KEY) - JWT ID (jti)
   - `is_revoked` (INTEGER) - флаг отзыва
   - `issued_at`, `expires_at`, `updated_at` (TEXT) - временные метки в Unix формате
   - `client_ip`, `user_agent` (TEXT) - информация о клиенте

2. **token_usages** - хранит события использования токенов:
   - `id` (INTEGER PRIMARY KEY AUTOINCREMENT)
   - `token_id` (TEXT) - внешний ключ на tokens.id с ON DELETE CASCADE
   - `ts` (INTEGER) - временная метка в Unix формате
   - `client_ip`, `user_agent`, `method` (TEXT) - информация о запросе
   - `status` (INTEGER) - HTTP статус код

### Слой сервера

- **parseJWTToken** - парсинг и валидация JWT токена
- **collectClientInfo** - извлечение IP адреса и User-Agent из запроса
- **logMiddleware** - middleware для логирования всех запросов
- **panicMiddleware** - middleware для обработки паник

API Endpoints:

- `GET /ping` - проверка работоспособности сервера
- `GET /tokens` - получение списка всех токенов
- `POST /tokens/auth` - создание нового JWT токена (имитация sign-up/login)
- `GET /tokens/validate?token=<JWT>` - валидация токена, возвращает полную структуру Token
- `GET /tokens/usage?token=<JWT>` - получение истории использования токена
- `DELETE /tokens/revoke?token=<JWT>` - отзыв токена, возвращает обновленную структуру Token

## Быстрый запуск

```bash
go run main.go
```

Приложение запустится на `localhost:8080` с базой данных `jwtgo.sqlite` в текущей директории.

## Настройка переменных окружения и сборка приложения

Переменные окружения находятся в `.env.sample`:

```bash
# Настройка базы данных
export DATABASE_URI="jwtgo.sqlite"

# Настройка адреса и порта сервера
export SERVER_ADDR="localhost"
export SERVER_PORT="8080"

# Настройка секрета для подписи JWT токенов
export JWT_SECRET="your-secret-key-here"
```

## Собрать и запустить приложение

```bash
# Сборка приложения
go build -o jwtgo main.go

# Запуск приложения
./jwtgo
```

### Примеры использования

#### Создание токена

```bash
curl -X POST http://localhost:8080/tokens/auth \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "expires_sec=3600"
```

#### Валидация токена

```bash
curl "http://localhost:8080/tokens/validate?token=<JWT_TOKEN>"
```

#### Получение истории использования

```bash
curl "http://localhost:8080/tokens/usage?token=<JWT_TOKEN>"
```

#### Отзыв токена

```bash
curl -X DELETE "http://localhost:8080/tokens/revoke?token=<JWT_TOKEN>"
```

#### Получение списка всех токенов

```bash
curl http://localhost:8080/tokens
```
