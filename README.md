# auth-factor-qr-server

Серверный компонент системы двухфакторной аутентификации с подтверждением входа через QR-коды и TOTP.

## Назначение

Сервис реализует:
- регистрацию мобильного устройства пользователя;
- просмотр устройств пользователя;
- отзыв зарегистрированного устройства;
- генерацию enrollment QR;
- подтверждение регистрации через TOTP;
- генерацию challenge для второй фазы входа;
- проверку response QR, сформированного мобильным приложением;
- привязку ответа к конкретной auth session;
- ограничение количества попыток;
- защиту от повторного использования response в рамках сессии;
- аудит ключевых событий безопасности;
- защиту API через integration API key.

## Технологии

- Kotlin
- Spring Boot
- Spring Web MVC
- Spring Data JPA
- PostgreSQL
- Flyway
- Testcontainers

## Требования

- Java 21
- Docker
- Docker Compose

## Запуск PostgreSQL

```bash
docker compose up -d postgres
```

По умолчанию приложение ожидает БД `auth_factor_qr` на `localhost:5432`
с пользователем `auth_factor_qr` и паролем `auth_factor_qr`.

Если у тебя локальный PostgreSQL уже запущен с другими реквизитами, можно не
менять код, а переопределить datasource через переменные окружения:

```bash
export SPRING_DATASOURCE_URL='jdbc:postgresql://localhost:5432/<db_name>'
export SPRING_DATASOURCE_USERNAME='<db_user>'
export SPRING_DATASOURCE_PASSWORD='<db_password>'
```

## Dev-профиль

Для локальной разработки можно использовать профиль `dev`: он автоматически
поднимет временный PostgreSQL через Testcontainers при старте приложения.

```bash
export SPRING_PROFILES_ACTIVE=dev
./gradlew bootRun
```

Нужен установленный Docker. Контейнер базы создаётся автоматически на запуске
приложения и не требует ручного создания `role` или `database`.
Схема в `dev`-профиле создаётся автоматически через Hibernate.

В `dev`-профиле также подставляются локальные значения для:
- `AUTH_FACTOR_MASTER_KEY_BASE64`
- `AUTH_FACTOR_API_KEY`

Для запросов к API в этом профиле используй заголовок:

```text
X-Auth-Factor-Api-Key: dev-api-key
```

Если нужен именно постоянный локальный PostgreSQL, можно по-прежнему использовать
`docker compose up -d postgres` и обычный профиль `default`, где используется Flyway.

## Production-like запуск через Docker Compose

Для запуска полного production-like контура можно поднимать и PostgreSQL, и само
приложение через `docker compose`.

```bash
export AUTH_FACTOR_MASTER_KEY_BASE64='<your_key>'
export AUTH_FACTOR_API_KEY='<your_api_key>'
export AUTH_FACTOR_PUBLIC_BASE_URL='http://localhost:8080'

docker compose up --build
```

В этом сценарии:
- PostgreSQL запускается как отдельный контейнер;
- приложение запускается в `default` профиле;
- схема БД накатывается через Flyway автоматически;
- сервис будет доступен на `http://localhost:8080`.

Если нужно оставить доступ для мобильного клиента из локальной сети, вместо
`localhost` в `AUTH_FACTOR_PUBLIC_BASE_URL` следует передать LAN IP машины, на
которой запущен compose.

## Переменная с master key

Нужно задать ключ для шифрования TOTP-секретов.

Пример генерации 32-байтного ключа в Base64:

```bash
openssl rand -base64 32
```

Далее экспортировать:

```bash
export AUTH_FACTOR_MASTER_KEY_BASE64='<your_key>'
```

## Переменная с API key

Сервис требует API key для всех endpoint'ов `/api/**` и защищённых actuator endpoint'ов.

```bash
export AUTH_FACTOR_API_KEY='<your_api_key>'
```

## Запуск приложения

```bash
./gradlew bootRun
```

## Запуск тестов

```bash
./gradlew test
```

## Основные endpoint'ы

### Старт регистрации устройства

`POST /api/v1/enrollments/start`

Пример тела:

```json
{
  "externalUserId": "user123",
  "displayName": "Artyom Bondarenko",
  "deviceLabel": "Pixel 8"
}
```

### Подтверждение регистрации устройства

`POST /api/v1/enrollments/confirm`

```json
{
  "deviceId": "uuid",
  "totpCode": "123456"
}
```

### Создание challenge

`POST /api/v1/auth/challenge`

```json
{
  "externalUserId": "user123",
  "firstFactorRef": "login-attempt-001"
}
```

### Проверка response QR

`POST /api/v1/auth/verify-qr-response`

```json
{
  "type": "response",
  "session_id": "uuid",
  "challenge": "base64url-token",
  "totp": "123456",
  "timestamp": 1774356605,
  "device_id": "uuid"
}
```

### Получение состояния сессии

`GET /api/v1/auth/sessions/{sessionId}`

### Список устройств пользователя

`GET /api/v1/enrollments/devices?externalUserId=user123`

### Отзыв устройства

`POST /api/v1/enrollments/devices/{deviceId}/revoke`

```json
{
  "externalUserId": "user123"
}
```

### Просмотр аудита

`GET /api/v1/audit-events?externalUserId=user123&limit=20`
