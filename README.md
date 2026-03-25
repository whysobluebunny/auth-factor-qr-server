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
docker compose up -d
````

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
  "deviceId": "uuid",
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

