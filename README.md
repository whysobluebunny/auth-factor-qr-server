# Auth Factor QR Server

Серверный компонент системы двухфакторной аутентификации с подтверждением входа через QR-коды и TOTP.

Сервис предоставляет:

- integration API для внешних систем;
- device-facing API для мобильного клиента;
- hosted web-интерфейс для регистрации устройства и подтверждения входа;
- опциональное demo-приложение и debug-инструменты для локальной проверки;
- шифрование TOTP-секретов при хранении;
- аудит событий безопасности, rate limiting, политики управления устройствами и очистку устаревших сессий.

## Содержание

- [Роли Компонентов](#роли-компонентов)
- [Границы Безопасности](#границы-безопасности)
- [Требования](#требования)
- [Конфигурация](#конфигурация)
- [Запуск сервиса](#запуск-сервиса)
- [Интеграция API](#интеграция-api)
- [Интеграция с встроенным веб](#интеграция-с-встроенным-веб)
- [Контракт мобильного клиента](#контракт-мобильного-клиента)
- [API Reference](#api-reference)
- [Hosted Web Routes](#hosted-web-routes)
- [Demo и Debug UI](#demo-и-debug-ui)
- [Тестирование](#тестирование)

## Роли Компонентов

Сервис имеет три основные поверхности интеграции.

| Поверхность | Потребитель | Назначение | Защита |
|---|---|---|---|
| Integration API | Backend внешней системы | Запуск enrollment, создание auth session, получение статуса, отзыв устройств, чтение аудита | `X-Auth-Factor-Api-Key` |
| Device API | Мобильное приложение второго фактора | Подтверждение enrollment и отзыв текущего устройства | TOTP и короткоживущий enrollment token |
| Hosted Web UI | Пользователь в браузере | Отображение enrollment QR, challenge QR и сканирование response QR камерой | Контекст сессии, проверка QR payload, TOTP, TTL, лимит попыток |

Внешняя система отвечает за первый фактор. Этот сервис подключается после того, как пользователь уже прошёл первичную аутентификацию.

## Границы Безопасности

Все интеграционные endpoint'ы под `/api/**` требуют API key, кроме `/api/v1/device/**`.

Device API не использует integration API key. Вместо этого он проверяет владение устройством:
- подтверждение enrollment требует `device_id`, `enrollment_token` и корректный TOTP;
- self-revoke устройства требует корректный текущий TOTP этого устройства.

Эндпоинты встроенного веб под `/ui/**` предназначены для браузерного пользовательского сценария. Они опираются на 
короткоживущие enrollment/auth contexts, проверку QR payload, TOTP, статусы, TTL и лимиты попыток.

Demo routes под `/demo/**` и debug routes под `/ui/tools/**`, `/ui/auth/challenges` управляются отдельными флагами конфигурации и по умолчанию выключены.

## Требования

- Java 21;
- Docker и Docker Compose для продуктового запуска через `docker compose`;
- локальный PostgreSQL или PostgreSQL из `docker-compose.yml`, если приложение запускается без контейнера приложения;
- Docker для интеграционных тестов, использующих Testcontainers.

## Конфигурация

Основные настройки находятся в `app.auth-factor` конфигурации `application.yml`.

| Property / env | Назначение | Значение по умолчанию |
|---|---|---|
| `AUTH_FACTOR_MASTER_KEY_BASE64` | Master key для шифрования TOTP-секретов | обязателен вне dev/compose defaults |
| `AUTH_FACTOR_API_KEY` | API key для integration API | обязателен вне dev/compose defaults |
| `AUTH_FACTOR_PUBLIC_BASE_URL` | Публичный base URL, который попадает в enrollment QR для мобильного клиента | `http://localhost:8080` |
| `app.auth-factor.api-key-header-name` | Имя заголовка API key | `X-Auth-Factor-Api-Key` |
| `app.auth-factor.service-id` | Логический идентификатор 2FA-сервиса | `auth-factor-qr-demo` |
| `app.auth-factor.debug-ui-enabled` | Включает debug web-инструменты | `false` |
| `app.auth-factor.demo-ui-enabled` | Включает demo relying-party приложение | `false` |
| `app.auth-factor.enrollment-token-ttl` | Время жизни enrollment token | `10m` |
| `app.auth-factor.device-response-token-ttl` | Время жизни auth response token | `2m` |
| `app.auth-factor.challenge-ttl` | Время жизни auth session | `2m` |
| `app.auth-factor.response-max-age` | Допустимый возраст response QR payload | `2m` |
| `app.auth-factor.allowed-clock-skew-steps` | Допустимое окно рассинхронизации TOTP | `1` |
| `app.auth-factor.challenge-rate-limit-window` | Окно rate limit для создания challenge | `1m` |
| `app.auth-factor.challenge-rate-limit-requests` | Максимум challenge-запросов в окне | `5` |
| `app.auth-factor.verify-rate-limit-window` | Окно rate limit для verify-запросов | `1m` |
| `app.auth-factor.verify-rate-limit-requests` | Максимум verify-запросов в окне | `10` |
| `app.auth-factor.max-verify-attempts` | Максимум неуспешных verify-попыток на session | `5` |
| `app.auth-factor.max-active-devices-per-user` | Максимум активных устройств пользователя | `5` |
| `app.auth-factor.max-pending-devices-per-user` | Максимум pending-устройств пользователя | `2` |
| `app.auth-factor.auth-session-retention` | Срок хранения завершённых/устаревших auth sessions | `7d` |
| `app.auth-factor.auth-session-cleanup-interval` | Интервал фоновой очистки auth sessions | `15m` |

Сгенерировать 32-байтный master key:

```bash
openssl rand -base64 32
```

Если мобильное приложение должно ходить в сервис из той же Wi-Fi сети, укажите LAN IP машины, на которой запущен backend:

```bash
export AUTH_FACTOR_PUBLIC_BASE_URL='http://192.168.1.37:8080'
```

Именно это значение попадёт в поле `base_url` внутри enrollment QR.

## Запуск Сервиса

### Production-like Docker Compose

Запускает PostgreSQL и приложение.

```bash
export AUTH_FACTOR_MASTER_KEY_BASE64='<base64-encoded-key>'
export AUTH_FACTOR_API_KEY='<integration-api-key>'
export AUTH_FACTOR_PUBLIC_BASE_URL='http://localhost:8080'

docker compose up --build
```

Сервис будет доступен на:

```text
http://localhost:8080
```

В этом режиме Flyway автоматически применяет миграции схемы БД.

### Dev Profile

Профиль `dev` предназначен для локальной ручной проверки. Он использует значения из `application-dev.yml`, включает demo UI и создаёт схему через Hibernate.

```bash
SPRING_PROFILES_ACTIVE=dev ./gradlew bootRun
```

Текущая dev-конфигурация:

- `demo-ui-enabled=true`;
- `debug-ui-enabled=false`;
- `api-key=dev-api-key`;
- Flyway выключен;
- Hibernate использует `ddl-auto=create-drop`.

Если нужны debug-инструменты:

```bash
SPRING_PROFILES_ACTIVE=dev \
APP_AUTH_FACTOR_DEBUG_UI_ENABLED=true \
./gradlew bootRun
```

Если переменная окружения не подхватывается в конкретной среде запуска, задайте property через JVM/system property или локально поменяйте dev-конфиг.

### Локальный PostgreSQL

По умолчанию приложение ожидает:

```text
jdbc:postgresql://localhost:5432/auth_factor_qr
username: auth_factor_qr
password: auth_factor_qr
```

Переопределить datasource можно переменными окружения:

```bash
export SPRING_DATASOURCE_URL='jdbc:postgresql://localhost:5432/<db_name>'
export SPRING_DATASOURCE_USERNAME='<db_user>'
export SPRING_DATASOURCE_PASSWORD='<db_password>'
```

## Интеграция API

Этот вариант подходит, если у целевой системы уже есть свой UI или если сервис используется не только в веб-приложении. Внешняя система вызывает integration API со своего backend и сама отображает/считывает QR-коды.

### Enrollment Flow

1. Backend внешней системы запускает enrollment после того, как пользователь прошёл первый фактор.

```http
POST /api/v1/enrollments/start
X-Auth-Factor-Api-Key: <integration-api-key>
Content-Type: application/json
```

```json
{
  "externalUserId": "user123",
  "displayName": "User Name",
  "deviceLabel": "Initial Device Label"
}
```

2. Сервис возвращает `qrPayloadRaw`. Внешняя система отображает это значение как enrollment QR в своём UI.

3. Мобильное приложение считывает enrollment QR и подтверждает регистрацию через Device API:

```http
POST {base_url}/api/v1/device/enrollments/confirm
Content-Type: application/json
```

```json
{
  "device_id": "device-uuid",
  "enrollment_token": "token-from-enrollment-qr",
  "device_label": "Pixel 8",
  "totp_code": "123456"
}
```

4. Backend внешней системы может получить список устройств пользователя:

```http
GET /api/v1/enrollments/devices?externalUserId=user123
X-Auth-Factor-Api-Key: <integration-api-key>
```

### Sign-In Flow

1. Внешняя система проверяет первый фактор.

2. Backend внешней системы создаёт сессию второго фактора:

```http
POST /api/v1/auth/challenge
X-Auth-Factor-Api-Key: <integration-api-key>
Content-Type: application/json
```

```json
{
  "externalUserId": "user123",
  "firstFactorRef": "login-attempt-001"
}
```

3. Сервис возвращает `qrPayloadRaw`. Внешняя система отображает это значение как challenge QR.

4. Мобильное приложение сканирует challenge QR и формирует response QR.

5. Внешняя система считывает response QR своим UI и отправляет payload на проверку.

Текущий integration endpoint:

```http
POST /api/v1/auth/verify-qr-response
X-Auth-Factor-Api-Key: <integration-api-key>
Content-Type: application/json
```

```json
{
  "type": "response",
  "session_id": "session-uuid",
  "challenge": "challenge-from-qr",
  "totp": "123456",
  "timestamp": 1774356605,
  "device_id": "device-uuid"
}
```

При успешной проверке сервис возвращает `approved=true` и переводит auth session в `APPROVED`.

Важно: hosted web flow принимает текущий response QR формат с `response_token`. Public integration endpoint `/api/v1/auth/verify-qr-response` сейчас принимает legacy `ResponseQrPayload` без `response_token`. Подробнее см. [Интеграционные Замечания](#интеграционные-замечания).

## Интеграция с встроенным веб

Этот вариант подходит, если внешняя система хочет делегировать сервису второго фактора браузерный UI: отображение QR, сканирование response QR через камеру и redirect обратно в приложение.

### Hosted Enrollment

Внешнее приложение может стартовать hosted enrollment через browser form:

```http
POST /ui/enrollments
Content-Type: application/x-www-form-urlencoded
```

Поля формы:

```text
externalUserId=user123
displayName=User Name
returnUrl=/account/security
```

Hosted page отображает enrollment QR. После подтверждения enrollment мобильным приложением страница опрашивает статус устройства и перенаправляет пользователя на `returnUrl`, когда устройство выходит из состояния `PENDING`.

Мобильное приложение подтверждает enrollment тем же Device API:

```http
POST {base_url}/api/v1/device/enrollments/confirm
```

### Hosted Sign-In Confirmation

1. Backend внешней системы проверяет первый фактор.

2. Backend внешней системы создаёт challenge:

```http
POST /api/v1/auth/challenge
X-Auth-Factor-Api-Key: <integration-api-key>
Content-Type: application/json
```

```json
{
  "externalUserId": "user123",
  "firstFactorRef": "login-attempt-001"
}
```

3. Browser перенаправляется на hosted auth page:

```text
/ui/auth/sessions/{sessionId}?returnUrl=/callback
```

4. Hosted page отображает challenge QR и запускает сканирование response QR через веб-камеру.

5. Мобильное приложение сканирует challenge QR и показывает response QR.

6. Hosted page считывает response QR и отправляет его на:

```text
POST /ui/auth/sessions/{sessionId}/verify
```

7. При успехе hosted page перенаправляет пользователя на:

```text
{returnUrl}?sessionId={sessionId}
```

8. Backend внешней системы должен дополнительно проверить статус session перед завершением входа:

```http
GET /api/v1/auth/sessions/{sessionId}
X-Auth-Factor-Api-Key: <integration-api-key>
```

Завершайте вход только если `status=APPROVED`.

## Контракт Мобильного Клиента

### Enrollment QR Payload

```json
{
  "type": "enroll",
  "service_id": "auth-factor-qr-demo",
  "base_url": "http://localhost:8080",
  "user_id": "user123",
  "device_id": "device-uuid",
  "secret": "BASE32SECRET",
  "enrollment_token": "token",
  "period": 30,
  "digits": 6,
  "algorithm": "SHA1"
}
```

Мобильное приложение сохраняет `service_id`, `base_url`, `user_id`, `device_id`, `secret`, `period`, `digits` и `algorithm`.

### Challenge QR Payload

```json
{
  "type": "challenge",
  "session_id": "session-uuid",
  "challenge": "challenge-token",
  "service_id": "auth-factor-qr-demo",
  "timestamp": 1774356605,
  "response_token": "response-token"
}
```

### Response QR Payload Для Hosted Web

```json
{
  "session_id": "session-uuid",
  "response_token": "response-token",
  "challenge": "challenge-token",
  "totp": "123456",
  "timestamp": 1774356620,
  "device_id": "device-uuid"
}
```

Мобильное приложение не обращается к серверу в момент подтверждения входа. Оно сканирует challenge QR, локально вычисляет TOTP и отображает response payload как QR-код.

### Device Self-Revoke

```http
POST {base_url}/api/v1/device/devices/{deviceId}/revoke
Content-Type: application/json
```

```json
{
  "totpCode": "123456"
}
```

После успешного ответа мобильное приложение должно удалить локальную запись устройства.

## API Reference

Все endpoints в этом разделе требуют:

```text
X-Auth-Factor-Api-Key: <integration-api-key>
```

Исключение: `/api/v1/device/**`.

### Enrollment

| Endpoint | Method | Назначение |
|---|---|---|
| `/api/v1/enrollments/start` | `POST` | Запустить enrollment и получить enrollment QR payload |
| `/api/v1/enrollments/confirm` | `POST` | Подтвердить enrollment через integration API по `deviceId` и `totpCode` |
| `/api/v1/enrollments/devices?externalUserId=...` | `GET` | Получить список устройств пользователя |
| `/api/v1/enrollments/devices/{deviceId}/revoke` | `POST` | Отозвать устройство через integration API |

### Authentication

| Endpoint | Method | Назначение |
|---|---|---|
| `/api/v1/auth/challenge` | `POST` | Создать сессию второго фактора |
| `/api/v1/auth/verify-qr-response` | `POST` | Проверить response payload через integration API |
| `/api/v1/auth/sessions/{sessionId}` | `GET` | Получить статус auth session |

### Device API

| Endpoint | Method | Назначение |
|---|---|---|
| `/api/v1/device/enrollments/confirm` | `POST` | Подтвердить enrollment из мобильного приложения |
| `/api/v1/device/devices/{deviceId}/revoke` | `POST` | Отозвать текущее мобильное устройство |

### Audit

| Endpoint | Method | Назначение |
|---|---|---|
| `/api/v1/audit-events?externalUserId=...&limit=20` | `GET` | Получить события аудита |

## Hosted Web Routes

| Route | Method | Назначение |
|---|---|---|
| `/ui/enrollments` | `GET` | Отобразить hosted enrollment page |
| `/ui/enrollments` | `POST` | Запустить или возобновить hosted enrollment |
| `/ui/enrollments/confirm` | `POST` | Ручное подтверждение enrollment через hosted/debug form |
| `/ui/devices?externalUserId=...` | `GET` | Hosted-страница со списком устройств пользователя |
| `/ui/enrollments/{deviceId}/status` | `GET` | Получить статус enrollment для polling |
| `/ui/auth/sessions/{sessionId}` | `GET` | Отобразить hosted auth page |
| `/ui/auth/sessions/{sessionId}/verify` | `POST` | Проверить response QR, считанный hosted page |

## Demo и Debug UI

Demo UI управляется настройкой:

```yaml
app.auth-factor.demo-ui-enabled: true
```

Routes:

```text
/demo
/demo/login
/demo/home
/demo/callback
```

Debug UI управляется настройкой:

```yaml
app.auth-factor.debug-ui-enabled: true
```

Routes:

```text
/ui/auth/challenges
/ui/tools/device-simulator
```

Demo и debug UI выключены по умолчанию в `application.yml`.

## Тестирование

Запуск всех тестов:

```bash
./gradlew test
```

Интеграционные тесты используют Spring Boot Test, MockMvc и Testcontainers для PostgreSQL.