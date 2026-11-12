# AthleteLink API Gateway

HTTP-прокси для Auth, Profile, Request/Core, Game и Chat. Gateway проверяет access JWT,
отзыв токена и бан пользователя, затем передаёт доверенную идентичность сервису.
Бизнес-права и проверка полезной нагрузки принадлежат целевому сервису.

- [Поведение прокси и авторизации](docs/PROXY.md)
- [Публичный OpenAPI](docs/contracts/gateway-openapi.yaml)
- [Конфигурация окружения](.env.example)
- [Журнал интеграции](docs/INTEGRATION.md)
- [План интеграции](docs/ROADMAP.md)

## Запуск

Установите переменные окружения по `.env.example`, включая `JWT_SECRET`, настройки
общего Redis, пять upstream URL и пять полных health URL. Файл `.env` автоматически
не загружается. Для upstream указывается origin без `/api/v1`, путей и query.
Путь API `/api/v1` сохраняется при пересылке.

| Сервис | Переменная URL | Локальный порт |
|---|---|---|
| Auth | `GATEWAY_AUTH_URL` | 8081 |
| Profile | `GATEWAY_PROFILE_URL` | 8082 |
| Request/Core | `GATEWAY_CORE_URL` | 8083 |
| Game | `GATEWAY_GAME_URL` | 8084 |
| Chat HTTP | `GATEWAY_CHAT_URL` | 8085 |

Для каждого сервиса доступны `GATEWAY_<SERVICE>_TIMEOUT` и обязательный
`GATEWAY_<SERVICE>_HEALTH_URL`. Тайм-аут прокси по умолчанию составляет 10 секунд
и должен быть меньше `GATEWAY_WRITE_TIMEOUT`. Health URL задаются независимо
от origin сервиса. В примере указан контрактный health Auth, остальные пути
нужно задать для своего окружения.

```sh
go run ./cmd/gateway
```

Gateway слушает `:8080` по умолчанию. `/healthz` проверяет процесс. `/readyz`
проверяет Redis и HTTP 200 от всех пяти health URL в пределах одного
`GATEWAY_HEALTH_TIMEOUT`. Недоступность Redis не препятствует запуску.

## API

`GET/PUT /api/v1/user` направляются в Profile, `POST/DELETE /api/v1/user` в Auth.
`GET /api/v1/user/me` направляется в Profile с доверенным заголовком `userId` из JWT.
`GET /api/v1/players` и `/api/v1/players/` подставляют `sub` в путь Game.
`GET /api/v1/ban/{email}` передаёт email в URL без обязательного тела запроса.

Список операций определяется [таблицей маршрутов](internal/httpapi/routes.go).
Публичны регистрация, login, refresh и две операции сброса пароля. Если
публичный запрос содержит `Authorization`, токен тоже проверяется. Остальные
бизнес-операции требуют access JWT. Старые переименованные Auth-пути и удалённые
операции Core не поддерживаются. WebSocket не входит в этот HTTP-контракт.

Поиск `jwt:denylist:<jti>` даёт 401, поиск `user:banlist:<sub>` даёт 403.
При наличии обоих ключей приоритет имеет 401. Недоступность Redis и тайм-аут
допускают запрос, остальные ошибки дают 503. Найденный бан или отзыв сохраняет
силу при ошибке другой проверки. Проверки выполняются для каждого действительного
токена без локального кеша.

## Документация и проверки

`/openapi.yaml` и `/swagger/` публичны. Swagger UI использует origin Gateway.
Спецификация встроена в бинарный файл, поэтому после её изменения нужна пересборка.

```sh
ruby scripts/build_gateway_openapi.rb
ruby scripts/build_standalone_swagger.rb
go test -race ./...
go vet ./...
ruby scripts/build_gateway_openapi.rb --check
ruby scripts/build_standalone_swagger.rb --check
```

[Автономный Swagger](docs/swagger-standalone.html) содержит спецификацию и ресурсы
интерфейса в одном файле. Для запросов из него укажите
`?gateway=https://your-gateway-origin` в URL страницы. Ресурсы Swagger UI и лицензии
хранятся в `docs/swagger-ui/`.
