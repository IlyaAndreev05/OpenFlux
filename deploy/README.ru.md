# Self-hosted OpenFlux Control

Папка содержит Compose-варианты с Control, Next.js-панелью и Traefik. Панель вызывает только HTTP API Control; БД не публикуется и доступна только внутри backend-сети. Для панели нужен соседний клон `OpenFlux-admin-panel`.

## SQLite по умолчанию

1. Создайте `.env` в корне репозитория из `.env.example`. Задайте домен, e-mail ACME, длинный `OPENFLUX_ADMIN_TOKEN`, пароль панели и URL-safe пароль PostgreSQL (последний нужен только для PostgreSQL).
2. Убедитесь, что DNS домена указывает на сервер и доступны TCP 80/443.
3. Запустите `docker compose -f deploy/compose/docker-compose.yml up -d --build`.
4. Войдите на `https://$OPENFLUX_DOMAIN`. API и JSON OpenAPI доступны по `/api/v1/openapi.json`; health-check — `/healthz`.

SQLite и installation key находятся в Docker volume `openflux-data`. Установочный ключ обязателен для расшифровки токенов/ключей из БД. Потеря ключа делает эти значения невосстановимыми.

Локальный выходной узел можно включить в том же Compose после первого запуска Control: создайте ноду в панели, сохраните выданные `OPENFLUX_NODE_ID` и `OPENFLUX_NODE_TOKEN` в `.env`, затем запустите `docker compose --profile local-node -f deploy/compose/docker-compose.yml up -d --build`. Нода подключается к Control по внутренней сети и выходит к документам через сеть edge. Без профиля сервис узла не запускается. Для Happ/Xray на отдельной машине используйте remote-node Compose ниже и подключите его к сети Remnawave.

## CLI

`openfluxctl` входит в образ Control; он обращается к тому же API и не содержит отдельной бизнес-логики. Команды доступны также из контейнера: `docker compose exec openflux-control openfluxctl users list`. Для запуска локального бинарника задайте `OPENFLUX_CONTROL_URL` и `OPENFLUX_ADMIN_TOKEN`. Используйте `--json` для машинного вывода; обычный вывод списков табличный.

Примеры:

```sh
openfluxctl users create alice
openfluxctl documents create docs-a https://disk.yandex.ru/i/REPLACE_ME
openfluxctl pools create primary least-loaded DOC_ID1,DOC_ID2 standalone
openfluxctl pools create happ sticky DOC_ID1 transport 10.255.0.1:19100 remnanode:19000
openfluxctl nodes create exit-a exit exit.example:443
openfluxctl subscription issue USER_ID
OPENFLUX_QR_FILE=/tmp/alice.png openfluxctl subscription issue USER_ID
OPENFLUX_QR_FILE=/tmp/alice-config.png openfluxctl config export USER_ID
openfluxctl devices list USER_ID
openfluxctl devices revoke DEVICE_ID
openfluxctl remnawave sync
```

Для обновления документа, пула, пользователя или ноды передайте JSON объект в `documents update ID JSON`, `pools update ID JSON`, `users update ID JSON` или `nodes update ID JSON`. Соответствия Internal Squad задаются `squad-pools set '{"mappings":[{"squad_uuid":"SQUAD_UUID","pool_id":"POOL_ID"}]}'`.

## PostgreSQL

Используйте тот же Compose с дополнительным файлом: `docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.postgres.yml up -d --build`. Функциональность и миграции общие, PostgreSQL не публикует порт наружу. Пароль в URL должен быть URL-safe.

## Удалённая нода и Remnawave

На сервере ноды склонируйте OpenFlux и запустите `docker compose -f deploy/compose/docker-compose.remote-node.yml up -d --build`, задав `OPENFLUX_CONTROL_URL`, `OPENFLUX_NODE_ID`, `OPENFLUX_NODE_TOKEN`. ID и токен создаются в Control и показываются при регистрации ноды; токен не логируется.

Для Happ-режима подключите контейнер к Docker-сети Remnawave через `REMNAWAVE_DOCKER_NETWORK`. В Remnawave нужно создать внутренний Xray inbound и указать его как `forward_target` в transport-пуле. Он должен быть доступен только по внутренней сети. Подробный шаблон, Response Rule и ограничения — в соседнем репозитории `ilya-remnawave-config/examples/openflux-integration`.

Node-agent получает желаемую версию по HTTPS, валидирует конфигурацию, запускает кандидат OpenFlux и подтверждает применение только после readiness. HTTP healthcheck node-agent слушает только loopback внутри контейнера.

## Резервная копия и восстановление

`deploy/scripts/backup.sh sqlite` создаёт согласованную SQLite-копию и копию installation key. Для PostgreSQL: `deploy/scripts/backup.sh postgres`. Копируйте обе части резервной копии в отдельное защищённое хранилище, не коммитьте их.

Восстановление проверяет целостность и требует точную пару файлов БД и ключа с одинаковым timestamp. Перед заменой скрипт сам создаёт резервную копию текущей установки, останавливает Control и панель, восстанавливает данные и поднимает сервисы. Укажите только имена файлов из каталога backup:

    OPENFLUX_RESTORE_CONFIRM=YES deploy/scripts/restore.sh sqlite openflux-<timestamp>.sqlite3 installation-<timestamp>.key
    OPENFLUX_RESTORE_CONFIRM=YES deploy/scripts/restore.sh postgres openflux-<timestamp>.dump installation-<timestamp>.key

SQLite оставляет предыдущую БД и ключ в volume. Для PostgreSQL скрипт проверяет custom dump и восстанавливает его через контейнер postgres. Не задавайте OPENFLUX_INSTALLATION_KEY напрямую: установочный ключ должен браться из восстановленного файла. Нестандартный каталог задаётся абсолютным OPENFLUX_BACKUP_DIR, одинаковым для Compose и скриптов. Перед рабочим сервером восстановление нужно проверить на отдельной установке.

Обновление: сделайте резервную копию, обновите репозитории на совместимые версии, выполните Compose build/up. Миграции запускаются Control при старте. Возврат к старому бинарнику после схемной миграции следует выполнять только вместе с восстановлением резервной БД.

## Ограничения текущей приёмки

Успешная сборка контейнеров не доказывает работу реального транспорта. Yandex CAPTCHA уже блокировала живую проверку; необходим повторный тест после допуска документов. UDP/DNS и IPv6, четыре клиентские платформы и нагрузка 100 клиентов не считаются подтверждёнными до отдельного сквозного прогона.
