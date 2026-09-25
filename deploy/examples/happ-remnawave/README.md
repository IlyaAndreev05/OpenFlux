# Пример: Happ → OpenFlux localhost → документы → Xray

Подробный Xray JSON template, скрытый localhost host, Happ Response Rule и внутренний inbound размещены в `ilya-remnawave-config/examples/openflux-integration`.

Схема: Happ/Xray сохраняет пользовательский VLESS UUID и TLS-поток; Xray outbound подключается к loopback TCP listener OpenFlux; клиентский OpenFlux переносит байты по пулу документов; выходной OpenFlux адресует поток во внутренний Xray inbound Remnawave. Внутренний inbound принимает VLESS и именно Xray ведёт пользовательскую статистику.

Пока это пример архитектуры, не маркировка готового режима: Android/Desktop локальный TCP listener и полный live test должны быть собраны/проверены отдельно.
