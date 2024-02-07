# Test Case Stakewolle

### Описание

Необходимо разработать простой RESTful API сервис для реферальной системы.

Функциональные требования:
- ✅ регистрация и аутентификация пользователя (JWT, Oauth 2.0);
- ✅ аутентифицированный пользователь должен иметь возможность создать свой реферальный код;
- ✅ аутентифицированный пользователь должен иметь возможность удалить свой реферальный код;
- ✅ одновременно у пользователя может быть активен только 1 код;
- ✅ при создании кода обязательно должен быть задан его срок годности;
- ✅ возможность получения реферального кода по email адресу реферера;
- ✅ возможность регистрации по реферальному коду в качестве реферала;
- ✅ получение информации о рефералах по id реферера;
- ✅ UI документация (Swagger/ReDoc).

Опциональные задачи:
- 💔 использование clearbit.com/platform/enrichment для получения дополнительной информации о пользователе при регистрации;
- ✅ использование emailhunter.co для проверки указанного email адреса;
- ✅ кеширование реферальных кодов с использованием in-memory БД. 
- ✅ Readme.md файл с описанием проекта и инструкциями по запуску и тестированию

Стек:
- ✅ использование любого современного веб фреймворка;
- ✅ использование СУБД и миграций (Sqlite, PostgreSQL, MySQL);
- ✅ размещение проекта на GitHub;

Требования к проекту:
- ✅ чистота и читаемость кода;
- ✅ все I/O bound операции должны быть асинхронными;
- ✅ проект должен быть хорошо структурирован.
- ✅ проект должен быть простым в деплое, обеспечивать обработку нестандартных ситуаций, быть устойчивой к неправильным действиям пользователя и т.д.

### Комментарии кандидата

1) 💔 использование clearbit.com/platform/enrichment для получения дополнительной информации о пользователе при регистрации

Если emailhunter.co еще предоставил в открытую API документацию, то clearbit.com такие разделы спрятал, а корпоративной почты у меня нет для регистрации.
В целом, это было бы одно и то же, что я наметил в src/auth/routers:auth_register для emailhunter.

3) ✅ получение информации о рефералах по id реферера;
   ✅ возможность получения реферального кода по email адресу реферера;

В целях конфиденциальности данных, даже если указать валидный, но несуществующий ID/email пользователя - сервер все-равно вернет 200.

4) ✅ кеширование реферальных кодов с использованием in-memory БД.

Кешируется весь эндпоинт выдачи кодов по почте. Кешрование происходит с учетом параметра пути, то есть при сообщении значения, которое уже фигурировало ранее, будет взято значение из кеша, при сообщении нового - функция будет выполнена, и кеш будет создан.

5) Не писал Pytest, так как это бы сильно затянуло работу. Хорошие тесты более объемные, чем код, которые они тестируют. Ознакомиться с моими навыками Pytest можно на основании другого проекта, надо которым я занимался несколько недель:

```
https://github.com/TheSuncatcher222/foodgram/tree/master/backend/api/v1/tests
```

### Развертка

1) Загрузить актуальную версию проекта

```
git clone git@github.com:TheSuncatcher222/test_case_stakewolle.git
```

2) Перейти в папку app

```
cd test_case_stakewolle/app
```

3) Создать файл переменных окружения из примера

```
cp .env.example .env
```

4) Изменить переменные окружения (если необходимо, для тестов - не обязательно)
```
(на примере редактора Nano)
nano .env
```

5) Перейти в корневую папку проекта
```
cd ..
```

6) Запустить Docker (убедитесь, что `docker daemon` запущен в системе!)

```
docker-compose up --build -d
```

7) Проверить доступность проекта на `localhost:8000`

```
http://localhost:8000/api/docs
```
