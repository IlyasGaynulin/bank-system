<#import "spring.ftl" as spring />
<script language="javascript" type="text/javascript"
        src="http://code.jquery.com/jquery-2.1.1.min.js"></script>
<head>
    <meta charset="UTF-8">
    <style>
        @import url(http://fonts.googleapis.com/css?family=Lato:400,700italic);
        * { padding: 0; margin: 0; }
        body { background: #1abc9c; font-family: 'Lato', sans-serif; text-transform: uppercase; letter-spacing: 1px;}

        header::after {
            content: '  ';
            display: inline-block;
            width: 100%;
        }
        header > div::before {
            content: '';
            height: 100%;
        }
        header {
            text-align: justify;
            letter-spacing: 1px;
            height: 8em;
            padding: 2em 10%;
            background: #2c3e50;
            color: #fff;
        }
        header h1,
        header nav {
            display: inline-block;
        }
        header::after {
            content: '';
            display: inline-block;
            width: 100%;
        }

        body {
            text-align: justify;
            letter-spacing: 5px;
            height: 5em;
            padding: 2em 3%;
            color: #fff;
        }


        a {
            color: #ffffff; /* Цвет обычной ссылки */
            text-decoration: none; /* Убираем подчеркивание у ссылок */
        }
        a:visited {
            color: #ffffff; /* Цвет посещённой ссылки */
        }
        a:hover {
            color: #dcd648; /* Цвет ссылки при наведении на нее курсора мыши */
            text-decoration: underline; /* Добавляем подчеркивание */
        }

        input[type=text], select {
            width: 50%;
            padding: 12px 20px;
            margin: 8px 0;
            display: inline-block;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-sizing: border-box;
        }

        input[type=password], select {
            width: 50%;
            padding: 12px 20px;
            margin: 8px 0;
            display: inline-block;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-sizing: border-box;
        }

        button {
            width: 50%;
            background-color: #4CAF50;
            color: white;
            padding: 14px 20px;
            margin: 8px 0;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }

        input[type=submit]:hover {
            background-color: #45a049;
        }

        div {
            border-radius: 5px;
            background-color: #f2f2f2;
            padding: 20px;
        }
    </style>

    <header>
        <h1>Онлайн Банк</h1>
        <nav>
            <a href="/signup">Регистрация</a>
            <a href="/signin">Войти</a>
        </nav>
    </header>
</head>
<div align="center">
    <br>
    <br>
    <input type="text" id="name" name="name" placeholder="Ваше имя..">
    <br>
    <br>
    <br>
    <input type="text" id="login" name="login" placeholder="Логин..">
    <br>
    <br>
    <br>
    <input type="text" id="age" name="age" placeholder="Возраст..">
    <br>
    <br>
    <br>
    <input type="password" id="password" name="password" placeholder="Пароль..">
    <br>
    <button id="submit">Регистрация</button>
</div>
<script type="text/javascript">
    $("#submit").click(function () {
        // объявили переменную, которая хранит введенные данные пользователя
        var json = {};
        // засунули данные в JSON
        json["name"] = $("#name").val();
        json["age"] = parseInt($("#age").val());
        json["login"] = $("#login").val();
        json["password"] = $("#password").val();

        // создали запрос
        var xhr = new XMLHttpRequest();
        // открыли сессию для запроса
        // true - говорит, что запрос асинхронный
        xhr.open("POST", "/clients", true);
        // положили заголовки
        xhr.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
        // отправили JSON преобразовав его в строку
        xhr.send(JSON.stringify(json));
        // перенаправляем страничку
        window.location = "http://localhost:8080/signin";
    });
</script>
</body>