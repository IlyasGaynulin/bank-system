<#import "spring.ftl" as spring />
<@spring.bind "cabinet" />
<head>
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
        table {
            font-family: "Lucida Sans Unicode", "Lucida Grande", Sans-Serif;
            font-size: 14px;
            border-collapse: collapse;
            text-align: center;
        }
        th, td:first-child {
            background: #AFCDE7;
            color: white;
            padding: 10px 20px;
        }
        th, td {
            border-style: solid;
            border-width: 0 1px 1px 0;
            border-color: white;
        }
        td {
            background: #D8E6F3;
        }
        th:first-child, td:first-child {
            text-align: left;
        }
    </style>

    <header>
        <h1>Онлайн Банк</h1>
        <nav>
            <a href="/clients/${cabinet.client.login}/accounts">Счета</a>
            <a href="/clients/${cabinet.client.login}/transfer">Перевод</a>
            <a href="/clients/${cabinet.client.login}/logout">Выйти</a>
        </nav>
    </header>
</head>

<body>
<div style="background-color: #1d65e7">
    <p align=left width="1000" style="color:#feffe7">Владелец: ${cabinet.client.name}</p>
    <p align=left width="1000" style="color:#feffe7">Баланс: ${cabinet.balance} р.</p>
</div>
<div>
<h2 style="color:#000000">Добро пожаловать в личный кабинет!</h2>
<br>
<h3 style="color:#000000">История операций</h3>
<br>
    <table>
<#list cabinet.history as history>
    <tr><td>${history.message}</td></tr>
</#list>
    </table>
</div>
<br>
<br><br><br><br>
</body>