<#import "spring.ftl" as spring />
<@spring.bind "accounts" />
<head xmlns="http://www.w3.org/1999/html">
    <script language="javascript" type="text/javascript"
            src="http://code.jquery.com/jquery-2.1.1.min.js"></script>
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
            border-spacing: 0;
            empty-cells: hide;
        }
        td {
            padding: 10px 20px;
            text-align: center;
            border-bottom: 1px solid #F4EEE8;
            transition: all 0.5s linear;
        }
        td:first-child {
            text-align: left;
            color: #3D3511;
            font-weight: bold;
        }
        th {
            padding: 10px 20px;
            color: #3D3511;
            border-bottom: 1px solid #F4EEE8;
            border-top-left-radius: 10px;
            border-top-right-radius: 10px;
        }
        td:nth-child(even) {
            background: #F6D27E;
        }
        td:nth-child(odd) {
            background: #D1C7BF;
        }
        th:nth-child(even)  {
            background: #F6D27E;
        }
        th:nth-child(odd)  {
            background: #D1C7BF;
        }
        .round-top {
            border-top-left-radius: 5px;
        }
        .round-bottom {
            border-bottom-left-radius: 5px;
        }
        tr:hover td{
            background: #D1C7BF;
            font-weight: bold;
        }
    </style>

    <header>
        <h1> <a href="/clients/${accounts.client.login}">Онлайн Банк</a></h1>
        <nav>
            <a href="/clients/${accounts.client.login}/accounts">Счета</a>
            <a href="/clients/${accounts.client.login}/transfer">Перевод</a>
            <a href="/clients/${accounts.client.login}/logout">Выйти</a>
        </nav>

    </header>
</head>
<body>

<div style="background-color: #1d65e7">
    <p align=left width="1000" style="color:#feffe7">Владелец: ${accounts.client.name}</p>
    <p align=left width="1000" style="color:#feffe7">Баланс: ${accounts.balance} р.</p>
</div>
<div>
<br><br><br>
<h2 style="color:#000000">Ваши счета:</h2>
<br>
<script type="text/javascript">
    if (${accounts.count} == 0){
        document.write("<p>На вашем аккаунте нет счетов</p>");
</script>
    <table>
<#list accounts.accounts as account>
<tr width = "1000"><td align=left width="250">${account.name}</td><td align=right width="1000">${account.balance} р.</td></tr>
</#list>
    </table>

<br><br><br>
<h3 style="color:#000000">Добавить новый счёт</h3>
<br>
<input type="text" id="name" name="name" placeholder="Имя счёта..">
<br><br>
<button id="submit">Создать счёт</button>
<script type="text/javascript">
    $("#submit").click(function () {
        // объявили переменную, которая хранит введенные данные пользователя
        var json = {};
        // засунули данные в JSON
        json["name"] = $("#name").val();
                // создали запрос
        var xhr = new XMLHttpRequest();
        // открыли сессию для запроса
        // true - говорит, что запрос асинхронный
        xhr.open("POST", "/clients/${accounts.client.login}/accounts", true);
        // положили заголовки
        xhr.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
        // отправили JSON преобразовав его в строку
        xhr.send(JSON.stringify(json));
        // перенаправляем страничку
        window.location = "http://localhost:8080/clients/${accounts.client.login}";
    });

</script>
<br><br><br><br><br>
</div>
</body>