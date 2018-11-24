<#import "spring.ftl" as spring />
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
    </style>

    <header>
        <h1>Онлайн Банк</h1>
        <nav>
            <a href="/signup">Регистрация</a>
            <a href="/signin">Войти</a>
        </nav>
    </header>
</head>

<body>
<div>
    <br>
    <br>
<h2 style="color: #000000">Вы вышли из системы!</h2>
</div>
</body>