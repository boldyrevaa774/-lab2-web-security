"""
Исправленная версия учебного веб-приложения.
SQL Injection устранена параметризованным SQL-запросом.
Reflected XSS устранена экранированием HTML.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import sqlite3
from html import escape

HOST = "127.0.0.1"
PORT = 8000
DB_NAME = "lab2.db"


def init_db():
    """Создаёт учебную базу и тестовую учётную запись."""
    with sqlite3.connect(DB_NAME) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        """)
        connection.execute(
            "INSERT OR IGNORE INTO users (id, username, password) "
            "VALUES (1, 'admin', 'admin123')"
        )


def page(content):
    """Общая HTML-оболочка страницы."""
    return f"""<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <title>Учебный сайт — лабораторная работа 2</title>
</head>
<body>
    <h1>Учебный сайт</h1>
    <p>Локальное приложение для изучения веб-безопасности.</p>
    {content}
    <hr>
    <a href="/">На главную</a>
</body>
</html>"""


class LabHandler(BaseHTTPRequestHandler):
    def send_html(self, content, status=200):
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/":
            content = """
            <h2>Вход</h2>
            <form method="post" action="/login">
                <label>Логин: <input name="username"></label><br>
                <label>Пароль: <input name="password" type="password"></label><br>
                <button type="submit">Войти</button>
            </form>

            <h2>Поиск</h2>
            <form method="get" action="/search">
                <label>Запрос: <input name="q"></label>
                <button type="submit">Искать</button>
            </form>
            """
            self.send_html(page(content))
            return

        if parsed.path == "/search":
            query = parse_qs(parsed.query).get("q", [""])[0]

            # ИСПРАВЛЕНИЕ XSS: экранируем специальные HTML-символы.
            safe_query = escape(query)
            content = f"<h2>Результаты поиска</h2><p>Вы искали: {safe_query}</p>"
            self.send_html(page(content))
            return

        self.send_html(page("<h2>Страница не найдена</h2>"), 404)

    def do_POST(self):
        if urlparse(self.path).path != "/login":
            self.send_html(page("<h2>Страница не найдена</h2>"), 404)
            return

        length = int(self.headers.get("Content-Length", "0"))
        form_data = self.rfile.read(length).decode("utf-8")
        values = parse_qs(form_data)
        username = values.get("username", [""])[0]
        password = values.get("password", [""])[0]

        # ИСПРАВЛЕНИЕ SQL Injection: используем параметры запроса.
        sql = "SELECT username FROM users WHERE username = ? AND password = ?"

        try:
            with sqlite3.connect(DB_NAME) as connection:
                result = connection.execute(sql, (username, password)).fetchone()
        except sqlite3.Error:
            result = None

        if result:
            self.send_html(page(f"<h2>Вход выполнен. Добро пожаловать, {result[0]}!</h2>"))
        else:
            self.send_html(page("<h2>Неверный логин или пароль.</h2>"), 401)

    def log_message(self, format, *args):
        # Оставляем стандартный журнал запросов в терминале.
        super().log_message(format, *args)


if __name__ == "__main__":
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), LabHandler)
    print(f"Сервер запущен: http://{HOST}:{PORT}")
    print("Для остановки нажмите Ctrl+C.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nСервер остановлен.")
        server.server_close()
