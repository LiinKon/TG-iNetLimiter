#!/usr/bin/env python3
"""
tg_limiter.py - локальный TCP-переадресатор с ограничением скорости СКАЧИВАНИЯ.

Схема:
    Telegram  ->  127.0.0.1:PORT (этот скрипт)  ->  твой MTProto-прокси

Скрипт ничего не знает про MTProto: он просто гонит байты в обе стороны и
притормаживает только поток "от прокси к Telegram" (то есть скачивание).
Секрет прокси остаётся в настройках Telegram, сюда его вводить НЕ нужно.

Запуск (пример):
    python tg_limiter.py --upstream proxy.example.com:443 --limit 1

Затем в Telegram Desktop: Настройки -> Продвинутые -> Тип соединения ->
Использовать прокси -> у своего MTProto-прокси замените сервер на 127.0.0.1
и порт на 18080 (или тот, что указали в --port). Секрет оставьте прежним.

Лимит можно менять на лету: введите число (МБ/с) в окне скрипта и нажмите Enter.
Остановка: Ctrl+C. После скачивания верните в Telegram прежний адрес прокси.

Требуется только Python 3.8+. Права администратора не нужны.
"""

import argparse
import asyncio
import sys
import threading
import time

CHUNK = 16 * 1024  # размер порции чтения


class Limiter:
    """Общий на все соединения ограничитель скорости (token bucket с долгом)."""

    def __init__(self, mb_per_s: float):
        self.set_rate(mb_per_s)
        self.tokens = self.capacity
        self.last = time.monotonic()
        self.lock = asyncio.Lock()
        self.total = 0  # всего байт скачано (для статистики)

    def set_rate(self, mb_per_s: float):
        self.rate = max(mb_per_s, 0.001) * 1024 * 1024  # байт/с
        self.capacity = max(self.rate * 0.25, 65536)  # допустимый "всплеск"

    async def consume(self, n: int):
        async with self.lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
            self.last = now
            self.tokens -= n
            self.total += n
            if self.tokens < 0:
                await asyncio.sleep(-self.tokens / self.rate)


async def pipe(reader, writer, limiter=None):
    try:
        while True:
            data = await reader.read(CHUNK)
            if not data:
                break
            if limiter is not None:
                await limiter.consume(len(data))
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle(client_r, client_w, upstream, limiter):
    try:
        up_r, up_w = await asyncio.wait_for(
            asyncio.open_connection(upstream[0], upstream[1]), timeout=15
        )
    except Exception as e:
        print(f"[!] Не удалось подключиться к прокси {upstream[0]}:{upstream[1]}: {e}")
        client_w.close()
        return

    # upload (Telegram -> прокси) не ограничиваем, download (прокси -> Telegram) ограничиваем
    t1 = asyncio.ensure_future(pipe(client_r, up_w))
    t2 = asyncio.ensure_future(pipe(up_r, client_w, limiter))
    await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
    for t in (t1, t2):
        t.cancel()
    for w in (client_w, up_w):
        try:
            w.close()
        except Exception:
            pass


async def reporter(limiter):
    last_total, last_t = 0, time.monotonic()
    while True:
        await asyncio.sleep(5)
        now = time.monotonic()
        speed = (limiter.total - last_total) / (now - last_t) / 1024 / 1024
        print(
            f"[инфо] скорость {speed:.2f} МБ/с | лимит {limiter.rate / 1024 / 1024:.2f} МБ/с"
            f" | скачано {limiter.total / 1024 / 1024:.0f} МБ"
        )
        last_total, last_t = limiter.total, now


def stdin_thread(loop, limiter):
    for line in sys.stdin:
        line = line.strip().replace(",", ".")
        if not line:
            continue
        try:
            v = float(line)
            if v <= 0:
                raise ValueError
        except ValueError:
            print("[!] Введите положительное число (МБ/с), например 1 или 0.5")
            continue
        loop.call_soon_threadsafe(limiter.set_rate, v)
        print(f"[ok] Новый лимит: {v} МБ/с")


async def main():
    ap = argparse.ArgumentParser(description="Ограничитель скорости скачивания для Telegram через прокси")
    ap.add_argument("--upstream", required=True, help="реальный прокси, host:port")
    ap.add_argument("--port", type=int, default=18080, help="локальный порт (по умолчанию 18080)")
    ap.add_argument("--limit", type=float, default=1.0, help="лимит скачивания, МБ/с (по умолчанию 1)")
    args = ap.parse_args()

    try:
        host, port = args.upstream.rsplit(":", 1)
        upstream = (host.strip("[]"), int(port))
    except ValueError:
        sys.exit("Ошибка: --upstream нужно указать как host:port")

    limiter = Limiter(args.limit)
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, upstream, limiter),
        host="127.0.0.1",  # только локально, снаружи недоступно
        port=args.port,
    )
    print(f"Слушаю 127.0.0.1:{args.port} -> {upstream[0]}:{upstream[1]}")
    print(f"Лимит скачивания: {args.limit} МБ/с (можно ввести другое число и нажать Enter)")
    print("В Telegram укажите сервер 127.0.0.1 и этот порт, секрет не меняйте. Стоп: Ctrl+C\n")

    if sys.stdin and sys.stdin.isatty():
        threading.Thread(
            target=stdin_thread, args=(asyncio.get_running_loop(), limiter), daemon=True
        ).start()

    asyncio.ensure_future(reporter(limiter))
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nОстановлено.")
