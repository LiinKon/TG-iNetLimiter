#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tg_limiter_gui.py - окно в стиле Windows 11 для ограничения скорости СКАЧИВАНИЯ
в Telegram Desktop. Два режима (вкладки сверху):

  1) "Через прокси" - Telegram у вас уже работает через прокси (MTProto, SOCKS5...).
     Программа встаёт между ними:
         Telegram -> 127.0.0.1:ПОРТ (эта программа, лимит) -> ваш прокси

  2) "Без прокси" - прокси у вас нет. Программа сама работает как локальный
     SOCKS5-прокси и выходит в интернет напрямую (или через ваш VPN):
         Telegram -> 127.0.0.1:ПОРТ (эта программа, лимит) -> интернет

Как пользоваться:
  1. Выберите вкладку. Для первой впишите адрес вашего прокси (host:port); можно
     вставить ссылку tg://proxy?... - возьмутся только адрес и порт, секрет не
     читается и не сохраняется.
  2. Выберите лимит и нажмите "Запустить".
  3. В Telegram: Настройки -> Продвинутые -> Тип соединения.
     Вкладка 1: у своего прокси замените сервер на 127.0.0.1 и порт на указанный
     в окне, секрет/логин не меняйте.
     Вкладка 2: добавьте прокси типа SOCKS5: сервер 127.0.0.1, порт из окна,
     логин и пароль пустые.
  4. После скачивания нажмите "Остановить" и верните в Telegram прежние настройки.

Нужен только Python 3.8+ (tkinter входит в стандартную установку для Windows).
Права администратора и драйверы не нужны. Лимит можно менять во время загрузки.
"""

import asyncio
import base64
import json
import math
import os
import queue
import socket
import sys
import tempfile
import threading
import time
import traceback
import types
import tkinter as tk
from tkinter import font as tkfont
from urllib.parse import parse_qs, urlparse

CHUNK = 16 * 1024
MB = 1024 * 1024
APP_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
CFG_PATH = os.path.join(APP_DIR, "tg_limiter_gui.json")

SCALE = 1.0


def px(v):
    return int(round(v * SCALE))


# --------------------------------------------------------------------------- #
#  Движок: TCP-переадресатор с общим лимитом на скачивание
# --------------------------------------------------------------------------- #
class Limiter:
    """Общий для всех соединений ограничитель скорости (token bucket)."""

    def __init__(self, mbps):
        self.set_rate(mbps)
        self.tokens = self.capacity
        self.last = time.monotonic()
        self.lock = asyncio.Lock()
        self.total = 0  # всего байт прошло в сторону Telegram

    def set_rate(self, mbps):
        self.rate = max(float(mbps), 0.01) * MB
        self.capacity = max(self.rate * 0.25, 65536)

    async def consume(self, n):
        async with self.lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
            self.last = now
            self.tokens -= n
            self.total += n
            if self.tokens < 0:
                await asyncio.sleep(-self.tokens / self.rate)


class Engine:
    def __init__(self):
        self.loop = None
        self.thread = None
        self.server = None
        self.limiter = None
        self.writers = set()
        self.conns = 0
        self.last_err = ""
        self.running = False

    @property
    def total(self):
        return self.limiter.total if self.limiter else 0

    def start(self, upstream, port, mbps):
        """Возвращает None при успехе или текст ошибки."""
        ready = threading.Event()
        result = {"err": None}

        def run():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self.loop = loop
            try:
                self.limiter = Limiter(mbps)
                self.server = loop.run_until_complete(
                    asyncio.start_server(
                        lambda r, w: self._handle(r, w, upstream), host="127.0.0.1", port=port
                    )
                )
            except Exception as e:  # порт занят и т.п.
                result["err"] = e
                ready.set()
                loop.close()
                return
            ready.set()
            try:
                loop.run_forever()
            finally:
                try:
                    loop.run_until_complete(asyncio.sleep(0))
                    loop.close()
                except Exception:
                    pass

        self.writers.clear()
        self.conns = 0
        self.last_err = ""
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        ready.wait(5)
        if result["err"] is not None:
            e = result["err"]
            if getattr(e, "errno", None) in (98, 10048):
                return f"Порт {port} уже занят. Выберите другой локальный порт."
            return f"Не удалось запустить: {e}"
        self.running = True
        return None

    def stop(self):
        if not self.running or not self.loop:
            return

        async def shutdown():
            self.server.close()
            for w in list(self.writers):
                try:
                    w.close()
                except Exception:
                    pass
            for t in [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]:
                t.cancel()
            await asyncio.sleep(0)

        try:
            asyncio.run_coroutine_threadsafe(shutdown(), self.loop).result(3)
        except Exception:
            pass
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(3)
        self.running = False

    def set_rate(self, mbps):
        if self.running and self.limiter:
            self.loop.call_soon_threadsafe(self.limiter.set_rate, mbps)

    async def _pipe(self, reader, writer, limiter):
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

    async def _socks_open(self, cr, cw):
        """SOCKS5-рукопожатие (без авторизации, только CONNECT).
        Возвращает (reader, writer) к целевому серверу или None."""
        T = 10
        fail = b"\x00\x01\x00\x00\x00\x00\x00\x00"
        try:
            head = await asyncio.wait_for(cr.readexactly(2), T)
            if head[0] != 5:
                return None
            methods = await asyncio.wait_for(cr.readexactly(head[1]), T)
            if 0 not in methods:
                cw.write(b"\x05\xff")
                await cw.drain()
                return None
            cw.write(b"\x05\x00")
            await cw.drain()
            _ver, cmd, _rsv, atyp = await asyncio.wait_for(cr.readexactly(4), T)
            if atyp == 1:
                host = socket.inet_ntoa(await asyncio.wait_for(cr.readexactly(4), T))
            elif atyp == 3:
                n = (await asyncio.wait_for(cr.readexactly(1), T))[0]
                host = (await asyncio.wait_for(cr.readexactly(n), T)).decode("ascii", "ignore")
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, await asyncio.wait_for(cr.readexactly(16), T))
            else:
                cw.write(b"\x05\x08" + fail)
                await cw.drain()
                return None
            port = int.from_bytes(await asyncio.wait_for(cr.readexactly(2), T), "big")
            if cmd != 1:  # поддерживается только CONNECT (этого достаточно для загрузок)
                cw.write(b"\x05\x07" + fail)
                await cw.drain()
                return None
            try:
                ur, uw = await asyncio.wait_for(asyncio.open_connection(host, port), 15)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.last_err = f"Не удалось подключиться к {host}:{port}: {e}"
                cw.write(b"\x05\x04" + fail)
                await cw.drain()
                return None
            self.last_err = ""
            cw.write(b"\x05\x00" + fail)
            await cw.drain()
            return ur, uw
        except asyncio.CancelledError:
            raise
        except Exception:
            return None

    async def _handle(self, cr, cw, upstream):
        self.conns += 1
        self.writers.add(cw)
        uw = None
        try:
            if upstream is None:  # режим "Без прокси": мы сами SOCKS5-прокси
                pair = await self._socks_open(cr, cw)
                if pair is None:
                    return
                ur, uw = pair
            else:  # режим "Через прокси": просто пересылаем на ваш прокси
                try:
                    ur, uw = await asyncio.wait_for(
                        asyncio.open_connection(upstream[0], upstream[1]), 15
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    self.last_err = f"Нет связи с прокси: {e}"
                    return
                self.last_err = ""
            self.writers.add(uw)
            # отдача (Telegram -> сервер) без лимита, скачивание (сервер -> Telegram) с лимитом
            t1 = asyncio.ensure_future(self._pipe(cr, uw, None))
            t2 = asyncio.ensure_future(self._pipe(ur, cw, self.limiter))
            await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
            for t in (t1, t2):
                t.cancel()
        except asyncio.CancelledError:
            pass
        finally:
            for w in (cw, uw):
                if w is not None:
                    self.writers.discard(w)
                    try:
                        w.close()
                    except Exception:
                        pass
            self.conns -= 1

# --------------------------------------------------------------------------- #
#  Вспомогательное
# --------------------------------------------------------------------------- #
def parse_upstream(text):
    s = text.strip()
    if not s:
        raise ValueError("Укажите адрес вашего прокси в формате host:port")
    if "://" in s or s.lower().startswith("tg:"):
        q = parse_qs(urlparse(s).query)
        try:
            return q["server"][0].strip(), int(q["port"][0])
        except (KeyError, IndexError, ValueError):
            raise ValueError("В ссылке не нашёл server и port")
    if ":" not in s:
        raise ValueError("Адрес прокси нужно указать как host:port")
    host, port = s.rsplit(":", 1)
    host = host.strip().strip("[]")
    try:
        port = int(port)
    except ValueError:
        raise ValueError("Порт прокси должен быть числом")
    if not host or not (1 <= port <= 65535):
        raise ValueError("Проверьте адрес и порт прокси")
    return host, port


def fmt_num(v):
    return ("%.2f" % v).rstrip("0").rstrip(".")


def fmt_time(sec):
    sec = int(max(0, sec))
    if sec >= 3600:
        return f"{sec // 3600} ч {(sec % 3600) // 60} мин"
    if sec >= 60:
        return f"{max(1, round(sec / 60))} мин"
    return f"{sec} сек"


def fmt_size(nbytes):
    mb = nbytes / MB
    return f"{mb / 1024:.2f} ГБ" if mb >= 1024 else f"{mb:.0f} МБ"


def nice(v):
    step = 0.05 if v < 1 else (0.1 if v < 5 else 0.5)
    return max(0.1, round(v / step) * step)


def frac_of(v):
    v = min(10.0, max(0.1, v))
    return math.log(v / 0.1) / math.log(100)


def mix(a, b, t):
    """Смесь цветов: t от a, (1-t) от b."""
    ca = [int(a[i:i + 2], 16) for i in (1, 3, 5)]
    cb = [int(b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(int(x * t + y * (1 - t)) for x, y in zip(ca, cb))


def system_dark():
    try:
        import winreg

        k = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        )
        return winreg.QueryValueEx(k, "AppsUseLightTheme")[0] == 0
    except Exception:
        return True


class Theme:
    def __init__(self, dark):
        self.dark = dark
        if dark:
            self.bg, self.card, self.border = "#262626", "#2b2b2b", "#343434"
            self.text, self.sub, self.dim = "#ffffff", "#d0d0d0", "#9a9a9a"
            self.accent, self.accent_text = "#7B95FF", "#ffffff"
            self.ctrl, self.ctrl_hover, self.ctrl_press = "#373737", "#3e3e3e", "#323232"
            self.ctrl_border, self.ctrl_dis = "#464646", "#2f2f2f"
            self.input, self.input_dis, self.input_border = "#333333", "#2c2c2c", "#454545"
            self.line, self.track = "#7a7a7a", "#6b6b6b"
            self.ok, self.err, self.warn = "#6ccb5f", "#ff99a4", "#fce100"
        else:
            self.bg, self.card, self.border = "#f7f7f7", "#fbfbfb", "#ebebeb"
            self.text, self.sub, self.dim = "#1a1a1a", "#4a4a4a", "#707070"
            self.accent, self.accent_text = "#7B95FF", "#ffffff"
            self.ctrl, self.ctrl_hover, self.ctrl_press = "#fdfdfd", "#f6f6f6", "#f0f0f0"
            self.ctrl_border, self.ctrl_dis = "#dcdcdc", "#f5f5f5"
            self.input, self.input_dis, self.input_border = "#ffffff", "#f2f2f2", "#e0e0e0"
            self.line, self.track = "#8a8a8a", "#8a8a8a"
            self.ok, self.err, self.warn = "#0f7b0f", "#c42b1c", "#9d5d00"
        self.accent_hover = mix(self.accent, self.card, 0.85)
        self.accent_press = mix(self.accent, self.card, 0.70)
        self.accent_dim = mix(self.accent, self.card, 0.22)


def rrect(cv, x1, y1, x2, y2, r, **kw):
    """Прямоугольник с настоящими круглыми углами радиуса r (дуги из отрезков)."""
    r = max(0.0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))  # не больше половины стороны
    pts = []
    for cx, cy, a0 in ((x2 - r, y1 + r, -90), (x2 - r, y2 - r, 0),
                       (x1 + r, y2 - r, 90), (x1 + r, y1 + r, 180)):
        for i in range(0, 10):
            ang = math.radians(a0 + 90 * i / 9)
            pts += [cx + r * math.cos(ang), cy + r * math.sin(ang)]
    return cv.create_polygon(pts, **kw)


# --------------------------------------------------------------------------- #
#  Виджеты в духе Fluent / Windows 11
# --------------------------------------------------------------------------- #
class Card(tk.Canvas):
    """Скруглённая карточка. Содержимое кладём в self.body."""

    def __init__(self, parent, th, width, pad=14):
        self.th, self.pad = th, px(pad)
        # начальная высота должна быть больше отступа, иначе Tk не покажет содержимое
        super().__init__(parent, width=width, height=2 * self.pad + px(40), bg=th.bg,
                         highlightthickness=0, bd=0)
        self.body = tk.Frame(self, bg=th.card)
        self.win = self.create_window(self.pad, self.pad, window=self.body, anchor="nw")
        self.bind("<Configure>", self._redraw)
        self.body.bind("<Configure>", self._fit)

    def _fit(self, _e=None):
        self.configure(height=self.body.winfo_reqheight() + 2 * self.pad)

    def _redraw(self, e):
        self.delete("bg")
        rrect(self, 1, 1, e.width - 1, e.height - 1, px(20), fill=self.th.card,
              outline=self.th.border, tags="bg")
        self.tag_lower("bg")
        self.itemconfigure(self.win, width=max(10, e.width - 2 * self.pad))


class Btn(tk.Canvas):
    def __init__(self, parent, th, text, command, font, accent=False, w=80, h=34, bg=None, radius=20):
        super().__init__(parent, width=px(w), height=px(h), bg=bg or th.card,
                         highlightthickness=0, bd=0, cursor="hand2")
        self.th, self.text, self.command, self.font = th, text, command, font
        self.accent, self.enabled, self.state = accent, True, "n"
        self.radius = radius
        self.bind("<Configure>", lambda e: self.draw())
        self.bind("<Enter>", lambda e: self._set("h"))
        self.bind("<Leave>", lambda e: self._set("n"))
        self.bind("<ButtonPress-1>", lambda e: self._set("p"))
        self.bind("<ButtonRelease-1>", self._release)

    def _set(self, s):
        if self.enabled:
            self.state = s
            self.draw()

    def _release(self, e):
        if not self.enabled:
            return
        inside = 0 <= e.x <= self.winfo_width() and 0 <= e.y <= self.winfo_height()
        self._set("h" if inside else "n")
        if inside and self.command:
            self.command()

    def configure_btn(self, text=None, accent=None, enabled=None):
        if text is not None:
            self.text = text
        if accent is not None:
            self.accent = accent
        if enabled is not None:
            self.enabled = enabled
            self.configure(cursor="hand2" if enabled else "arrow")
            self.state = "n"
        self.draw()

    def draw(self):
        t = self.th
        self.delete("all")
        w = max(self.winfo_width(), 4)
        h = max(self.winfo_height(), 4)
        if not self.enabled:
            fill, outline, fg = t.ctrl_dis, t.ctrl_dis, t.dim
        elif self.accent:
            fill = {"n": t.accent, "h": t.accent_hover, "p": t.accent_press}[self.state]
            outline, fg = fill, t.accent_text
        else:
            fill = {"n": t.ctrl, "h": t.ctrl_hover, "p": t.ctrl_press}[self.state]
            outline, fg = t.ctrl_border, t.text
        rrect(self, 1, 1, w - 1, h - 1, px(self.radius), fill=fill, outline=outline)
        self.create_text(w // 2, h // 2, text=self.text, fill=fg, font=self.font)


class Slider(tk.Canvas):
    def __init__(self, parent, th, command, bg=None):
        super().__init__(parent, height=px(28), bg=bg or th.card, highlightthickness=0, bd=0,
                         cursor="hand2")
        self.th, self.command = th, command
        self.frac, self.hover, self.drag = 0.3, False, False
        self.pad = px(12)
        self.bind("<Configure>", lambda e: self.draw())
        self.bind("<Enter>", lambda e: self._h(True))
        self.bind("<Leave>", lambda e: self._h(False))
        self.bind("<ButtonPress-1>", self._press)
        self.bind("<B1-Motion>", self._move)
        self.bind("<ButtonRelease-1>", self._release)

    def _h(self, v):
        self.hover = v
        self.draw()

    def _x2f(self, x):
        w = max(self.winfo_width(), 2 * self.pad + 1)
        return min(1.0, max(0.0, (x - self.pad) / (w - 2 * self.pad)))

    def _press(self, e):
        self.drag = True
        self.frac = self._x2f(e.x)
        self.draw()
        self.command(self.frac)

    def _move(self, e):
        if self.drag:
            self.frac = self._x2f(e.x)
            self.draw()
            self.command(self.frac)

    def _release(self, _e):
        self.drag = False
        self.draw()

    def set_frac(self, f):
        self.frac = min(1.0, max(0.0, f))
        self.draw()

    def draw(self):
        t = self.th
        self.delete("all")
        w, h = max(self.winfo_width(), 2 * self.pad + 2), px(28)
        cy, x0, x1 = h // 2, self.pad, w - self.pad
        xv = x0 + (x1 - x0) * self.frac
        self.create_line(x0, cy, x1, cy, width=px(4), capstyle="round", fill=t.track)
        self.create_line(x0, cy, xv, cy, width=px(4), capstyle="round", fill=t.accent)
        ro = px(10)
        self.create_oval(xv - ro, cy - ro, xv + ro, cy + ro, fill=t.ctrl, outline=t.ctrl_border)
        ri = px(4) if self.drag else (px(6) if self.hover else px(5))
        self.create_oval(xv - ri, cy - ri, xv + ri, cy + ri, fill=t.accent, outline=t.accent)


class Field(tk.Canvas):
    """Поле ввода со скруглением 10 px; при фокусе рамка становится акцентной."""

    def __init__(self, parent, th, var, font, width=10, justify="left"):
        try:
            pbg = parent.cget("bg")
        except Exception:
            pbg = th.card
        super().__init__(parent, bg=pbg, highlightthickness=0, bd=0)
        self.th, self.focus, self.enabled = th, False, True
        self.entry = tk.Entry(
            self, textvariable=var, font=font, width=width, justify=justify, relief="flat", bd=0,
            highlightthickness=0, bg=th.input, fg=th.text, insertbackground=th.text,
            disabledbackground=th.input_dis, disabledforeground=th.dim,
            selectbackground=th.accent, selectforeground=th.accent_text,
        )
        self.padx = px(16)
        self.win = self.create_window(self.padx, 0, window=self.entry, anchor="w")
        self.configure(width=self.entry.winfo_reqwidth() + 2 * self.padx,
                       height=self.entry.winfo_reqheight() + px(16))
        self.entry.bind("<FocusIn>", lambda e: self._focus(True))
        self.entry.bind("<FocusOut>", lambda e: self._focus(False))
        self.bind("<Configure>", lambda e: self.draw())
        self.bind("<ButtonPress-1>", lambda e: self.entry.focus_set())

    def _focus(self, on):
        self.focus = on
        self.draw()

    def draw(self):
        t = self.th
        w, h = max(self.winfo_width(), 8), max(self.winfo_height(), 8)
        self.delete("bg")
        fill = t.input if self.enabled else t.input_dis
        outline = t.accent if self.focus else t.input_border
        rrect(self, 1, 1, w - 1, h - 1, px(20), fill=fill, outline=outline,
              width=2 if self.focus else 1, tags="bg")
        self.tag_lower("bg")
        self.coords(self.win, self.padx, h // 2)
        self.itemconfigure(self.win, width=max(4, w - 2 * self.padx))

    def set_enabled(self, on):
        self.enabled = on
        self.entry.configure(state="normal" if on else "disabled")
        self.draw()


class Tabs(tk.Canvas):
    """Вкладки в стиле Windows 11 (Pivot): текст и акцентная линия под выбранной."""

    def __init__(self, parent, th, labels, command, font, bg=None):
        super().__init__(parent, height=px(38), bg=bg or th.bg, highlightthickness=0, bd=0,
                         cursor="hand2")
        self.th, self.labels, self.command, self.font = th, labels, command, font
        self.sel, self.enabled, self.hover = 0, True, -1
        self.bind("<Configure>", lambda e: self.draw())
        self.bind("<Motion>", lambda e: self._set_hover(self._idx(e.x)))
        self.bind("<Leave>", lambda e: self._set_hover(-1))
        self.bind("<ButtonRelease-1>", self._click)

    def _idx(self, x):
        w = max(self.winfo_width(), 2)
        return min(len(self.labels) - 1, max(0, int(x * len(self.labels) / w)))

    def _set_hover(self, i):
        if i != self.hover:
            self.hover = i
            self.draw()

    def _click(self, e):
        i = self._idx(e.x)
        if self.enabled and i != self.sel:
            self.command(i)

    def set(self, i):
        self.sel = i
        self.draw()

    def set_enabled(self, on):
        self.enabled = on
        self.configure(cursor="hand2" if on else "arrow")
        self.draw()

    def draw(self):
        t = self.th
        self.delete("all")
        w, h, n = max(self.winfo_width(), 10), px(38), len(self.labels)
        self.create_line(0, h - 1, w, h - 1, fill=t.border)
        for i, lab in enumerate(self.labels):
            cx = (i + 0.5) * w / n
            if i == self.sel:
                fg = t.text
            elif self.enabled and i == self.hover:
                fg = t.sub
            else:
                fg = t.dim
            self.create_text(cx, h // 2 - px(2), text=lab, font=self.font, fill=fg)
            if i == self.sel:
                half = self.font.measure(lab) / 2 + px(6)
                self.create_line(cx - half, h - px(2), cx + half, h - px(2), width=px(3),
                                 capstyle="round", fill=t.accent)


class Spark(tk.Canvas):
    """График скорости. Едва заметная сетка плавно ползёт влево, пока идёт загрузка,
    а на конце линии горит "живая" точка: сразу видно, что программа не зависла."""

    STEP_T = 0.5  # секунд между отсчётами
    N = 90        # сколько отсчётов помещается в окно графика

    def __init__(self, parent, th, h=44):
        super().__init__(parent, height=px(h), bg=th.card, highlightthickness=0, bd=0)
        self.th = th
        self.samples, self.limit = [], 1.0
        self.n_total, self.t_last = 0, time.monotonic()
        self.bind("<Configure>", lambda e: self.draw())

    def update_data(self, samples, limit):
        self.samples, self.limit = samples, limit
        if samples:
            self.n_total += 1
            self.t_last = time.monotonic()
        else:
            self.n_total = 0
        self.draw()

    def draw(self):
        t = self.th
        self.delete("all")
        w, h = max(self.winfo_width(), 10), max(self.winfo_height(), 10)
        n = len(self.samples)
        step = w / (self.N - 1)
        shift = min(1.0, (time.monotonic() - self.t_last) / self.STEP_T) * step if n else 0.0
        x_start = w - step * (n - 1) if n else w

        # сетка: горизонтальные линии + вертикальные, которые едут влево вместе с графиком
        grid = mix(t.dim, t.card, 0.18)
        for k in (1, 2, 3):
            self.create_line(0, h * k / 4, w, h * k / 4, fill=grid)
        base = self.n_total - n
        for i in range(-self.N, self.N + 1):
            if (base + i) % 10 == 0:
                x = x_start + i * step - shift
                if 0 <= x <= w:
                    self.create_line(x, 0, x, h, fill=grid)

        top = max(self.limit * 1.3, (max(self.samples) if self.samples else 0) * 1.1, 0.2)
        ly = h - 2 - (h - 6) * min(1.0, self.limit / top)
        self.create_line(0, ly, w, ly, fill=t.dim, dash=(3, 4))
        if n >= 2:
            pts = []
            for i, v in enumerate(self.samples):
                pts += [x_start + i * step - shift, h - 2 - (h - 6) * min(1.0, v / top)]
            pts += [w, pts[-1]]  # дотягиваем линию до правого края
            self.create_polygon([pts[0], h] + pts + [pts[-2], h], fill=t.accent_dim, outline="")
            self.create_line(pts, fill=t.accent, width=px(2), joinstyle="round")
            r = px(3)
            col = t.accent if self.samples[-1] > 0.01 else t.dim
            self.create_oval(w - 2 * r, pts[-1] - r, w - 1, pts[-1] + r, fill=col, outline=col)

# --------------------------------------------------------------------------- #
#  Приложение
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
#  Значок в трее (только Windows; чистый ctypes, сторонние библиотеки не нужны)
# --------------------------------------------------------------------------- #
def ensure_icons():
    """Кладёт встроенные иконки во временную папку и возвращает пути к ним."""
    d = os.path.join(tempfile.gettempdir(), "tg_limiter_icons")
    out = {}
    try:
        os.makedirs(d, exist_ok=True)
        for key, b64 in (("on", ICON_ON_B64), ("off", ICON_OFF_B64), ("app", ICON_APP_B64)):
            path = os.path.join(d, key + ".ico")
            data = base64.b64decode(b64)
            if not os.path.exists(path) or os.path.getsize(path) != len(data):
                with open(path, "wb") as f:
                    f.write(data)
            out[key] = path
    except OSError:
        return None
    return out


def _make_structs(wchar, wndproc_type):
    """Структуры Win32 с фиксированным размером полей (одинаково на x86 и x64)."""
    import ctypes as c

    class NOTIFYICONDATAW(c.Structure):
        class GUID(c.Structure):
            _fields_ = [("Data1", c.c_uint32), ("Data2", c.c_uint16), ("Data3", c.c_uint16),
                        ("Data4", c.c_ubyte * 8)]

        _fields_ = [("cbSize", c.c_uint32), ("hWnd", c.c_void_p), ("uID", c.c_uint32),
                    ("uFlags", c.c_uint32), ("uCallbackMessage", c.c_uint32), ("hIcon", c.c_void_p),
                    ("szTip", wchar * 128), ("dwState", c.c_uint32), ("dwStateMask", c.c_uint32),
                    ("szInfo", wchar * 256), ("uVersion", c.c_uint32), ("szInfoTitle", wchar * 64),
                    ("dwInfoFlags", c.c_uint32), ("guidItem", GUID), ("hBalloonIcon", c.c_void_p)]

    class WNDCLASSW(c.Structure):
        _fields_ = [("style", c.c_uint32), ("lpfnWndProc", wndproc_type), ("cbClsExtra", c.c_int),
                    ("cbWndExtra", c.c_int), ("hInstance", c.c_void_p), ("hIcon", c.c_void_p),
                    ("hCursor", c.c_void_p), ("hbrBackground", c.c_void_p),
                    ("lpszMenuName", c.c_wchar_p), ("lpszClassName", c.c_wchar_p)]

    return NOTIFYICONDATAW, WNDCLASSW


def _load_win32():
    import ctypes
    from ctypes import wintypes

    w = types.SimpleNamespace()
    w.byref, w.sizeof = ctypes.byref, ctypes.sizeof
    w.user32 = ctypes.WinDLL("user32", use_last_error=True)
    w.shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    w.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    LRESULT = ctypes.c_ssize_t
    w.WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM,
                                   wintypes.LPARAM)
    w.NID, w.WNDCLASSW = _make_structs(ctypes.c_wchar, w.WNDPROC)
    w.POINT, w.MSG = wintypes.POINT, wintypes.MSG

    u, H = w.user32, wintypes
    u.RegisterClassW.argtypes, u.RegisterClassW.restype = [ctypes.POINTER(w.WNDCLASSW)], H.ATOM
    u.CreateWindowExW.argtypes = [H.DWORD, H.LPCWSTR, H.LPCWSTR, H.DWORD, ctypes.c_int, ctypes.c_int,
                                  ctypes.c_int, ctypes.c_int, H.HWND, H.HMENU, H.HINSTANCE, H.LPVOID]
    u.CreateWindowExW.restype = H.HWND
    u.DefWindowProcW.argtypes = [H.HWND, H.UINT, H.WPARAM, H.LPARAM]
    u.DefWindowProcW.restype = LRESULT
    u.PostMessageW.argtypes = [H.HWND, H.UINT, H.WPARAM, H.LPARAM]
    u.PostMessageW.restype = H.BOOL
    u.GetMessageW.argtypes = [ctypes.POINTER(H.MSG), H.HWND, H.UINT, H.UINT]
    u.GetMessageW.restype = ctypes.c_int
    u.TranslateMessage.argtypes = [ctypes.POINTER(H.MSG)]
    u.DispatchMessageW.argtypes = [ctypes.POINTER(H.MSG)]
    u.DispatchMessageW.restype = LRESULT
    u.PostQuitMessage.argtypes = [ctypes.c_int]
    u.DestroyWindow.argtypes = [H.HWND]
    u.CreatePopupMenu.restype = H.HMENU
    u.AppendMenuW.argtypes = [H.HMENU, H.UINT, ctypes.c_size_t, H.LPCWSTR]
    u.TrackPopupMenu.argtypes = [H.HMENU, H.UINT, ctypes.c_int, ctypes.c_int, ctypes.c_int, H.HWND,
                                 ctypes.c_void_p]
    u.TrackPopupMenu.restype = ctypes.c_int
    u.DestroyMenu.argtypes = [H.HMENU]
    u.GetCursorPos.argtypes = [ctypes.POINTER(H.POINT)]
    u.SetForegroundWindow.argtypes = [H.HWND]
    u.LoadImageW.argtypes = [H.HINSTANCE, H.LPCWSTR, H.UINT, ctypes.c_int, ctypes.c_int, H.UINT]
    u.LoadImageW.restype = H.HANDLE
    u.GetSystemMetrics.argtypes = [ctypes.c_int]
    u.RegisterWindowMessageW.argtypes, u.RegisterWindowMessageW.restype = [H.LPCWSTR], H.UINT
    w.shell32.Shell_NotifyIconW.argtypes = [H.DWORD, ctypes.POINTER(w.NID)]
    w.shell32.Shell_NotifyIconW.restype = H.BOOL
    w.kernel32.GetModuleHandleW.argtypes = [H.LPCWSTR]
    w.kernel32.GetModuleHandleW.restype = H.HMODULE
    return w


class Tray:
    """Значок в области уведомлений. Живёт в своём потоке со своим циклом сообщений.
    Наружу общается через очередь events: "click", "open", "toggle", "quit"."""

    WM_TRAY = 0x0400 + 20  # WM_USER + 20: сообщения от значка
    WM_CMD = 0x8000 + 1    # WM_APP + 1: команды от окна программы

    def __init__(self, icons):
        self.icons = icons
        self.events = queue.Queue()
        self._cmds = queue.Queue()
        self.ok, self.hwnd, self.w = False, None, None
        self._hicon = {}
        self._running, self._tip = False, ""
        self._last_click, self.taskbar_msg = 0.0, 0

    # ---- запуск ----
    def start(self):
        ready = threading.Event()
        self._thread = threading.Thread(target=self._run, args=(ready,), daemon=True)
        self._thread.start()
        ready.wait(5)
        return self.ok

    def _log(self):
        try:
            with open(os.path.join(APP_DIR, "tg_limiter_tray_error.log"), "a", encoding="utf-8") as f:
                f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + traceback.format_exc() + "\n")
        except Exception:
            pass

    def _run(self, ready):
        try:
            w = self.w = _load_win32()
            u = w.user32
            self._proc = w.WNDPROC(self._wndproc)  # ссылку нужно держать, иначе сборщик мусора её удалит
            hinst = w.kernel32.GetModuleHandleW(None)
            wc = w.WNDCLASSW()
            wc.lpfnWndProc, wc.hInstance, wc.lpszClassName = self._proc, hinst, "TgLimiterTrayWnd"
            if not u.RegisterClassW(w.byref(wc)):
                raise OSError("RegisterClassW не удалось")
            self.hwnd = u.CreateWindowExW(0, wc.lpszClassName, "TgLimiterTray", 0, 0, 0, 0, 0,
                                          None, None, hinst, None)
            if not self.hwnd:
                raise OSError("CreateWindowExW не удалось")
            self.taskbar_msg = u.RegisterWindowMessageW("TaskbarCreated")  # панель задач перезапущена
            size = u.GetSystemMetrics(49)  # SM_CXSMICON: размер значка в трее с учётом масштаба
            for key, path in self.icons.items():
                self._hicon[key] = u.LoadImageW(None, path, 1, size, size, 0x10)  # IMAGE_ICON, из файла
            if not self._hicon.get("off") or not self._hicon.get("on"):
                raise OSError("не удалось загрузить иконки")
            self._notify(0, 0x1 | 0x2 | 0x4)  # NIM_ADD: сообщения + иконка + подсказка
            self.ok = True
        except Exception:
            self._log()
            ready.set()
            return
        ready.set()
        try:
            msg = w.MSG()
            while u.GetMessageW(w.byref(msg), None, 0, 0) > 0:
                u.TranslateMessage(w.byref(msg))
                u.DispatchMessageW(w.byref(msg))
        except Exception:
            self._log()
        finally:
            self.ok = False

    # ---- работа со значком ----
    def _notify(self, action, flags, title=None, text=None):
        w = self.w
        nid = w.NID()
        nid.cbSize = w.sizeof(w.NID)
        nid.hWnd, nid.uID, nid.uFlags = self.hwnd, 1, flags
        nid.uCallbackMessage = self.WM_TRAY
        nid.hIcon = self._hicon.get("on" if self._running else "off")
        nid.szTip = (self._tip or "Лимитер скорости")[:127]
        if title is not None:
            nid.szInfoTitle, nid.szInfo = title[:63], (text or "")[:255]
            nid.dwInfoFlags = 0x1 | 0x10  # NIIF_INFO + NIIF_NOSOUND
        w.shell32.Shell_NotifyIconW(action, w.byref(nid))

    def _menu(self, hwnd):
        w = self.w
        u = w.user32
        pt = w.POINT()
        u.GetCursorPos(w.byref(pt))
        menu = u.CreatePopupMenu()
        u.AppendMenuW(menu, 0, 1, "Открыть окно")
        u.AppendMenuW(menu, 0, 2, "Остановить лимитер" if self._running else "Запустить лимитер")
        u.AppendMenuW(menu, 0x800, 0, None)  # разделитель
        u.AppendMenuW(menu, 0, 3, "Выход")
        u.SetForegroundWindow(hwnd)  # без этого меню не закрывается кликом мимо
        cmd = u.TrackPopupMenu(menu, 0x100 | 0x2, pt.x, pt.y, 0, hwnd, None)  # RETURNCMD | RIGHTBUTTON
        u.PostMessageW(hwnd, 0, 0, 0)  # WM_NULL
        u.DestroyMenu(menu)
        name = {1: "open", 2: "toggle", 3: "quit"}.get(cmd)
        if name:
            self.events.put(name)

    def _process(self):
        while True:
            try:
                cmd = self._cmds.get_nowait()
            except queue.Empty:
                return
            if cmd[0] == "state":
                self._running, self._tip = cmd[1], cmd[2]
                self._notify(1, 0x2 | 0x4)  # NIM_MODIFY: иконка + подсказка
            elif cmd[0] == "balloon":
                self._notify(1, 0x10, cmd[1], cmd[2])  # NIF_INFO: всплывающее уведомление
            elif cmd[0] == "quit":
                self._notify(2, 0)  # NIM_DELETE: убрать значок
                self.w.user32.DestroyWindow(self.hwnd)

    def _wndproc(self, hwnd, msg, wparam, lparam):
        u = self.w.user32
        try:
            if msg == self.WM_TRAY:
                ev = lparam & 0xFFFF
                if ev == 0x202:  # WM_LBUTTONUP (двойной клик даёт два подряд - гасим второй)
                    now = time.monotonic()
                    if now - self._last_click > 0.4:
                        self._last_click = now
                        self.events.put("click")
                elif ev == 0x205:  # WM_RBUTTONUP
                    self._menu(hwnd)
                return 0
            if msg == self.WM_CMD:
                self._process()
                return 0
            if self.taskbar_msg and msg == self.taskbar_msg:  # Проводник перезапустился: вернуть значок
                self._notify(0, 0x1 | 0x2 | 0x4)
                return 0
            if msg == 0x2:  # WM_DESTROY
                u.PostQuitMessage(0)
                return 0
        except Exception:
            self._log()
        return u.DefWindowProcW(hwnd, msg, wparam, lparam)

    # ---- команды из окна программы ----
    def _post(self, *cmd):
        if self.ok:
            self._cmds.put(cmd)
            self.w.user32.PostMessageW(self.hwnd, self.WM_CMD, 0, 0)

    def set_state(self, running, tip):
        self._post("state", running, tip)

    def balloon(self, title, text):
        self._post("balloon", title, text)

    def stop(self):
        if self.ok:
            self._post("quit")
            self._thread.join(2)


def set_app_identity(icon_path):
    """Имя программы в уведомлениях Windows: без этого там написано "Python".
    Задаём идентификатор приложения и записываем в раздел текущего пользователя
    (раздел HKCU, Software/Classes/AppUserModelId/TgLimiter.SpeedLimiter) отображаемое имя и значок."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        import winreg

        aumid = "TgLimiter.SpeedLimiter"
        k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\AppUserModelId" + "\\" + aumid)
        winreg.SetValueEx(k, "DisplayName", 0, winreg.REG_SZ, "Лимитер скорости")
        if icon_path:
            winreg.SetValueEx(k, "IconUri", 0, winreg.REG_SZ, icon_path)
        winreg.CloseKey(k)
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(aumid)
    except Exception:
        pass


def make_tray(icons):
    """Значок в трее (на Windows); если не получилось - None, программа работает и без него."""
    if sys.platform != "win32" or not icons:
        return None
    t = Tray(icons)
    return t if t.start() else None


class ThinScroll(tk.Canvas):
    """Тонкая полоса прокрутки (как оверлейная в Windows 11)."""

    def __init__(self, parent, th, target):
        super().__init__(parent, width=px(12), bg=th.bg, highlightthickness=0, bd=0)
        self.th, self.target = th, target
        self.lo, self.hi = 0.0, 1.0
        self.bind("<Configure>", lambda e: self.draw())
        self.bind("<ButtonPress-1>", self._drag)
        self.bind("<B1-Motion>", self._drag)

    def set(self, lo, hi):  # вызывается самим Text
        self.lo, self.hi = float(lo), float(hi)
        self.draw()

    def draw(self):
        self.delete("all")
        if self.hi - self.lo >= 0.999:
            return
        h = max(self.winfo_height(), 10)
        y0, y1 = self.lo * h + px(2), self.hi * h - px(2)
        x = self.winfo_width() // 2
        self.create_line(x, y0, x, max(y0, y1), width=px(4), capstyle="round", fill=self.th.dim)

    def _drag(self, e):
        h, span = max(self.winfo_height(), 1), self.hi - self.lo
        self.target.yview_moveto(min(max(e.y / h - span / 2, 0.0), max(0.0, 1.0 - span)))


HELP_TABS = ["Через прокси", "Без прокси", "Лимит и ошибки"]

# (вид, текст): h - заголовок, p - абзац, s - нумерованный шаг, b - пункт списка,
# code - схема, tbl - таблица, n - важное замечание
HELP = [
    [
        ("h", "Когда нужна эта вкладка"),
        ("p", "Telegram у вас уже работает через прокси (MTProto, SOCKS5 и т.п.). Программа встаёт "
              "между Telegram и вашим прокси и ограничивает скорость скачивания."),
        ("code", "Telegram → 127.0.0.1:порт (лимитер) → ваш прокси → интернет"),
        ("h", "Как пользоваться"),
        ("s", "Узнайте, какой прокси стоит в Telegram: Настройки → Продвинутые → Тип соединения. "
              "Запомните сервер и порт."),
        ("s", "В поле «Ваш прокси» впишите этот сервер и порт (host:port). Можно вставить ссылку "
              "tg://proxy?… — возьмутся только адрес и порт, секрет не читается и не сохраняется."),
        ("s", "«Локальный порт» оставьте 18080 (подойдёт любой свободный, но не такой, как у вашего "
              "прокси). Выберите лимит и нажмите «Запустить»."),
        ("s", "В Telegram у своего прокси замените сервер на 127.0.0.1, а порт на порт из окна. "
              "Тип, логин, пароль или секрет не трогайте."),
        ("s", "Качайте файл. Когда закончите, нажмите «Остановить» и верните в Telegram прежние "
              "адрес и порт прокси."),
        ("n", "Пока идёт загрузка, окно программы должно оставаться открытым, а ваш настоящий прокси "
              "(если это программа на этом компьютере) — запущенным."),
    ],
    [
        ("h", "Когда нужна эта вкладка"),
        ("p", "Прокси у вас нет: Telegram открывается напрямую или через VPN, включённый на всём "
              "компьютере. Программа сама работает как локальный SOCKS5-прокси и выходит в интернет "
              "напрямую."),
        ("code", "Telegram → 127.0.0.1:порт (лимитер) → интернет"),
        ("n", "Эта вкладка только ограничивает скорость. Блокировки она не обходит."),
        ("h", "Как пользоваться"),
        ("s", "Оставьте «Локальный порт» 18080, выберите лимит и нажмите «Запустить»."),
        ("s", "В Telegram: Настройки → Продвинутые → Тип соединения → Использовать прокси → "
              "Добавить прокси."),
        ("s", "Тип — SOCKS5, сервер — 127.0.0.1, порт — как в окне (по умолчанию 18080). Логин и "
              "пароль оставьте пустыми."),
        ("s", "«Использовать прокси для звонков» не включайте: звонки через лимитер не работают."),
        ("s", "Качайте файл. Когда закончите, нажмите «Остановить» и отключите этот прокси в Telegram."),
    ],
    [
        ("h", "Какой лимит поставить"),
        ("p", "Время загрузки = размер файла в МБ ÷ лимит. Для файла 4 ГБ:"),
        ("tbl", "0,5 МБ/с   около 2 ч 15 мин   очень незаметно\n"
                "1 МБ/с     около 1 ч 10 мин   вариант по умолчанию\n"
                "2 МБ/с     около 35 мин\n"
                "5 МБ/с     около 14 мин\n"
                "10 МБ/с    около 7 мин        заметно в слабой сети"),
        ("n", "Фактическая скорость обычно на 5–10% выше лимита. Лимит можно менять прямо во время "
              "загрузки."),
        ("h", "График"),
        ("p", "Линия светло-синего цвета — текущая скорость, пунктир — лимит. Тусклая сетка движется влево, пока "
              "программа работает: если она едет, программа не зависла, даже когда линия ровная."),
        ("h", "Значок в трее"),
        ("p", "Светло-синий значок с зелёной точкой — лимитер работает, серый — остановлен. Клик по значку "
              "показывает или прячет окно, правый клик открывает меню: открыть окно, запустить или "
              "остановить, выйти. При запуске и остановке появляется уведомление."),
        ("n", "Если закрыть окно, пока лимитер работает, он продолжит работать в трее. Чтобы выйти "
              "совсем, нажмите правой кнопкой по значку и выберите «Выход»."),
        ("h", "Если что-то не работает"),
        ("b", "«Порт уже занят» — впишите другой локальный порт (например, 18081) и поменяйте его же "
              "в Telegram."),
        ("b", "«Нет связи с прокси» — адрес прокси указан неверно или сам прокси не запущен. Проверьте, "
              "что адрес и порт такие же, как были в Telegram до замены."),
        ("b", "«Не удалось подключиться к…» на вкладке «Без прокси» — Telegram напрямую недоступен. "
              "Включите VPN на всём компьютере или используйте вкладку «Через прокси»."),
        ("b", "Telegram пишет «Подключение…» — проверьте, что статус зелёный и порт в Telegram совпадает "
              "с «Локальным портом». На вкладке «Без прокси» тип прокси должен быть именно SOCKS5."),
        ("b", "Скорость не падает до лимита — Telegram качает не через прокси. Убедитесь, что включён "
              "именно тот прокси, который указывает на 127.0.0.1 и порт из окна."),
        ("b", "Забыли вернуть прокси — Настройки → Продвинутые → Тип соединения, впишите прежние "
              "значения."),
    ],
]


class HelpWindow:
    """Окно справки: те же инструкции, что в README, но внутри приложения."""

    def __init__(self, app, tab):
        self.app, th = app, app.th
        self.win = win = tk.Toplevel(app.root)
        win.title("Справка")
        win.configure(bg=th.bg)
        win.transient(app.root)
        W, H = px(540), px(600)
        win.geometry(f"{W}x{H}+{app.root.winfo_rootx() + px(40)}+{app.root.winfo_rooty() + px(30)}")
        win.minsize(px(420), px(360))
        self.tabs = Tabs(win, th, HELP_TABS, self.show, app.f_semi)
        self.tabs.pack(fill="x", padx=px(16), pady=(px(14), px(4)))
        body = tk.Frame(win, bg=th.bg)
        body.pack(fill="both", expand=True, pady=(0, px(10)))
        self.text = tk.Text(
            body, wrap="word", bg=th.bg, fg=th.sub, font=app.f_body, relief="flat", bd=0,
            highlightthickness=0, padx=px(20), pady=px(6), cursor="arrow", insertwidth=0,
            selectbackground=th.accent, selectforeground=th.accent_text)
        sb = ThinScroll(body, th, self.text)
        self.text.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y", padx=(0, px(4)))
        self.text.pack(side="left", fill="both", expand=True)
        t = self.text
        t.tag_configure("h", font=app.f_h, foreground=th.text, spacing1=px(14), spacing3=px(5))
        t.tag_configure("p", spacing3=px(6))
        t.tag_configure("s", lmargin1=0, lmargin2=px(24), tabs=(px(24),), spacing3=px(7))
        t.tag_configure("b", lmargin1=px(4), lmargin2=px(22), tabs=(px(22),), spacing3=px(7))
        t.tag_configure("code", font=app.f_mono, foreground=th.text, background=th.ctrl,
                        lmargin1=px(10), lmargin2=px(10), spacing1=px(4), spacing3=px(10))
        t.tag_configure("tbl", font=app.f_mono, foreground=th.sub, lmargin1=px(4), lmargin2=px(4),
                        spacing3=px(8))
        t.tag_configure("n", font=app.f_small, foreground=th.dim, spacing3=px(8))
        win.bind("<Escape>", lambda e: win.destroy())
        self.show(tab)
        app._style_titlebar(win)

    def show(self, i):
        self.tabs.set(i)
        t = self.text
        t.configure(state="normal")
        t.delete("1.0", "end")
        n = 0
        for kind, txt in HELP[i]:
            if kind == "s":
                n += 1
                t.insert("end", f"{n}.\t{txt}\n", "s")
            elif kind == "b":
                t.insert("end", f"•\t{txt}\n", "b")
            elif kind == "n":
                t.insert("end", f"Важно: {txt}\n", "n")
            else:
                t.insert("end", txt + "\n", kind)
        t.configure(state="disabled")
        t.yview_moveto(0)


class App:
    def __init__(self):
        global SCALE
        if sys.platform == "win32":
            try:
                import ctypes

                try:
                    ctypes.windll.shcore.SetProcessDpiAwareness(1)
                except Exception:
                    ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass
        self.root = root = tk.Tk()
        root.withdraw()
        try:
            SCALE = max(1.0, root.winfo_fpixels("1i") / 96.0)
        except Exception:
            SCALE = 1.0
        self.th = th = Theme(system_dark())
        root.title("Лимитер скорости")
        root.configure(bg=th.bg)
        root.resizable(False, False)

        fams = set(tkfont.families(root))
        fam = next((f for f in ("Segoe UI Variable Text", "Segoe UI", "Noto Sans", "DejaVu Sans")
                    if f in fams), "TkDefaultFont")
        if "Segoe UI Semibold" in fams:
            semi, sw = "Segoe UI Semibold", "normal"  # как в Windows 11
        else:
            semi, sw = fam, "bold"
        self.f_body = tkfont.Font(family=fam, size=10)
        self.f_small = tkfont.Font(family=fam, size=9)
        self.f_semi = tkfont.Font(family=semi, size=10, weight=sw)
        self.f_big = tkfont.Font(family=semi, size=14, weight=sw)
        self.f_title = tkfont.Font(family=semi, size=17, weight=sw)
        self.f_h = tkfont.Font(family=semi, size=11, weight=sw)
        mono = next((f for f in ("Cascadia Mono", "Consolas", "DejaVu Sans Mono", "Courier New")
                     if f in fams), "TkFixedFont")
        self.f_mono = tkfont.Font(family=mono, size=9)

        cfg = {}
        try:
            with open(CFG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            pass
        self.v_up = tk.StringVar(value=cfg.get("upstream", ""))
        self.v_port = tk.StringVar(value=str(cfg.get("port", 18080)))
        self.v_lim = tk.StringVar(value=fmt_num(float(cfg.get("limit", 1.0))))
        self.v_size = tk.StringVar(value=str(cfg.get("size_gb", 4)))
        self.mode = 1 if cfg.get("mode") == 1 else 0  # 0 = через прокси, 1 = без прокси

        self.engine = Engine()
        self.help_win = None
        self._lock = False
        self.history, self.speed = [], 0.0
        self.last_total, self.last_t = 0, time.monotonic()

        self._build()
        self.v_lim.trace_add("write", self._on_limit_var)
        self.v_size.trace_add("write", lambda *_: self.update_eta())
        self.v_port.trace_add("write", lambda *_: self.update_hint())
        self.slider.set_frac(frac_of(self._limit() or 1.0))
        self._layout_mode()
        self.update_hint()
        self.update_eta()

        root.update_idletasks()
        for w in root.winfo_children():  # высота карточек по содержимому
            if isinstance(w, Card):
                w._fit()
        root.update_idletasks()
        W, H = root.winfo_reqwidth(), root.winfo_reqheight()
        sx, sy = root.winfo_screenwidth(), root.winfo_screenheight()
        # только позиция: размер окно подстроит само под содержимое
        root.geometry(f"+{max(0, (sx - W) // 2)}+{max(0, (sy - H) // 3)}")
        self._style_titlebar()
        self.icons = ensure_icons()
        set_app_identity(self.icons.get("app") if self.icons else None)
        self.tray, self._sig = make_tray(self.icons), None
        if self.icons:  # иконка окна и панели задач
            try:
                root.iconbitmap(default=self.icons["app"])
            except Exception:
                pass
        self._apply_state()
        root.after(150, self.poll_tray)
        self._fix_shortcuts()
        root.bind("<F1>", lambda e: self.open_help())
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.deiconify()
        root.after(500, self.tick)
        root.after(60, self.anim)

    # ---- сборка интерфейса ------------------------------------------------
    def _build(self):
        th, root = self.th, self.root
        P = px(16)
        CW = px(440) - 2 * P

        hdr = tk.Frame(root, bg=th.bg)
        hdr.pack(fill="x", padx=P, pady=(px(14), px(10)))
        tk.Label(hdr, text="Лимитер скорости", font=self.f_title, bg=th.bg, fg=th.text).pack(anchor="w")
        tk.Label(hdr, text="Ограничение скорости скачивания в Telegram", font=self.f_small,
                 bg=th.bg, fg=th.dim).pack(anchor="w")
        self.btn_help = Btn(hdr, th, "?", self.open_help, self.f_semi, w=32, h=32, radius=20, bg=th.bg)
        self.btn_help.place(relx=1.0, rely=0.0, anchor="ne", y=px(4))

        self.tabs = Tabs(root, th, ["Через прокси", "Без прокси"], self.set_mode, self.f_semi)
        self.tabs.set(self.mode)
        self.tabs.pack(fill="x", padx=P, pady=(0, px(10)))

        # --- Подключение
        c1 = Card(root, th, CW)
        c1.pack(fill="x", padx=P, pady=(0, px(10)))
        b = c1.body
        b.columnconfigure(0, weight=1)
        self.l_up = tk.Label(b, text="Ваш прокси (адрес:порт)", font=self.f_small, bg=th.card,
                             fg=th.sub)
        self.l_up.grid(row=0, column=0, sticky="w", pady=(0, px(4)))
        tk.Label(b, text="Локальный порт", font=self.f_small, bg=th.card,
                 fg=th.sub).grid(row=0, column=1, sticky="w", padx=(px(10), 0), pady=(0, px(4)))
        self.f_up = Field(b, th, self.v_up, self.f_body, width=20)
        self.f_up.grid(row=1, column=0, sticky="ew")
        self.f_port = Field(b, th, self.v_port, self.f_body, width=7)
        self.f_port.grid(row=1, column=1, sticky="ew", padx=(px(10), 0))
        self.l_direct = tk.Label(
            b, text="Telegram подключается к программе как к SOCKS5-прокси, а программа "
                    "выходит в интернет напрямую (или через ваш VPN).",
            font=self.f_small, bg=th.card, fg=th.sub, justify="left", anchor="nw",
            wraplength=CW - px(150))
        self.l_direct.grid(row=0, column=0, rowspan=2, sticky="nw")

        # --- Лимит
        c2 = Card(root, th, CW)
        c2.pack(fill="x", padx=P, pady=(0, px(10)))
        b = c2.body
        b.columnconfigure(0, weight=1)
        tk.Label(b, text="Лимит скачивания", font=self.f_semi, bg=th.card,
                 fg=th.text).grid(row=0, column=0, sticky="w")
        right = tk.Frame(b, bg=th.card)
        right.grid(row=0, column=1, sticky="e")
        self.f_lim = Field(right, th, self.v_lim, self.f_body, width=6, justify="center")
        self.f_lim.pack(side="left")
        tk.Label(right, text="МБ/с", font=self.f_body, bg=th.card, fg=th.sub).pack(side="left", padx=(px(6), 0))

        self.slider = Slider(b, th, self._on_slider)
        self.slider.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(px(8), px(2)))

        chips = tk.Frame(b, bg=th.card)
        chips.grid(row=2, column=0, columnspan=2, sticky="w", pady=(0, px(10)))
        for v in (0.5, 1, 2, 5, 10):
            Btn(chips, th, fmt_num(v), lambda v=v: self.v_lim.set(fmt_num(v)), self.f_small,
                w=52, h=28).pack(side="left", padx=(0, px(6)))

        frow = tk.Frame(b, bg=th.card)
        frow.grid(row=3, column=0, columnspan=2, sticky="ew")
        tk.Label(frow, text="Размер файла, ГБ", font=self.f_small, bg=th.card,
                 fg=th.sub).pack(side="left")
        self.f_size = Field(frow, th, self.v_size, self.f_body, width=5, justify="center")
        self.f_size.pack(side="left", padx=(px(8), px(10)))
        self.l_eta = tk.Label(frow, text="", font=self.f_small, bg=th.card, fg=th.sub)
        self.l_eta.pack(side="left")

        # --- Состояние
        c3 = Card(root, th, CW)
        c3.pack(fill="x", padx=P, pady=(0, px(10)))
        b = c3.body
        st = tk.Frame(b, bg=th.card)
        st.pack(fill="x")
        self.l_dot = tk.Label(st, text="●", font=self.f_small, bg=th.card, fg=th.dim)
        self.l_dot.pack(side="left")
        self.l_status = tk.Label(st, text="Остановлено", font=self.f_body, bg=th.card, fg=th.text,
                                 anchor="w", justify="left", wraplength=CW - px(60))
        self.l_status.pack(side="left", padx=(px(6), 0), fill="x")

        stats = tk.Frame(b, bg=th.card)
        stats.pack(fill="x", pady=(px(8), px(6)))
        for i in range(3):
            stats.columnconfigure(i, weight=1, uniform="s")
        self.s_speed = self._stat(stats, 0, "Скорость", "0 МБ/с")
        self.s_total = self._stat(stats, 1, "Скачано", "0 МБ")
        self.s_conn = self._stat(stats, 2, "Соединений", "0")

        self.spark = Spark(b, th)
        self.spark.pack(fill="x")

        # --- Кнопка и подсказка
        self.btn = Btn(root, th, "Запустить", self.toggle, self.f_semi, accent=True, h=40, bg=th.bg)
        self.btn.pack(fill="x", padx=P, pady=(0, px(8)))
        self.l_hint = tk.Label(root, text="", font=self.f_small, bg=th.bg, fg=th.dim, justify="left",
                               anchor="w", wraplength=CW)
        self.l_hint.pack(fill="x", padx=P, pady=(0, px(12)))

    def _stat(self, parent, col, caption, value):
        th = self.th
        f = tk.Frame(parent, bg=th.card)
        f.grid(row=0, column=col, sticky="w")
        tk.Label(f, text=caption, font=self.f_small, bg=th.card, fg=th.dim).pack(anchor="w")
        lbl = tk.Label(f, text=value, font=self.f_big, bg=th.card, fg=th.text)
        lbl.pack(anchor="w")
        return lbl

    # ---- оформление окна Windows 11 ---------------------------------------
    def _style_titlebar(self, win=None):
        if sys.platform != "win32":
            return
        win = win or self.root
        try:
            import ctypes

            win.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
            dwm = ctypes.windll.dwmapi

            def put(attr, val):
                v = ctypes.c_int(val)
                dwm.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(v), ctypes.sizeof(v))

            def cref(h):
                return int(h[1:3], 16) | int(h[3:5], 16) << 8 | int(h[5:7], 16) << 16

            put(20, 1 if self.th.dark else 0)  # тёмный/светлый заголовок
            put(33, 2)  # скруглённые углы окна
            put(35, cref(self.th.bg))  # цвет заголовка = фон окна (Windows 11)
            put(36, cref(self.th.text))  # цвет текста заголовка
            put(34, cref(self.th.bg))  # цвет рамки окна
        except Exception:
            pass

    def _fix_shortcuts(self):
        """Ctrl+C/V/X/A при русской раскладке (в tkinter по умолчанию не работают)."""
        if sys.platform != "win32":
            return

        def handler(e):
            w = e.widget
            if not isinstance(w, tk.Entry) or e.keysym.lower() in ("v", "c", "x", "a"):
                return
            k = e.keycode
            if k == 86:
                w.event_generate("<<Paste>>")
            elif k == 67:
                w.event_generate("<<Copy>>")
            elif k == 88:
                w.event_generate("<<Cut>>")
            elif k == 65:
                w.select_range(0, "end")
                w.icursor("end")
            else:
                return
            return "break"

        self.root.bind_all("<Control-KeyPress>", handler)

    # ---- логика -----------------------------------------------------------
    def _limit(self):
        try:
            v = float(self.v_lim.get().strip().replace(",", "."))
            return v if v > 0 else None
        except ValueError:
            return None

    def _size(self):
        try:
            v = float(self.v_size.get().strip().replace(",", "."))
            return v if v > 0 else None
        except ValueError:
            return None

    def _on_slider(self, frac):
        v = nice(0.1 * 100 ** frac)
        self._lock = True
        self.v_lim.set(fmt_num(v))
        self._lock = False
        self._apply(v)

    def _on_limit_var(self, *_):
        if self._lock:
            return
        v = self._limit()
        if v is None:
            return
        self._lock = True
        self.slider.set_frac(frac_of(v))
        self._lock = False
        self._apply(v)

    def _apply(self, v):
        self.engine.set_rate(v)
        self.update_eta()

    def update_eta(self):
        size, lim = self._size(), self._limit()
        if not size or not lim:
            self.l_eta.configure(text="")
            return
        full = size * 1024
        if self.engine.running and self.engine.total > 0:
            done = self.engine.total / MB
            if done >= full:
                self.l_eta.configure(text="объём достигнут")
            else:
                self.l_eta.configure(text=f"осталось ≈ {fmt_time((full - done) / lim)}")
        else:
            self.l_eta.configure(text=f"≈ {fmt_time(full / lim)} на весь файл")

    def update_hint(self):
        port = self.v_port.get().strip() or "…"
        if self.mode == 1:
            if self.engine.running:
                txt = (f"В Telegram: SOCKS5, сервер 127.0.0.1, порт {port}, без логина и пароля. "
                       "После загрузки отключите этот прокси.")
            else:
                txt = ("Запустите, затем в Telegram добавьте SOCKS5-прокси: сервер 127.0.0.1 и этот "
                       "порт, без логина и пароля.")
        elif self.engine.running:
            txt = (f"В Telegram: сервер 127.0.0.1, порт {port}, секрет прежний. "
                   "После загрузки верните прежний адрес прокси.")
        else:
            txt = "Запустите, затем в Telegram укажите сервер 127.0.0.1 и этот порт. Секрет не меняйте."
        self.l_hint.configure(text=txt)

    def set_status(self, text, kind="idle"):
        color = {"idle": self.th.dim, "ok": self.th.ok, "err": self.th.err, "warn": self.th.warn}[kind]
        self.l_dot.configure(fg=color)
        self.l_status.configure(text=text)
        if kind == "err":
            self.show_window(only_if_hidden=True)  # ошибку должно быть видно, даже если окно в трее

    def set_inputs(self, enabled):
        self.f_up.set_enabled(enabled)
        self.f_port.set_enabled(enabled)
        self.tabs.set_enabled(enabled)

    def _layout_mode(self):
        if self.mode == 1:
            self.l_up.grid_remove()
            self.f_up.grid_remove()
            self.l_direct.grid()
        else:
            self.l_direct.grid_remove()
            self.l_up.grid()
            self.f_up.grid()

    def set_mode(self, i):
        if self.engine.running or i == self.mode:
            return
        self.mode = i
        self.tabs.set(i)
        self._layout_mode()
        self.set_status("Остановлено", "idle")
        self.update_hint()
        self.save_cfg()

    def open_help(self):
        """Справка открывается на вкладке, соответствующей текущему режиму."""
        w = self.help_win
        if w is not None and w.win.winfo_exists():
            w.show(self.mode)
            w.win.lift()
            w.win.focus_force()
            return
        self.help_win = HelpWindow(self, self.mode)

    def anim(self):
        """Плавное движение сетки графика, пока идёт загрузка."""
        if self.engine.running:
            self.spark.draw()
        self.root.after(60, self.anim)

    def toggle(self):
        if self.engine.running:
            self.stop()
        else:
            self.start()

    def start(self):
        try:
            up = parse_upstream(self.v_up.get()) if self.mode == 0 else None
            try:
                port = int(self.v_port.get().strip())
                if not 1 <= port <= 65535:
                    raise ValueError
            except ValueError:
                raise ValueError("Локальный порт должен быть числом от 1 до 65535")
            if up and up[0].lower() in ("127.0.0.1", "localhost", "::1") and up[1] == port:
                raise ValueError("Адрес прокси совпадает с локальным портом. Выберите другой порт.")
            lim = self._limit()
            if lim is None:
                raise ValueError("Лимит должен быть положительным числом (МБ/с)")
        except ValueError as e:
            self.set_status(str(e), "err")
            return
        if up:
            self.v_up.set(f"{up[0]}:{up[1]}")  # если вставили ссылку - оставляем только адрес и порт
        err = self.engine.start(up, port, lim)
        if err:
            self.set_status(err, "err")
            return
        self.save_cfg()
        self.history, self.speed = [], 0.0
        self.last_total, self.last_t = 0, time.monotonic()
        self.set_inputs(False)
        self.btn.configure_btn(text="Остановить", accent=False)
        target = f"{up[0]}:{up[1]}" if up else "интернет"
        self.set_status(f"Работает · 127.0.0.1:{port} → {target}", "ok")
        self.update_hint()
        self.update_eta()
        self._apply_state()
        self._notify("Лимитер запущен",
                     f"Лимит {fmt_num(lim)} МБ/с. " + (
                         f"В Telegram замените порт прокси на {port}." if self.mode == 0 else
                         f"В Telegram добавьте SOCKS5-прокси 127.0.0.1:{port}."))

    def stop(self):
        self.engine.stop()
        self.set_inputs(True)
        self.btn.configure_btn(text="Запустить", accent=True)
        self.set_status("Остановлено. Верните прежний адрес прокси в Telegram." if self.mode == 0
                        else "Остановлено. Отключите прокси 127.0.0.1 в настройках Telegram.", "idle")
        self.s_speed.configure(text="0 МБ/с")
        self.s_conn.configure(text="0")
        self.history = []
        self.spark.update_data([], self._limit() or 1.0)
        self.update_hint()
        self.update_eta()
        self._apply_state()
        self._notify("Лимитер остановлен",
                     "Верните прежний адрес прокси в Telegram." if self.mode == 0
                     else "Отключите прокси 127.0.0.1 в настройках Telegram.")

    def tick(self):
        if self.engine.running:
            now = time.monotonic()
            dt = max(now - self.last_t, 1e-3)
            total = self.engine.total
            inst = (total - self.last_total) / MB / dt
            self.speed = 0.5 * self.speed + 0.5 * inst
            self.last_total, self.last_t = total, now
            self.history = (self.history + [self.speed])[-90:]
            self.s_speed.configure(text=f"{self.speed:.2f} МБ/с")
            self.s_total.configure(text=fmt_size(total))
            self.s_conn.configure(text=str(self.engine.conns))
            self.spark.update_data(self.history, self._limit() or 1.0)
            self.update_eta()
            if self.engine.last_err:
                self.set_status(self.engine.last_err, "warn")
            else:
                port = self.v_port.get().strip()
                target = self.v_up.get() if self.mode == 0 else "интернет"
                self.set_status(f"Работает · 127.0.0.1:{port} → {target}", "ok")
        self._apply_state()
        self.root.after(500, self.tick)

    def save_cfg(self):
        try:
            with open(CFG_PATH, "w", encoding="utf-8") as f:
                json.dump({
                    "upstream": self.v_up.get().strip(),
                    "port": self.v_port.get().strip(),
                    "limit": self._limit() or 1.0,
                    "size_gb": self._size() or 4,
                    "mode": self.mode,
                }, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    # ---- трей ----
    def _tip_text(self):
        if not self.engine.running:
            return "Лимитер: остановлен"
        return f"Лимитер: {self.speed:.1f} МБ/с (лимит {fmt_num(self._limit() or 0)} МБ/с)"

    def _apply_state(self):
        """Синхронизирует значок и подсказку в трее с состоянием (только если что-то изменилось)."""
        sig = (self.engine.running, self._tip_text())
        if self.tray is not None and sig != self._sig:
            self.tray.set_state(*sig)
        self._sig = sig

    def _notify(self, title, text):
        if self.tray is not None:
            self.tray.balloon(title, text)

    def show_window(self, only_if_hidden=False):
        r = self.root
        if only_if_hidden and r.state() == "normal":
            return
        r.deiconify()
        r.state("normal")
        r.lift()
        r.attributes("-topmost", True)  # чтобы окно реально вышло на передний план
        r.after(250, lambda: r.attributes("-topmost", False))
        r.focus_force()

    def toggle_window(self):
        if self.root.state() == "normal":
            self.root.withdraw()
        else:
            self.show_window()

    def poll_tray(self):
        t = self.tray
        if t is not None:
            try:
                while True:
                    ev = t.events.get_nowait()
                    if ev == "click":
                        self.toggle_window()
                    elif ev == "open":
                        self.show_window()
                    elif ev == "toggle":
                        self.toggle()
                    elif ev == "quit":
                        self.quit_app()
                        return
            except queue.Empty:
                pass
        self.root.after(150, self.poll_tray)

    def close(self):
        """Крестик: если лимитер работает и есть значок в трее - прячемся в трей, иначе выходим."""
        if self.tray is not None and self.engine.running:
            self.root.withdraw()
            self._notify("Лимитер работает в фоне",
                         "Клик по значку в трее открывает окно, правый клик - меню с выходом.")
            return
        self.quit_app()

    def quit_app(self):
        self.save_cfg()
        self.engine.stop()
        if self.tray is not None:
            self.tray.stop()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


# --- иконки значка в трее (ICO: 16/20/24/32/48 px), встроены, чтобы хватало одного файла ---
ICON_ON_B64 = (
    "AAABAAUAEBAAAAAAIAAoBAAAVgAAABQUAAAAACAAaAYAAH4EAAAYGAAAAAAgACgJAADmCgAAICAAAAAAIAAoEAAADhQAADAw"
    "AAAAACAAKCQAADYkAAAoAAAAEAAAACAAAAABACAAAAAAAAAEAADEDgAAxA4AAAAAAAAAAAAA/39/AgAAAAD/WzYO/4JeVP+E"
    "ZWr/gGFr/4Bha/+AYWv/gGFr/4Bha/+AYWv/g2Rr/4FgVf9mRA8AAAAA/39/AgAAAAD/kXMz/6WO2f/Nvv//z8D//8/A///P"
    "wP//0MH//9DB///PwP//z8D//8/A///Nvv//p47a/41xNgAAAAD/mYgP/5B03/+3oP///Pv7//z8/P/9/Pz////8//r5/P/6"
    "+fz////8//38/P/8/Pz//Pv7/7ei//+QdOL/n48Q/5Z9U/+cgf//knj8/5Z9//+Xfv//mYD//5J3//+nkf//p5L//5J3//+Z"
    "gP//l37//5d9//+SePz/nIH//5V7V/+Ue2n/nIH+/5R7/P+Uev//lnz//5B0//+chP//8u////Pw//+dhf//j3T//5Z8//+U"
    "ev//lHv8/5yB/v+Ve23/ln1m/5yB//+Ue/z/l33//5J3//+chP//7+v/////////////8Oz//52F//+Rdv//l33//5R7/P+c"
    "gf//l31q/5R7Z/+cgf//lnz8/5B1//+ZgP//6+b////////+/f///v3////////s5///moH//5B1//+VfPz/nIH//5Z7a/+U"
    "e2f/nYL//5N5/P+fh///8O3//////////////////////////////////vPv//2giP/9lHr8/52C//+We2v/lHtn/52C//+R"
    "d/z/qJP//72u//+zof//0MX/////////////0sf//rGc//+4qv//ppn//4tx/P6cgP//ln5r/5R7Z/+cgf//lHz8/5J3//+O"
    "dP//h2r//7Og/////////////rGd//+Sfv/pxKL/z8uW//bBrPz/nYf//JN0a/+WfWb/nIH//5R7/P+WfP//mH///5B1//+5"
    "p////////f/+///Buf/B2Jv/U9k+/0vPKf9l3lP87dOy//+Nemr/lHtp/5yB/v+Ue/z/lXv//5Z9//+Oc///uKX//v79///8"
    "/P/539T/ZtNF/03II/9azDP/QcgZ/KLjf/7/vcRt/5V8Uv+bgP//k3r8/5V7//+Wff//jnP//7qp//7/////////9+XY/2DQ"
    "Pf9Ryij/W801/0TIG/uY4nf//8/eVv+Rfw7/lXre/6CE//+Uevv/lXr9/5J4/P+givz/uqr8/Lml/P+uovyr35H8Q9An/UPK"
    "IPxl40b/09yv4P+v/xAAAAAA/5Z8Mf+agNb/m4D//5yA//+cgf//mn7//5V5//+Wef//lXn//7Kh/93aqP+52o7/6Ny42P+6"
    "yTQAAAAA/39/AgAAAAD/f2oM/5yCUP+Xfmf/lnpm/5d7Z/+ZgGf/mYBn/5mAZ/+Ja2b/kopn/6azUf8TTg0AAAAA/39/AigA"
    "AAAUAAAAKAAAAAEAIAAAAAAAQAYAAMQOAADEDgAAAAAAAAAAAAAAAAAA/39/AgAAAAD/AAAC/45wMv+OcET/imxE/4psRP+K"
    "bET/imxE/4psRP+KbET/imxE/4psRP+OcET/jG4z/1VVAwAAAAD/f38CAAAAAP9/fwIAAAAA/5F4SP+bgM3/oov7/6SM//+j"
    "jP//o4z//6OM//+jjP//o4z//6OM//+jjP//o4z//6OM//+ji/v/m4DP/5J3SwAAAAD/f38CAAAAAP+dg0T/lXj//9XI////"
    "///////+/////v////7////+/////v////7////+/////v////7////+///////Xyv//lnn//5uDSAAAAAD/mZkF/5d90f+Y"
    "fP//taT6/97W///d1f//3tb//97W///g2P//2tH//9rR///g2P//3tb//97W///d1f//3tb//7em+v+Xe///ln3V/5FtB/+X"
    "fC//lXr9/5V8/v+Qdf//j3P//49z//+Pc///kXb//4dq//+nkf//qJP//4dq//+Rdv//j3P//49z//+Pc///kHX//5V7/v+V"
    "e/7/mHo0/5d/QP+Xff//lXv//5Z8//+Wff//lnz//5h///+Qdf//p5L///v6///8+///qZP//5B1//+Yf///lnz//5Z9//+W"
    "fP//lHv+/5h+//+XfUX/lX0//5d9//+Ve///lXv//5V7//+Xff//kHT//6SO///28//////////////39f//pZD//490//+X"
    "fv//lXv//5V7//+Ue/7/mH7//5Z7RP+VfT//l33//5V7//+Ve///l33//5B1//+ii///9PH////////+/v///v7////////1"
    "8v//o43//5B0//+Xff//lXv//5R7/v+Yfv//lntE/5V9P/+Xff//lXv//5Z8//+Pc///nob///Dt/////////f3/////////"
    "/////f3///7+///x7v//n4j//45z//+WfP//lHv+/5h+//+We0T/lX0//5d9//+VfP//knj//6WP///39f//////////////"
    "///////////////////////////////6+P//qJL//5N5//+VfP7/mH7//5Z7RP+VfT//l33//5V8//+Sd///s6H//8W2///B"
    "sv//vq7//+rl/////////////+vm//+/sP/+wbH//b+t//+tmP/9jW///ZV7/v+Yf///lntE/5V9P/+Xff//lXv//5Z8//+Q"
    "df//jXH//490//+Gaf//187/////////////2tL//oVl//+OeP//qp7//7eo//+vpf//kXr+/5d7//+Zf0T/lX0//5d9//+V"
    "e///lXv//5Z8//+Xff//mH///5B1///b0v////////////7a0P//l4T/5N/C/4vjev9y21r/k+OB/+3Vvv7/moT/+5J0RP+V"
    "fT//l33//5V7//+Ve///lXv//5V7//+Wff//jnP//9rR///////+/////tfQ/+7Ntf9i3U7/RcYZ/0/JJ/9DxRf/b+Bf/vrM"
    "u///e11E/5d/QP+Xff//lXv//5V7//+Ve///lXv//5Z9//+Oc///2dD///79//z+/f//5er/tNuS/0bKIP9azTT/Vcww/1nM"
    "Mv9GyyL+z+Cq//+msUX/l3wv/5V6/f+Ve/7/lXv//5V7//+Ve///ln3//45y///e1v///////P/////t9P+s2ov/SMsi/1nN"
    "M/9UzC7/WM0z/0jLI/7C3qH+/6/NM/+ZZgX/lXrQ/52B//+Uevr/lXv//5V7//+WfP//kHb//8O1///c1P/93dX//sK4/+LX"
    "tv9R1Db/TMYg/1TKLP9FxRn6aeFM/+7dx9T/VaoGAAAAAP+VfUH/m4D+/52B//+Ve///lXv//5V7//+Ve///kXb//49z//+P"
    "dP/9jG///6eY/8nmtP9p21P/WtQ9/3vkYv/k6sH//8DHRQAAAAD/f38CAAAAAP+Se0T/mn/K/5d8+f+Xff//l33//5d9//+Y"
    "fv//mH7//5h+//+Zf///k3b//6GQ///Gtv/tz7T5/9DFy/+lqEcAAAAA////AgAAAAD/f38CAAAAAAAAAAD/m38u/5l9P/+V"
    "eT//lX0//5V9P/+VfT//lX0//5V5P/+ZgT/2iWU//3lZP/93bC8AAAABAAAAAP///wIAAAAAKAAAABgAAAAwAAAAAQAgAAAA"
    "AAAACQAAxA4AAMQOAAAAAAAAAAAAAAAAAAAAAAAA/39/AgAAAAAAAAAA/7adFf+sjiL/oIoj/6CKI/+giiP/oIoj/6CKI/+g"
    "iiP/oIoj/6CKI/+giiP/pY4i/6eKI/+tlhYAAAAAAAAAAP9/fwIAAAAAAAAAAAAAAAD/f38CAAAAAP+Ue0j/knW4/5F16f+Q"
    "dfT/j3P1/4909f+PdPX/j3T1/4909f+PdPX/j3T1/4909f+PdPX/j3P1/5B19P+Sder/knW6/5V6SwAAAAD/f38CAAAAAP//"
    "fwIAAAAA/5Z8d/+dgf//zLz//9/X///e1f//39b//9/W///f1v//39b//9/W///f1v//39b//9/W///f1v//39b//97V///g"
    "1///zb3//56C//+We3wAAAAA/39/AgAAAAD/mH1D/56C//+Xffz/+vn7/////v////7////+/////v////7////+/////v//"
    "//7////+/////v////7////+/////v////7/+/v8/5l++/+fg///mHtIAAAAAAAAAAD/lXu6/56D/v+Sd/v/q5f//8Gx///A"
    "sf//wbH//8Gy///Asf//wrP//7ys//+8rP//wrP//8Cx///Bsv//wbH//8Cx///Bsf//rJj//5J3+/+egv7/lXy/AAAAAP+b"
    "fxL/lXvq/5h9//+Ve/7/kXX//41y//+Ocv//jnL//41x//+QdP//hWf//7Cc//+xnv//hWf//5B0//+Ncv//jnL//45y//+N"
    "cv//kHX//5V7/v+Xff//lXvt/5Z/Fv+cex//lXvy/5d9//+Ve/7/lnz//5d9//+Xff//l33//5mA//+PdP//sp//////////"
    "////s6H//490//+ZgP//l33//5d9//+Xff//lnz//5V7/v+XfP//lXv1/5t4JP+Zfx7/lXvy/5d9//+Ve/7/lXv//5V7//+V"
    "e///l37//45y//+tmf//+/r///7+///+/v///Pv//7Cc//+Ocv//l37//5V7//+Ve///lXv//5V7/v+XfP//lXv1/5l7I/+Z"
    "fx7/lXvy/5d9//+Ve/7/lXv//5V7//+Xfv//jnP//6uW///6+f////////7+///+/v////////v6//+tmf//jnL//5d+//+V"
    "e///lXv//5V7/v+XfP//lXv1/5l7I/+Zfx7/lXvy/5d9//+Ve/7/lXv//5d+//+Pc///qZP///j3/////////v7/////////"
    "/////v7////////5+P//qpX//45z//+Xfv//lXv//5V7/v+XfP//lXv1/5l7I/+Zfx7/lXvy/5d9//+Ve/7/ln3//41x//+k"
    "jv//9fP///7+///8/P////////////////////////z8///+/f//9vT//6aQ//+Ncf//ln3//5V7/v+XfP//lXv1/5l7I/+Z"
    "fx7/lXvy/5d9//+VfP7/knf//6uW///9/P////////////////////////////////////////////////////////7+//+t"
    "mf//knj//5V8/v+XfP//lXv1/5l7I/+Zfx7/lXvy/5d9//+Ve/7/k3n//8Cw///Nwf//yr3//8q9///Owv//+/r/////////"
    "/////Pv//8/D///Kvv//zL///cy9//y9q//9knb//5Z9/v+Xff//lXv1/5l7I/+Zfx7/lXvy/5d9//+Ve/7/lXz//490//+N"
    "cf//jXP//4tv//+Uev//9vT/////////////9/b//5Z9//6Kbv//h2n//5J+//+dj///m4r//45y/v6Wev//lnz1/5l7I/+Z"
    "fx7/lXvy/5d9//+Ve/7/lXv//5Z8//+Xff//l37//5V7//+dhf//9/X/////////////+fj//52E//+Vff//zsb/1Oa7/7nl"
    "o//R5Lf//87F/v+Zgv/9k3f1/6CDI/+Zfx7/lXvy/5d9//+Ve/7/lXv//5V7//+Ve///lXz//5N5//+bg///9/X/////////"
    "///++fb//pqD//bYy/+F5nj/Sswl/0nKIv9KyyT/fuNw/vTg0f//lHz195F0I/+Zfx7/lXvy/5d9//+Ve/7/lXv//5V7//+V"
    "e///lXz//5N5//+bg///9/X////////////98ez//8G7/5vnjP9CxRX/WMwx/1fMMf9YzTL/QsMU/pXphv//wLn16V4kI/+c"
    "ex//lXvy/5d9//+Ve/7/lXv//5V7//+Ve///lXz//5N5//+bg///9/T////+//7//v//8e//+NzN/2TVSP9Ryin/Vcwv/1TM"
    "Lv9VzC//Usoq/mDXQ//z2cX1/2pcJP+lhxH/lXvp/5h9//+Ue/7/lXv//5V7//+Ve///lXz//5N5//+bg///+ff///////7/"
    "////9PP/9d7N/2HUQ/9Syir/Vcwv/1TMLv9VzC//Usor/l/XQP/t3cXt/2FhFQAAAAD/lXu4/56C/v+Vevv/lXv//5V7//+V"
    "e///lXz//5N5//+bgv//8e3///j3///59//96uT//8vF/4Xhcv9GxRr/Ws41/1bNMf9azjX/RcYZ+4rqcf7/2te9AAAAAAAA"
    "AAD/l3tA/56C//+We/3/lXr7/5R7/v+Ve/7/lXv+/5R6/v+Ve/7/nIT+/52F/v+dhf79m4H+/5qF/uTnzv5i2Ur+RcYa/knH"
    "IP5Dxxn7XthD/PL11f//tbhFAAAAAP//fwIAAAAA/5V7cv+egv//noL//5h9//+Xff//l33//5d9//+Xff//lXr//5V6//+V"
    "ev//lnz//5N2//+kk//y5ND/rOmY/5LlfP+x75r/9evU//+4tHcAAAAA////AgAAAAD/f38CAAAAAP+UfUP/m4Cz/5d95v+V"
    "e/L/lHvy/5V78v+Ve/L/lXzy/5V88v+VfPL/lXvy/5Z98v2RdPL/knvy/62l8v++tub/vLm1/5GDRgAAAAD///8CAAAAAAAA"
    "AAAAAAAA/1VVAwAAAAAAAAAA/5t/Ev+Zfx7/kHce/5l/Hv+Zfx7/mX8e/5l/Hv+Zfx7/mX8e/5B3Hv+hiB72mXce5WYzHuI4"
    "ABIAAAAAAAAAAP///wIAAAAAAAAAACgAAAAgAAAAQAAAAAEAIAAAAAAAABAAAMQOAADEDgAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAD/AAAB/6pVAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/qlUD//8AAQAAAAAAAAAAAAAAAAAAAAAAAAAA//8AAQAAAAAAAAAA/56CLf+Z"
    "fX7/lnuw/5Z7wP+UesD/k3nB/5N5wf+TecH/k3nB/5N5wf+TecH/k3nB/5N5wf+TecH/k3nB/5N5wf+TecH/lHrA/5Z7wP+X"
    "e7H/mX+A/52CLwAAAAAAAAAA////AQAAAAAAAAAAAAAAAP//AAEAAAAA/5FtB/+Zf5T/lXn9/6GF//+hh///oIX//6CF//+g"
    "hf//oIX//6CF//+ghf//oIX//6CF//+ghf//oIX//6CF//+ghf//oIX//6CF//+ghf//oIX//6GH//+hhf//lXn+/5t+mf+Z"
    "fwoAAAAA////AQAAAAD///8B/1VVA/+2kQf/mX65/5+B//+smP7/7Oj7//Lv/P/y7/z/8u/8//Lv/P/y7/z/8u/8//Lv/P/y"
    "7/z/8u/8//Lv/P/y7/z/8u/8//Lv/P/y7/z/8u/8//Lv/P/y7/z/8u/8/+3p+/+vnP3/noH//5h+wP+Zfwr/f38C////Af+q"
    "VQMAAAAA/5Z8kv+lif//jG/5/9jP/v//////////////////////////////////////////////////////////////////"
    "/////////////////////////////////////////9zU//+McPn/pIj//5V8mgAAAAD/qlUDAAAAAP+WfCf/mH39/5d9/P+R"
    "dv7/q5f//+nk///v7P//8Oz///Ds///w7P//8Oz///Ds///w7P//8O3///Ht///x7f//8O3///Ds///w7P//8Oz///Ds///w"
    "7P//8Oz//+/s///q5f//rZn//5F2/v+WfPz/mX7//5Z/LAAAAAAAAAAA/5V8e/+ghf//lXr7/5Z8//+Rdv//lHr//5d9//+W"
    "ff//l33//5d9//+Xff//ln3//5d9//+Xff//k3n//5N5//+Xff//l33//5Z9//+Xff//l33//5d9//+Wff//l33//5R6//+R"
    "dv//lnz//5V6+/+ghP//l32CAAAAAAAAAAD/lnut/56D//+Uevz/lXv//5Z8//+Ve///lHr//5R6//+Uev//lHr//5R6//+V"
    "e///lnz//4xv///NwP//z8T//4xw//+WfP//lXv//5R6//+Uev//lHr//5R6//+Uev//lXv//5Z8//+Ve///lHr8/56C//+W"
    "e7QAAAAAAAAAAP+Ve7r/noL//5R7/P+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXz//5d9//+Ncf//xrn/////////"
    "////ybz//41y//+Xff//lXz//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ue/z/nYH//5V6wQAAAAAAAAAA/5V7uv+e"
    "gv//lHv8/5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Xff//jXH//8O1/////////f3///39////////xrj//41x//+X"
    "ff//lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5R7/P+dgf//lXrBAAAAAAAAAAD/lXu6/56C//+Ue/z/lXv//5V7//+V"
    "e///lXv//5V7//+Ve///l33//41x///Asf////////79//////////////39////////w7X//41x//+Xff//lXv//5V7//+V"
    "e///lXv//5V7//+Ve///lHv8/52B//+VesEAAAAAAAAAAP+Ve7r/noL//5R7/P+Ve///lXv//5V7//+Ve///lXv//5d9//+N"
    "cf//va3////////+/v////////////////////////79////////wLH//41x//+Xff//lXv//5V7//+Ve///lXv//5V7//+U"
    "e/z/nYH//5V6wQAAAAAAAAAA/5V7uv+egv//lHv8/5V7//+Ve///lXv//5V7//+Xfv//jXH//7qq/////////v7/////////"
    "//////////////////////////7+////////va3//41x//+Xff//lXv//5V7//+Ve///lXv//5R7/P+dgf//lXrBAAAAAAAA"
    "AAD/lXu6/56C//+Ue/z/lXv//5V7//+Ve///l37//41x//+3pv////////7+/////v//////////////////////////////"
    "//////////7+////////uqr//41x//+Xfv//lXv//5V7//+Ve///lHv8/52B//+VesEAAAAAAAAAAP+Ve7r/noL//5R7/P+V"
    "e///lXv//5Z9//+Mb///s6D///38///9/P///fz///79///+/v/////////////////////////+///+/f///f3///38///+"
    "/f//tqT//4xv//+WfP//lXv//5V7//+Ue/z/nYH//5V6wQAAAAAAAAAA/5V7uv+egv//lHv8/5V7//+WfP//kXb//7in////"
    "////////////////////////////////////////////////////////////////////////////////////u6r//5F2//+W"
    "fP//lXv//5R7/P+dgf//lXrBAAAAAAAAAAD/lXu6/56C//+Ue/z/lXz//5N5//+dhf//2tD//93U///c0///3dT//93V///a"
    "0f//8/D////////+/v////7////////08f//29L//93V///d1P//3NT//97W///c1P//oIj//5R6//+WfP//lHv8/52B//+V"
    "esEAAAAAAAAAAP+Ve7r/noL//5R7/P+Ve///lXv//5Z8//+QdP//j3P//490//+Pc///kHb//4hr///Yzv////////39///+"
    "/f///////9vS//+JbP//kHb//5F1//6Ocf/8iGn//Ido//yOcP/9kXX//5Z8//+VfPz/nYH//5V6wQAAAAAAAAAA/5V7uv+e"
    "gv//lHv8/5V7//+Ve///lXv//5Z8//+Wff//ln3//5Z9//+Xf///j3X//9rS/////////f3///79////////3dT//5B2//+Y"
    "gP/9j3L//5uF//+2rv//w7///723//+llf/+j3H//5J4/P+egv//lXrBAAAAAAAAAAD/lXu6/56C//+Ue/z/lXv//5V7//+V"
    "e///lXv//5V7//+Ve///lXv//5Z9//+Oc///2tH////////9/f///v3////////d1P//kHX//pBz//+/tv/z7+H/ve+0/6Pq"
    "l/+u7KP/3fLR///Z1///mYH8/5p9//+WfcEAAAAAAAAAAP+Ve7r/noL//5R7/P+Ve///lXv//5V7//+Ve///lXv//5V7//+V"
    "e///ln3//45z///a0f////////39///+/f///////97W//6Iaf//ysT/zfnP/2DSQP9Ixx7/SMce/0jHHf9Oyif/m+qQ///s"
    "6/z/oIb//ZN5wQAAAAAAAAAA/5V7uv+egv//lHv8/5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Wff//jnP//9rR////"
    "/////f3///79///////92Mz//6aV/9763v9Syyv/Tskl/1jNMv9XzTH/V80y/1bMMP9CxBT/n+2Y/P/e2//7jGzBAAAAAAAA"
    "AAD/lXu6/56C//+Ue/z/lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5Z9//+Oc///2tH////////9/f///v3///////3V"
    "yf//09D/iOR5/0nHHv9YzTP/VMwu/1TMLv9UzC7/Vcwv/1TMLv9RzS789Pvj//+ikcEAAAAAAAAAAP+Ve7r/noL//5R7/P+V"
    "e///lXv//5V7//+Ve///lXv//5V7//+Ve///ln3//45z///a0f////////39///+/f/+/////9zV//jj1f9k1kj/Ucop/1XM"
    "L/9UzC7/VMwu/1TMLv9UzC7/V80x/0fIH/zO+L3//7y4wQAAAAAAAAAA/5V8rP+fg/7/lHr8/5V7//+Ve///lXv//5V7//+V"
    "e///lXv//5V7//+Wff//jnP//9nQ///+/f///Pv///37//7+/f//3Nb/9OTU/2DUQ/9Ryin/Vcwv/1TMLv9UzC7/VMwu/1TM"
    "Lv9XzTH/Rsge/Mn4t///w8OzAAAAAAAAAAD/ln14/6GF//+Vevv/lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5Z9//+O"
    "cv//3tb///////////////////////7b0v/+29X/dt1h/03IJP9WzTH/VMwu/1TMLv9UzC7/VMwu/1bNMf9JyiP76v/Y//+5"
    "tYAAAAAAAAAAAP+bfyT/l338/5Z8/P+Ve/7/lXv//5V7//+Ve///lXv//5V7//+Ve///lnz//5B2///Etf//3dX//9vT///c"
    "0///3tX//b6s//+6sv/A9bz/RcUY/1fNMf9XzTH/Vcww/1bMMP9ZzjT/RsYb/n3fZ/z/6uf++IVtKgAAAAD/qqoDAAAAAP+W"
    "eo3/o4f//5R6+f+Ve/7/lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5F2//+PdP//j3T//490//+PdP//kXb//ZJ3///k"
    "4/+c65P/R8Yb/0vIIf9OySb/Tckk/0XFGf5l10r5+v/z//+6sZQAAAAA////A///AAH/f38C/6p/Bv+YfbP/o4b//5V7//+U"
    "evv/lHr8/5R7/P+Ue/z/lHv8/5R7/P+Uevz/lXz8/5Z8/P+WfPz/lnz8/5V8/P+Wffz/knj8/Zh//P/h3/zF88D8geFw/GzZ"
    "U/xz3V77peuZ/v/+8P//v7W5vwAACP+qqgP//wABAAAAAP//AAEAAAAA/79/BP+Zf4z/mX75/6CF//+fg///noL//56C//+e"
    "gv//noL//56C//+egv//noL//56C//+egv//noL//52C//+eg///nH///5l8//++s///4Nz//+zi///q4///zMj7/6eRkdoA"
    "AAcBAQIA//8AAQAAAAAAAAAAAAAAAP8AAAEAAAAAAAAAAP+WfCf/m392/5h9qf+Ve7r/lHy5/5V7uv+Ve7r/lXu6/5V7uv+V"
    "e7r/lXu6/5V7uv+Ve7r/lXu6/5R7uv+VfLr/lXu6/IxuufyLbLr/kXaq/45uePJpNykAAAAAAAECAP8AAAEAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAP8AAAH/qlUDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP+qqgP/AAABAAAAAAAAAAAAAAAAKAAAADAAAABgAAAAAQAgAAAA"
    "AAAAJAAAxA4AAMQOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/AAAB/6qqA/+qVQMAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/6pVA/9/fwT/AAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAP9/fwIAAAAAAAAAAAAAAAD/spkK/5t/JP+cfDH/lnwx/5x8Mf+cfDH/nHwx/5x8Mf+c"
    "fDH/nHwx/5x8Mf+cfDH/nHwx/5x8Mf+cfDH/nHwx/5x8Mf+cfDH/nHwx/5x8Mf+cfDH/nHwx/5x8Mf+cfDH/lnwx/5x8Mf+e"
    "giX/qn8MAAAAAAAAAAAAAAAA/6pVAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/6qqAwAA"
    "AAD/f38E/5p/Vv+cga3/mYDj/5d9/P+agP//moD//5qA//+agP//moD//5qA//+agP//moD//5qA//+agP//moD//5qA//+a"
    "gP//moD//5qA//+agP//moD//5qA//+agP//moD//5qA//+agP//moD//5qA//+Xfvz/mX7l/5uAsf+bglr/kW0HAAAAAP+q"
    "qgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/qqoDAAAAAP+VfUH/m4DM/5+D//+Ye///kXX//45z//+N"
    "cv//jXL//41y//+Ncv//jXL//41y//+Ncv//jXL//41y//+Ncv//jXL//41y//+Ncv//jXL//41y//+Ncv//jXL//41y//+N"
    "cv//jXL//41y//+Ncv//jXL//41y//+Ocv//kXX//5h7//+fg///moDR/5Z9RwAAAAD/qlUDAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAP9/fwQAAAAA/5h+bf+agP7/m4D//5F3/P+xnfz/wLD9/76u/v+/r///v6///7+v//+/r///v6///7+v//+/"
    "r///v6///7+v//+/r///v6///7+v//+/r///v6///7+v//+/r///v6///7+v//+/r///v6///7+v//+/r///v6///7+v//++"
    "rv7/vq/+/7Of/P+Rd/z/mn///5yB//+YfHcAAAAA/6qqAwAAAAAAAAAAAAAAAAAAAAAAAAAA/6qqAwAAAAD/l31s/6CE//+X"
    "fP3/jnP8/8i7////////////////////////////////////////////////////////////////////////////////////"
    "///////////////////////////////////////////////////////////////////////////////NwP//j3P9/5Z9/P+h"
    "hf//lnx3AAAAAP+qqgMAAAAAAAAAAAAAAAD/VVUDAAAAAP+cfTn/mn/+/5Z8/P+Tef7/l37///Xy///9/f///Pv///38///9"
    "/P///fz///38///9/P///fz///38///9/P///fz///38///9/P///fz///38///9/P///fz///38///9/P///fz///38///9"
    "/P///fz///38///9/P///fz///38///9/P///Pv///38///49///moH//5N5/v+WfPv/nIH//5h9QwAAAAD/qlUDAAAAAP8A"
    "AAH/f38C/79/BP+Ve87/nIH//5R6/P+WfP//knf//+Xe////////////////////////////////////////////////////"
    "////////////////////////////////////////////////////////////////////////////////////////////////"
    "///////////////p5P//lHn//5V7//+Ue/z/moD//5V71/+ffwj///8B/wAAAf9/fwQAAAAA/5h9Tf+egv//lHr8/5V7//+W"
    "fP//knf//6KM///e1///7Oj//+zo///s6P//7Oj//+zo///s6P//7Oj//+zo///s6P//7Oj//+zo///t6P//7Oj//+3p///t"
    "6f//7Oj//+3o///s6P//7Oj//+zo///s6P//7Oj//+zo///s6P//7Oj//+zo///s6P//7Oj//+DY//+lj///knb//5Z8//+V"
    "e///k3r8/56D//+XflkAAAAA/39/BP+qVQMAAAAA/5d8qP+eg/7/lXr7/5V7//+Ve///lnz//5J3//+Qdf//lHr//5R6//+U"
    "ev//lHr//5R6//+Uev//lHr//5R6//+Uev//lHr//5R6//+Uev//lnz//5F3//+Rdv//lnz//5R6//+Uev//lHr//5R6//+U"
    "ev//lHr//5R6//+Uev//lHr//5R6//+Uev//lHv//5F2//+Sd///lnz//5V7//+Ve///lXr7/56C/v+XfbMAAAAA/1VVAwAA"
    "AAD/qn8G/5V83/+Zfv//lXr9/5V7//+Ve///lXv//5Z8//+WfP//lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+V"
    "e///lXv//5V7//+Xff//j3T//6aQ//+okv//j3P//5d9//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+V"
    "e///lXv//5Z8//+WfP//lXv//5V7//+Ve///lHr+/5h9//+We+f/oosLAAAAAAAAAAD/nnsd/5V79/+WfP//lXv+/5V7//+V"
    "e///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5d9//+Rdv//nob///Tx///2"
    "9P//oYr//5F1//+Xfv//lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+V"
    "e///lXv+/5V7//+Ve/3/k38mAAAAAAAAAAD/lnwn/5V7//+Ve///lXv+/5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+V"
    "e///lXv//5V7//+Ve///lXv//5V7//+Ve///l33//5F2//+chf//7+z/////////////8u///5+I//+Qdf//l33//5V7//+V"
    "e///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Yfv//nHwxAAAAAAAA"
    "AAD/lnwn/5V7//+Ve///lXv+/5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+X"
    "ff//kXf//5uD///s6P////////79///+/f///////+/s//+ehv//kXb//5d9//+Ve///lXv//5V7//+Ve///lXv//5V7//+V"
    "e///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Yfv//nHwxAAAAAAAAAAD/lnwn/5V7//+Ve///lXv+/5V7//+V"
    "e///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5Z9//+SeP//mYD//+rl/////////f3/////////"
    "/////f3////////u6v//nIP//5J3//+Wff//lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+V"
    "e///lXv//5V7//+Yfv//nHwxAAAAAAAAAAD/lnwn/5V7//+Ve///lXv+/5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+V"
    "e///lXv//5V7//+Ve///ln3//5N4//+Xfv//6OP////////9/f////////////////////////79////////7Of//5mB//+S"
    "d///l33//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Yfv//nHwxAAAAAAAA"
    "AAD/lnwn/5V7//+Ve///lXv+/5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+WfP//k3j//5Z9///l"
    "3/////////39///////////////////////////////////9/f///////+nk//+Zf///knj//5Z9//+Ve///lXv//5V7//+V"
    "e///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Yfv//nHwxAAAAAAAAAAD/lnwn/5V7//+Ve///lXv+/5V7//+V"
    "e///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5Z8//+Tef//lXv//+Pc/////////f3/////////////////////////"
    "/////////////////////f3////////m4P//ln3//5N4//+Wff//lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+V"
    "e///lXv//5V7//+Yfv//nHwxAAAAAAAAAAD/lnwn/5V7//+Ve///lXv+/5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+V"
    "e///lnz//5R6//+TeP//4dn////////9/f////////////////////////////////////////////////////////39////"
    "////5N7//5V6//+Tef//lnz//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Yfv//nHwxAAAAAAAA"
    "AAD/lnwn/5V7//+Ve///lXv+/5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+WfP//lHr//5J4///e1v////////39////"
    "///////////////////////////////////////////////////////////////9/f///////+Lb//+Uev//lHn//5Z8//+V"
    "e///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Yfv//nHwxAAAAAAAAAAD/lnwn/5V7//+Ve///lXv+/5V7//+V"
    "e///lXv//5V7//+Ve///lXv//5Z8//+Vev//kXf//9vS/////////f3/////////////////////////////////////////"
    "/////////////////////////////////////f3////////f1///k3n//5R6//+WfP//lXv//5V7//+Ve///lXv//5V7//+V"
    "e///lXv//5V7//+Yfv//nHwxAAAAAAAAAAD/lnwn/5V7//+Ve///lXv+/5V7//+Ve///lXv//5V7//+Ve///lnz//5V7//+Q"
    "df//2M/////////9/f//////////////////////////////////////////////////////////////////////////////"
    "//////////39////////3NT//5F2//+Ve///lnz//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Yfv//nHwxAAAAAAAA"
    "AAD/lnwn/5V7//+Ve///lXv+/5V7//+Ve///lXv//5V7//+WfP//lXv//49z///Vy/////////38/////v////7////+////"
    "/v////7///////////////////////////////////////////////7////+/////v////7////+///8/P///////9nR//+Q"
    "df//lXr//5Z8//+Ve///lXv//5V7//+Ve///lXv//5V7//+Yfv//nHwxAAAAAAAAAAD/lnwn/5V7//+Ve///lXv+/5V7//+V"
    "e///lXv//5V7//+Ve///kXX//9TJ////////////////////////////////////////////////////////////////////"
    "///////////////////////////////////////////////////////////////Yzv//knf//5V6//+Ve///lXv//5V7//+V"
    "e///lXv//5V7//+Yfv//nHwxAAAAAAAAAAD/lnwn/5V7//+Ve///lXv+/5V7//+Ve///lXv//5Z8//+Rdv//ybz///38///3"
    "9f//+Pf///n3///49///+Pf///j3///49///+ff////+////////////////////////////////////////+fj///j3///5"
    "9///+Pf///j3///49///+Pf///b0///9/P//zcH//5J3//+WfP//lXv//5V7//+Ve///lXv//5V7//+Yfv//nHwxAAAAAAAA"
    "AAD/lnwn/5V7//+Ve///lXv+/5V7//+Ve///lXv//5V7//+WfP//oYr//52F//+ehv//nob//56G//+ehv//nob//56H//+c"
    "hP//o4z///f1/////////v7///////////////7////////5+P//ppD//5yD//+fh///nob//56G//+ehv//nob//56G//+e"
    "hv//oov//5d9//+Ve///lXv//5V7//+Ve///lXv//5V7//+Yfv//nHwxAAAAAAAAAAD/lnwn/5V7//+Ve///lXv+/5V7//+V"
    "e///lXv//5V7//+Ve///knf//5N4//+TeP//k3j//5N4//+TeP//k3j//5N5//+Rdv//mX////b0/////////v7/////////"
    "//////7////////49///nIT//5F1//+Uef//k3j//5N4//+Uev//lHr//5J3//+QdP//j3P//5N5//+WfP//ln3//5V7//+V"
    "e///lXv//5V7//+Yfv//nHwxAAAAAAAAAAD/lnwn/5V7//+Ve///lXv+/5V7//+Ve///lXv//5V7//+Ve///lXz//5Z8//+W"
    "fP//lnz//5Z8//+WfP//lnz//5Z9//+Uev//nIP///b0/////////v7///////////////7////////49///nof//5R5//+W"
    "ff//ln3//5Z8//+PdP/9j3L//Zl+//6ji//+o4z//Zp///2Pcv/+jnL//5V7//+WfP//lXv//5V7//+Yfv//nHwxAAAAAAAA"
    "AAD/lnwn/5V7//+Ve///lXv+/5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V8//+T"
    "ef//m4L///b0/////////v7///////////////7////////49///nob//5N4//+Xff//knj//pF1//+1o///4OH///f+///+"
    "/////v////j////j5v//uqr//ZN3//+Rdv//ln3//5V7//+Yfv//nHwxAAAAAAAAAAD/lnwn/5V7//+Ve///lXv+/5V7//+V"
    "e///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V8//+Tef//m4L///b0/////////v7/////////"
    "//////7////////49///nob//5R6//+Rd//9nYT//+Lf//7////G9MD/kuF9/3vYXv962F3/j+B4/7/xuP/5/////+jo//2j"
    "i///kHX//5Z9//+Yfv//nHwxAAAAAAAAAAD/lnwn/5V7//+Ve///lXv+/5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+V"
    "e///lXv//5V7//+Ve///lXv//5V8//+Tef//m4L///b0/////////v7///////////////7////////49///n4f//5B1//2f"
    "hv//8vP/3/vf/3PUUv9Jxx//Scgg/0zJJP9MyST/Scgg/0nHHv9q0Uf/1PbQ///5/P/9pY7//5B1//+af///nHwxAAAAAAAA"
    "AAD/lnwn/5V7//+Ve///lXv+/5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V8//+T"
    "ef//m4L///b0/////////v7///////////////7////////59///nob//ZF0///q6P/c+dv/Wcsx/0vJI/9XzTL/V80x/1bN"
    "MP9WzTD/Vs0x/1fNMv9Nyib/UMkn/8/0yf//8vP//Zd8//+XfP//nIIxAAAAAAAAAAD/lnwn/5V7//+Ve///lXv+/5V7//+V"
    "e///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V8//+Tef//m4L///b0/////////v7/////////"
    "//////7////////6+f/+lnz//r6v//b//f9q0Uf/TMok/1jNMv9UzC7/VMwu/1TMLv9UzC7/VMwu/1TMLv9XzTL/T8so/13N"
    "N//t//L//szD//+Rc///oYcxAAAAAAAAAAD/lnwn/5V7//+Ve///lXv+/5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+V"
    "e///lXv//5V7//+Ve///lXv//5V8//+Tef//m4L///b0/////////v7///////////////7////////59//8m4H//+3y/7Tu"
    "qf9Hxxz/WM0z/1TMLv9UzC7/VMwu/1TMLv9UzC7/VMwu/1TMLv9UzC7/WM0y/0fHHf+h5Y////f9//+bf///lncxAAAAAAAA"
    "AAD/lnwn/5V7//+Ve///lXv+/5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V8//+T"
    "ef//m4L///b0/////////v7///////////////7////////18v/+rZj///3//3rYXv9MyST/Vs0w/1TMLv9UzC7/VMwu/1TM"
    "Lv9UzC7/VMwu/1TMLv9UzC7/Vcwv/0/KKP9r0kr/+//9//+ynv//fFgxAAAAAAAAAAD/lnwn/5V7//+Ve///lXv+/5V7//+V"
    "e///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V8//+Tef//m4L///b0/////////v7/////////"
    "//////7///////7z7///vK7/9//3/2PQQP9Qyyn/Vcwv/1TMLv9UzC7/VMwu/1TMLv9UzC7/VMwu/1TMLv9UzC7/Vcwv/1PM"
    "LP9YzDL/6v/u///Dt//5ckgxAAAAAAAAAAD/mn8c/5Z89v+WfP//lXv+/5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+V"
    "e///lXv//5V7//+Ve///lXv//5V8//+Tef//m4L///b0/////////v7///////////////7///////7y7v//wLP/8//0/2DP"
    "O/9Ryyr/Vcwv/1TMLv9UzC7/VMwu/1TMLv9UzC7/VMwu/1TMLv9UzC7/VMwu/1PMLf9Vyi3+5v/o///Eu/zxYDAlAAAAAAAA"
    "AAD/mZkF/5Z83f+af///lXr9/5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V8//+T"
    "ef//m4L///bz/////v///v3////+/////v////3////+///z8P//tqX/+//8/2vTSv9Pyij/Vcwv/1TMLv9UzC7/VMwu/1TM"
    "Lv9UzC7/VMwu/1TMLv9UzC7/Vcwv/1LLK/9dzTn++P74//++r+XlMwAKAAAAAP+qqgMAAAAA/5V9pf+fg/7/lXr7/5V7//+V"
    "e///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V8//+Tef//m4L///f2////////////////////"
    "///////////////49//9pIz///n//5LhfP9JyCD/V80x/1TMLv9UzC7/VMwu/1TMLv9UzC7/VMwu/1TMLv9UzC7/Vs0x/0vJ"
    "I/9922P7/////vyslbAAAAAA////A/+qqgMAAAAA/5h/SP+dgv//lHr8/5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+V"
    "e///lXv//5V7//+Ve///lXv//5V8//+Tef//m4L///Dt///59///+Pb///j3///49///+Pb///n3///08f/9lnv//9rX/9n5"
    "2P9NyCP/Vs0w/1TMLv9UzC7/VMwu/1TMLv9UzC7/VMwu/1TMLv9UzC7/V80y/0jHHf/I88L8//Dw//WIZFQAAAAA/39/BP8A"
    "AAH/f38C/6pVA/+We8j/nYH//5R6/P+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+V"
    "e///lnz//52F//+ehv//nob//56G//+ehv//nob//56G//+ehv//knf//aaO//////+f4or/Q8YZ/1fNMv9WzTD/VMwu/1TM"
    "Lv9UzC7/VMwu/1XMMP9YzTP/Rcca/4zcc/z//////baj0v8AAAb///8B/wAAAQAAAAD/f38CAAAAAP+bfTP/mn77/5d8/f+V"
    "ev3/lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5N5//+TeP//k3j//5N4//+T"
    "eP//k3j//5N4//+TeP//ln3//45y//3Etf/+////ld58/0fHHf9Nyib/VMwu/1bNMP9WzTD/Vcwv/0/KJ/9Gxxz/h9lp/fj/"
    "//z91Mf//39ZPAAAAAD/qlUDAAAAAAAAAAAAAAAA/6pVAwAAAAD/lXtj/56D//+We/7/lHr8/5V7//+Ve///lXv//5V7//+V"
    "e///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5Z8//+WfP//lnz//5Z8//+WfP//lnz//5Z8//+WfP//lXv//5Z8//+P"
    "c//+yLr//////8HwuP9y1VL/U8oq/0vIIf9LyCH/Ucop/23SS/+27av8/////f/bzv/8jG1tAAAAAP+qVQMAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAP+qqgMAAAAA/5Z8ZP+bgPn/nYH//5R6/P+Uevz/lXr9/5V7/v+Ve/7/lXv+/5V7/v+Ve/7/lXv+/5V7/v+V"
    "e/7/lXv+/5V7/v+Ve/7/lXv+/5V7/v+Ve/7/lXv+/5V7/v+Ve/7/lXv+/5V7/v+VfP7/jnL+/bCc/v/q7f7////+4P3j/sr2"
    "yP7J9sf93Pzf/Pz///z/9vr//b2r/fyIamwAAAAA/6qqAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/qlUDAAAAAP+Z"
    "fTf/m4DC/52C//+eg///mX///5Z8//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+V"
    "e///lXv//5V7//+Ve///lXv//5V7//+Ve///l33//5B0//2Tdv//rZn//8jA///Z2P//3dz//9TL//+4pP/7mnzI+ntaPgAA"
    "AAD/qqoDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/6pVAwAAAAAAAAAA/5yBS/+bgKH/mH3a/5Z89f+V"
    "e///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+Ve///lXv//5V7//+V"
    "e///lXv//5Z9//+Ve///kHT//o1w//yOcPX8jnDc+45tpf+Kak//fwACAAAAAP+qqgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAP9/fwIAAAAAAAAAAAAAAAD/v38E/6CEG/+WfCf/lnwn/5Z8J/+WfCf/lnwn/5Z8J/+W"
    "fCf/lnwn/5Z8J/+WfCf/lnwn/5Z8J/+WfCf/lnwn/5Z8J/+WfCf/lnwn/5Z8J/+WfCf/lnwn/5Z8J/+WfCf/nIIn/6OJJ/+t"
    "kRz///8FAAAAAAAAAAAAAAAA/39/AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAD/AAAB/6qqA/+qqgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/6qqA/+qqgP/AAABAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)

ICON_OFF_B64 = (
    "AAABAAUAEBAAAAAAIAAoBAAAVgAAABQUAAAAACAAaAYAAH4EAAAYGAAAAAAgACgJAADmCgAAICAAAAAAIAAoEAAADhQAADAw"
    "AAAAACAAKCQAADYkAAAoAAAAEAAAACAAAAABACAAAAAAAAAEAADEDgAAxA4AAAAAAAAAAAAAf39/AgAAAABISDYOcGFYVHNl"
    "W2pwYVhrcGFaa3BhWmtwYVprcGFaa3BhWGtyZFprb2BXVVVERA8AAAAAf39/AgAAAAB9c2kzlIiA2buyrP+8tK7/vLSu/7y0"
    "rv+9tK//vbWv/7y0rv+8tK7/vLSu/7uzrf+VioHaenFnNgAAAACIiHcPfnJq36SZkf/r5+T76eXi/Onl4vzr5+T85+Lf/Ofi"
    "3/zr5+T86eXi/Onl4vzr5+X7pZqT/39zauKPj38QhHpxU4p+df+BdW38hXlx/4d7c/+IfXX/gXVt/5WLg/+Wi4T/gXVt/4h9"
    "df+He3P/hXpy/4F1bfyKfnX/g3hvV4N5b2mKfnX+hHhw/IN3b/+EeHH/f3Jq/4t/eP/g3Nj/4t3Z/4yAef9/cmr/hXlx/4N3"
    "b/+EeHD8i352/oV5cG2EenBmin51/4R4cPyGenL/gXRs/4t/eP/d2dX/7+zp/+/r6f/f2tb/jIF5/4B0bP+GenL/hHhw/It+"
    "dv+GenFqg3lvZ4p+df+FeXH8f3Nr/4h8dP/Z1ND/8Ozp/+nl4v/p5eL/7+zp/9rV0f+IfXX/f3Nr/4V5cfyLfnb/hXlwa4N5"
    "b2eLfnb/gnZu/I6De//f2tb/+PXy/+3p5//r5+T/6+fk/+3p5v/49fL/4NvX/4+EfP+Cdm78i392/4V5cGuDeW9ni352/4F1"
    "bfyXjYb/rqaf/6KYkf++t7H/7urn/+7q6P+/uLL/oZiR/66mn/+YjYb/gXVt/It/dv+FeXBrg3lvZ4p+df+FeXH8gXRs/31y"
    "af93amH/opiR//Ds6f/w7Or/pJmT/3ZqYf99cmn/gHRs/4V5cfyLfnb/hXlwa4R6cGaKfnX/hHhw/IV5cf+HfHT/gHNr/6ee"
    "l//w7On/8Ozq/6mfmf9/c2v/h3x0/4V5cf+EeHD8i352/4Z6cWqDeW9pin51/oR4cPyEeHD/hXpy/35xaf+mnZX/7+rn/+/q"
    "6P+onZf/fXFp/4V6cv+EeHD/hHhw/It+dv6FeXBthXlvUop9df+Dd2/8hHhw/4V6cv9+cWn/qJ+Y//fz8P/38/H/qqCa/31x"
    "af+FenL/hHhw/4R3b/uKfXX/hXlwVn9/bQ6Ed3DejoF4/4R3b/uEd3D9gnVt/I+FffyqoJr8qqCa/JCFfvyBdW38hHdw/YN3"
    "b/yNgXj/hHhw4H9/bxAAAAAAh3dyMYl9dNaKfXX/in11/4t+dv+Ie3P/g3Zu/4N2bv+Ie3P/i352/4p9df+KfXX/iH102IR6"
    "cDQAAAAAf39/AgAAAABqamoMjH91UIV5cWeEeHBmhXlxZ4h7dGeIe3RnhXlxZ4R4cGaFeXFnin10UXViYg0AAAAAf39/AigA"
    "AAAUAAAAKAAAAAEAIAAAAAAAQAYAAMQOAADEDgAAAAAAAAAAAAAAAAAAf39/AgAAAAAAAAACemtmMntsZUR4bGFEeGxlRHhs"
    "ZUR4bGVEeGxlRHhsZUR4bGVEeGxhRHtsZUR4bmQzVVVVAwAAAAB/f38CAAAAAH9/fwIAAAAAg3RtSIh8dM2Rhn77kod//5KH"
    "f/+Sh3//kod//5KHf/+Sh3//kod//5KHf/+Sh3//kod//5GGfvuIfHXPgXNsSwAAAAB/f38CAAAAAIp/eESDdm3/wrq0//bz"
    "8P/t6uf+7+zp/u/s6f7v6+n+8O3q/vDt6v7v6+n+7+zp/u/s6f7t6uf+9vPw/8S8tv+Ed27/in90SAAAAACZmWYFhnpx0YZ5"
    "cf+km5P6z8nE/8rEv//LxcD/y8XA/83Gwv/Iwbz/x8G8/83Gwv/LxcD/y8XA/8vEv//PycX/pZyV+oZ5cP+GenHVbW1tB4d8"
    "cS+Ed2/9hHlx/oBza/99cWj/fnJp/35xaf+AdGv/d2ph/5WLhP+WjIX/d2ph/4B0a/9+cWn/fnJp/31xaf9/c2v/hHhw/oR4"
    "cP6EenA0h3tzQIZ6cv+EeHD/hXlx/4V6cv+FeXH/h3x0/39za/+Vi4T/6eXi/+vn4/+XjIX/f3Nr/4d8dP+FeXH/hXpy/4V5"
    "cf+EeHD+h3ty/4h5ckWFeXE/hnpy/4R4cP+EeHD/hHhw/4Z6cv9/cmr/k4iA/+Xg3f/t6uf/7enm/+bi3v+UiYL/fnJq/4Z6"
    "cv+EeHD/hHhw/4R4cP6He3L/h3hwRIV5cT+GenL/hHhw/4R4cP+GenL/f3Nq/5CFfv/j3tv/7+vo/+rl4v/q5uL/7+vo/+Tg"
    "3P+Sh3//f3Jq/4Z6cv+EeHD/hHhw/od7cv+HeHBEhXlxP4Z6cv+EeHD/hXlx/35xaf+NgXr/39vX/+7q5//p5OH/6+fk/+vn"
    "5P/p5eH/7ern/+Hc2P+Og3v/fnFp/4V5cf+EeHD+h3ty/4d4cESFeXE/hnpy/4R5cf+BdW3/lImC/+bi3v/39PL/8e3r/+7q"
    "5//r5+T/6+fk/+7q5//x7ev/9/Tx/+jj4P+VioP/gXVt/4R4cf6He3L/h3hwRIV5cT+GenL/hHlx/4F1bf+imJL/tq2o/6+n"
    "of+tpJ7/19HN/+7q5//u6uf/2NPP/62knv+vpqD/tq2o/6OZk/+BdW3/hHhw/od7cv+HeHBEhXlxP4Z6cv+EeHD/hXlx/39z"
    "a/97b2b/fnJq/3ZpYP/Gvrn/8O3q//Ds6v/IwLz/dmpg/35xaf97b2b/f3Nr/4V5cf+EeHD+h3ty/4d4cESFeXE/hnpy/4R4"
    "cP+EeHD/hXlx/4Z6cv+HfHT/gHNr/8nCvf/w7er/8Ozq/8vEwP+AdGv/h3tz/4Z6cv+FeXH/hHhw/4R4cP6He3L/h3hwRIV5"
    "cT+GenL/hHhw/4R4cP+EeHD/hHhw/4V6cv9+cWn/yMG8//Dt6v/w7Or/ysO//35yaf+FeXH/hHhw/4R4cP+EeHD/hHhw/od7"
    "cv+HeHBEh3tzQIZ6cv+EeHD/hHhw/4R4cP+EeHD/hXpy/35xaf/HwLv/7+vo/+/q6P/Jwr7/fnJp/4V5cf+EeHD/hHhw/4R4"
    "cP+EeHD+h3ty/4h5ckWCd3EvhHdv/YR4cP6EeHD/hHhw/4R4cP+FenL/fnFp/8zGwf/39PL/9/Py/87IxP9+cmn/hXlx/4R4"
    "cP+EeHD/hHhw/4R4cP6EeHD+h3hzM2ZmZgWEeG/Qi352/4N3b/qEeHD/hHhw/4V5cf+Ac2v/sqmj/83Hwv/Nx8L/s6ul/4B0"
    "a/+FeXH/hHhw/4R4cP+Dd3D6in51/4R4b9R/f38GAAAAAIV5cUGJfXX+i352/4R4cP+EeHD/hHhw/4R4cP+AdGv/fnFp/35x"
    "af+Ac2v/hHhw/4R4cP+EeHD/hHhw/4p+df+KfnX/hXlyRQAAAAB/f38CAAAAAIN4cESIfHTKhnlx+YZ6cv+GenL/hnpy/4d7"
    "c/+He3P/h3tz/4d7c/+GenL/hnpy/4Z6cv+GeXL5iHx0y4F2b0cAAAAAf39/AgAAAAB/f38CAAAAAAAAAACKf3QuhXlxP4V5"
    "cT+FeXE/hXlxP4V5cT+FeXE/hXlxP4V5cT+FeXE/hXlxP4d8dy8AAAABAAAAAH9/fwIAAAAAKAAAABgAAAAwAAAAAQAgAAAA"
    "AAAACQAAxA4AAMQOAAAAAAAAAAAAAAAAAAAAAAAAf39/AgAAAAAAAAAAnZGRFZaHfyKRg3sjkYN7I5GDeyORg3sjkYN7I5GD"
    "eyORg3sjkYN7I5GDeyOWh38ikYN7I6KWixYAAAAAAAAAAH9/fwIAAAAAAAAAAAAAAAB/f38CAAAAAIN4cUiAdGy4gHRr6X9y"
    "avR+cmr1fnJq9X5yavV+cmr1fnJq9X5yavV+cmr1fnJq9X5yavV+cmr1f3Jq9IBzauqAdGq6hHdwSwAAAAB/f38CAAAAAH9/"
    "fwIAAAAAhHhxd4t+df+5sKr/0MnF/8vFwP/MxcH/zMXB/8zFwf/MxcH/zMXB/8zFwf/MxcH/zMXB/8zFwf/MxcH/y8XA/9DJ"
    "xf+6sav/jH92/4N5cXwAAAAAf39/AgAAAACFeXJDjH93/4Z6cvzn4+D7/Pn3/vf08v749fP++PXz/vj18/749fP++fb0/vn2"
    "9P749fP++PXz/vj18/749fP+9/Ty/vz59/7o5OH8iHtz+42Ad/+GeHFIAAAAAAAAAACEeHC6jIB3/oF0bPuakIn/samj/66m"
    "oP+vpqD/r6ag/6+moP+wqKL/qqGb/6qhm/+wqKL/r6ag/6+moP+vpqD/rqag/7Gpo/+bkYr/gnVs+4x/d/6EeXC/AAAAAI1/"
    "cRKDd3Dqhnpy/4R4cP6Ac2v/fHBn/31waP99cGj/fXBo/39yav90Z17/npSN/6CWj/90Z17/f3Jq/31waP99cGj/fXBo/3xw"
    "Z/9/c2v/hHhw/oZ6cv+EeG/ti3NzFotzah+DeHDyhnpy/4R4cP6FeXH/hnpy/4Z6cv+FenL/iHx0/39yav+glo//7+vo//Ds"
    "6f+hmJH/fnJp/4h8dP+FenL/hnpy/4Z6cv+FeXH/hHhw/oV5cf+EeHD1hnhxJIh3bh6DeHDyhnpy/4R4cP6EeHD/hHhw/4R4"
    "cP+GenL/fXFo/5ySi//r5+T/7Ojl/+zo5f/s6OX/npSN/31waP+GenL/hHhw/4R4cP+EeHD/hHhw/oV5cf+EeHD1g3t0I4h3"
    "bh6DeHDyhnpy/4R4cP6EeHD/hHhw/4Z6cv9+cWn/mY+I/+rl4v/t6eb/6ubj/+rm4//t6eb/6ufj/5uRiv99cWj/hnpy/4R4"
    "cP+EeHD/hHhw/oV5cf+EeHD1g3t0I4h3bh6DeHDyhnpy/4R4cP6EeHD/hnpy/35xaf+XjIX/6OTg/+7q5//q5uL/6+fk/+vn"
    "5P/q5uP/7enn/+nl4v+Yjof/fnFp/4Z6cv+EeHD/hHhw/oV5cf+EeHD1g3t0I4h3bh6DeHDyhnpy/4R4cP6FeXH/fHBo/5KI"
    "gf/l4N3/7Onm/+jk4f/r5+T/6+fk/+vn5P/r5+T/6OTh/+zo5f/m4t7/lIqD/3xwZ/+FeXH/hHhw/oV5cf+EeHD1g3t0I4h3"
    "bh6DeHDyhnpy/4R4cf6BdW3/mpCJ/+zo5f/28/D/8e3r//Lv7P/s6OX/6+fk/+vn5P/r5+T/8u/s//Hu6//28/D/7enm/5yS"
    "i/+BdW3/hHlx/oV5cf+EeHD1g3t0I4h3bh6DeHDyhnpy/4R4cP6Cdm7/rqag/762sf+4sKr/uLGr/7y1r//n4+D/7Ojl/+zo"
    "5f/o5OH/vbWw/7ixq/+4sKr/vrax/6+nof+Dd2//hHhw/oV5cf+EeHD1g3t0I4h3bh6DeHDyhnpy/4R4cP6EeHD/fnJq/3tv"
    "Zv99cGn/em5l/4N3b//i3tv/7Onm/+zo5f/l4Nz/hXpx/3puZf9+cWn/e29m/35yav+EeHD/hHhw/oV5cf+EeHD1g3t0I4h3"
    "bh6DeHDyhnpy/4R4cP6EeHD/hXlx/4Z6cv+GenP/hHhw/4yBef/j39z/7Onm/+zo5f/l4N3/joN7/4R4cP+He3P/hnpy/4V5"
    "cf+EeHD/hHhw/oV5cf+EeHD1g3t0I4h3bh6DeHDyhnpy/4R4cP6EeHD/hHhw/4R4cP+EeHH/gnZu/4p/d//j39z/7Onm/+zo"
    "5f/l4N3/jIF5/4J2bv+FeXH/hHhw/4R4cP+EeHD/hHhw/oV5cf+EeHD1g3t0I4h3bh6DeHDyhnpy/4R4cP6EeHD/hHhw/4R4"
    "cP+EeHH/gnZu/4p/d//j39z/7Onm/+zo5f/l4N3/jIF5/4J2bv+FeXH/hHhw/4R4cP+EeHD/hHhw/oV5cf+EeHD1g3t0I4Nz"
    "ah+DeHDyhnpy/4R4cP6EeHD/hHhw/4R4cP+EeHH/gnZu/4p/d//j39z/7Onm/+zo5f/l4N3/jIF5/4J2bv+FeXH/hHhw/4R4"
    "cP+EeHD/hHhw/oV5cf+EeHD1hnhxJId4eBGEeHDphnpy/4N4cP6EeHD/hHhw/4R4cP+EeHH/gnZu/4p/d//k4d7/7uvo/+7q"
    "5//m4t//jIF5/4J2bv+FeXH/hHhw/4R4cP+EeHD/hHhw/oZ6cv+EeG/thXl5FQAAAACFeHC4jH93/oR3b/uEeHD/hHhw/4R4"
    "cP+EeHH/gnZu/4p/d//e2db/5uLf/+bh3v/f2tf/jIB5/4J2bv+FeXH/hHhw/4R4cP+EeHD/hHdv+4t/dv6EeXG9AAAAAAAA"
    "AACDd29AjH93/4V4cP2Ed2/7g3hw/oR4cP6EeHD+g3dv/oR4cP6LgHj+jIB5/oyAef6LgHj+hHhw/oN3b/6EeHD+hHhw/oN4"
    "cP6Ed2/7hXlx/I2Ad/+FeXJFAAAAAH9/fwIAAAAAg3hvcox/d/+Mf3f/h3py/4Z6cf+GenL/hnpy/4Z6cf+EeG//hHdv/4R3"
    "b/+EeG//hnpx/4Z6cv+GenL/hnpx/4d6cv+Mf3b/jIB3/4J4b3cAAAAAf39/AgAAAAB/f38CAAAAAIV5ckOIfXSzhnly5oN4"
    "cPKDeG/yg3hw8oN4cPKEeXDyhHlw8oR5cPKEeXDyg3hw8oN4cPKDeG/yhHhw8oZ5cuaIe3O1hnhwRgAAAAB/f38CAAAAAAAA"
    "AAAAAAAAVVVVAwAAAAAAAAAAjX9xEoh/dx5/d24eiHduHoh3bh6Id24eiHduHoh3bh6Id24eiHduHoh3bh5/d24eiH93Ho1/"
    "fxIAAAAAAAAAAH9/fwIAAAAAAAAAACgAAAAgAAAAQAAAAAEAIAAAAAAAABAAAMQOAADEDgAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAABVVVVAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABVVVUDAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAjYJ3LYd7"
    "c36FeHGwhHdvwIN3b8CCdm7BgnZuwYJ2bsGCdm7BgnZuwYJ2bsGCdm7BgnZuwYJ2bsGCdm7BgnZuwYJ2bsGDd2/AhHdvwIR5"
    "cLGHe3OAjYJ3LwAAAAAAAAAA/wAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAkW1tB4h8c5SEd279joF4/5CEe/+Ognr/joJ6/46C"
    "ev+Ognr/joJ6/46Cev+Ognr/joJ6/46Cev+Ognr/joJ6/46Cev+Ognr/joJ6/46Cev+Ognr/kIN7/46Cef+Ed2/+iH10mX9/"
    "ZgoAAAAA//8AAQAAAAD//wABVVVVA5GRbQeIfHO5jH92/5uRiv7d2NX74NvY/N/b1/zg29f84NvX/ODb1/zg29f84NvX/ODb"
    "1/zg29f84NvX/ODb1/zg29f84NvX/ODb1/zg29f84NvX/N/b1/zg29f83tnW+56Ujv2MfnX/h3tzwJl/fwp/f38C////AapV"
    "VQMAAAAAhHhvkpKFfP96bmb5xr+7/vv49v/u6+j/8e3r//Ht6//x7ev/8e3r//Ht6//x7ev/8e3r//Ht6//x7ev/8e3r//Ht"
    "6//x7ev/8e3r//Ht6//x7ev/8e3r/+/r6P/7+Pb/ysO+/3tuZvmShXz/hHhwmgAAAABVVVUDAAAAAIJ8byeHenL9hXpy/IB0"
    "bP6akIn/2tTR/93Y1f/d19T/3djU/93Y1P/d2NT/3djU/93Y1P/d2NT/3djV/93Y1f/d2NT/3djU/93Y1P/d2NT/3djU/93Y"
    "1P/d19T/3djU/9vV0v+ckov/gHNr/oV5cfyIe3P/hXlzLAAAAAAAAAAAhHhve46Bef+Ed2/7hXlx/4B0bP+Ddm7/hnpz/4Z6"
    "cv+GenL/hnpy/4Z6cv+GenL/hnpy/4Z6cv+Ddm7/g3Zu/4Z6cv+GenL/hnpy/4Z6cv+GenL/hnpy/4Z6cv+GenP/g3dv/4B0"
    "bP+FeXH/hHdv+46Bef+FeXGCAAAAAAAAAACEeHCtjIB3/4N3cPyEeHD/hXlx/4R4cP+Dd2//g3dv/4N3b/+Dd2//g3dv/4R4"
    "cP+FeXH/e25m/7uzrv+9trD/e29m/4V5cf+EeHD/g3dv/4N3b/+Dd2//g3dv/4N3b/+EeHD/hXlx/4R4cP+DeHD8jH93/4N4"
    "cbQAAAAAAAAAAIN4cLqMf3b/g3hw/IR4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hnpy/3xwaP+1rKf/8u7s//Pv"
    "7f+3r6r/fXBo/4Z6cv+EeHH/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cPyLfnb/hHhwwQAAAAAAAAAAg3hwuox/"
    "dv+DeHD8hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4Z6cv98cGf/samj//Lu6//q5uP/6uXi//Lv7P+0rKb/fG9n/4Z6"
    "cv+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/It+dv+EeHDBAAAAAAAAAACDeHC6jH92/4N4cPyEeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+GenL/fG9n/66moP/x7uv/6ubj/+vn5P/r5+T/6ubj//Lu6/+xqaP/fHBn/4Z6cv+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD8i352/4R4cMEAAAAAAAAAAIN4cLqMf3b/g3hw/IR4cP+EeHD/hHhw/4R4cP+EeHD/hnpy/3xv"
    "Z/+ropz/8e3q/+vn5P/q5uP/6+fk/+vn5P/r5uP/6ubj//Hu6/+upqD/fG9n/4Z6cv+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cPyLfnb/hHhwwQAAAAAAAAAAg3hwuox/dv+DeHD8hHhw/4R4cP+EeHD/hHhw/4Z6cv98b2f/qJ+Z//Ds6f/r5+T/6ubj/+vn"
    "5P/r5+T/6+fk/+vn5P/q5uP/6+fk//Dt6v+ropz/fG9n/4Z6cv+EeHD/hHhw/4R4cP+EeHD/hHhw/It+dv+EeHDBAAAAAAAA"
    "AACDeHC6jH92/4N4cPyEeHD/hHhw/4R4cP+GenL/fHBn/6aclv/v6+j/6+fk/+rm4//r5+T/6+fk/+vn5P/r5+T/6+fk/+vn"
    "5P/q5uP/6+fk//Ds6f+on5n/fG9n/4Z6cv+EeHD/hHhw/4R4cP+EeHD8i352/4R4cMEAAAAAAAAAAIN4cLqMf3b/g3hw/IR4"
    "cP+EeHD/hXlx/3tuZv+hmJH/7enm/+rm4//p5eH/6ubi/+vm4//r5+T/6+fk/+vn5P/r5+T/6+fj/+rm4v/p5eL/6ubj/+7q"
    "5/+km5T/e25m/4V5cf+EeHD/hHhw/4R4cPyLfnb/hHhwwQAAAAAAAAAAg3hwuox/dv+DeHD8hHhw/4V5cf+AdGz/p52X//Pw"
    "7f/y7+z/8O3q//Hu6//y7uz/7enm/+vn5P/r5+T/6+fk/+vn5P/t6eb/8u7r//Hu6//w7er/8u/s//Tx7v+poJr/gHRs/4V5"
    "cf+EeHD/hHhw/It+dv+EeHDBAAAAAAAAAACDeHC6jH92/4N4cPyEeXH/gnZu/4yBef/Jwr3/zcbC/8rDvv/LxMD/y8XA/8nC"
    "vf/g29f/7enm/+vm4//r5uP/7enm/+Hc2P/Jwr3/y8TA/8vEv//Kw77/zMbB/8rEv/+Ngnr/gnZu/4R5cf+EeHD8i352/4R4"
    "cMEAAAAAAAAAAIN4cLqMf3b/g3hw/IR4cP+EeHD/hXlx/39zav9+cWn/fnJq/35yaf9/dGz/eGpi/8W/uv/y7uv/6uXi/+rl"
    "4v/x7uv/ycK9/3hrYv9/c2v/fnJp/35yav9+cWn/f3Jq/4V5cf+EeHD/hHhw/4R4cPyLfnb/hHhwwQAAAAAAAAAAg3hwuox/"
    "dv+DeHD8hHhw/4R4cP+EeHD/hXlx/4V5cv+FeXH/hXlx/4Z7c/9/cmv/x8G8//Lu6//q5eL/6uXi//Hu6//LxL//f3Nq/4Z6"
    "cv+FeXH/hXlx/4V5cf+FeXH/hHhw/4R4cP+EeHD/hHhw/It+dv+EeHDBAAAAAAAAAACDeHC6jH92/4N4cPyEeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hXpy/35xaf/Hwbz/8u7r/+rl4v/q5eL/8e7r/8vEv/9+cmn/hXlx/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD8i352/4R4cMEAAAAAAAAAAIN4cLqMf3b/g3hw/IR4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+FenL/fnFp/8fBvP/y7uv/6uXi/+rl4v/x7uv/y8S//35yaf+FeXH/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cPyLfnb/hHhwwQAAAAAAAAAAg3hwuox/dv+DeHD8hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4V6cv9+cWn/x8G8//Lu"
    "6//q5eL/6uXi//Hu6//LxL//fnJp/4V5cf+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/It+dv+EeHDBAAAAAAAA"
    "AACDeHC6jH92/4N4cPyEeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hXpy/35xaf/Hwbz/8u7r/+rl4v/q5eL/8e7r/8vE"
    "v/9+cmn/hXlx/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD8i352/4R4cMEAAAAAAAAAAIN4cLqMf3b/g3hw/IR4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+FenL/fnFp/8fBvP/y7uv/6uXi/+rl4v/x7uv/y8S//35yaf+FeXH/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cPyLfnb/hHhwwQAAAAAAAAAAhXhwrIyAd/6Dd3D8hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4V6cv9+cWn/xsC7//Ds6f/p5OD/6eTg//Ds6f/Kw77/fnJp/4V5cf+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/g3dw/Ix/d/+EeXCzAAAAAAAAAACFeXB4joF5/4R3b/uEeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hXpy/35x"
    "af/LxcH/+fXz//Ds6f/w7On/+PXz/8/JxP9+cmn/hXlx/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+Ed2/7joF5/4V5"
    "cYAAAAAAAAAAAIZ/cSSGenL8hXlx/IR4cP6EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+FeXH/gHNr/7KqpP/PycT/ysO+/8rD"
    "vv/PycT/taym/4B0bP+FeXH/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/oR4cPyHe3L+hXlzKgAAAACqVVUDAAAAAIR3"
    "cI2Qg3v/g3dv+YR4cP6EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/gHRs/35xaf9+cmr/fnJq/35xaf+AdGz/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP6Dd2/5kIN6/4R4b5QAAAAAVVVVA/8AAAF/f38Cf39/BoV6cbOQg3r/hHhw/4R3"
    "b/uDd3D8g3hw/IN4cPyDeHD8g3hw/IN3cPyEeHH8hXlx/IV5cfyFeXH8hXlx/IR5cfyDeHD8g3hw/IN4cPyDeHD8g3hw/IN3"
    "cPyEd2/7g3hw/pCDev+HenK5f39/CFVVVQP//wABAAAAAAAAAAEAAAAAf39/BIh7coyIe3P5joF5/4yAd/+Mf3b/jH92/4x/"
    "dv+Mf3b/jH92/4x/d/+Mf3f/jH93/4x/d/+Mf3f/jH93/4x/dv+Mf3b/jH92/4x/dv+Mf3b/jIB3/46Bef+Ie3P7h3t0kZFt"
    "bQcAAAAA/wAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAIl8dSeKfXR2h3pyqYN4cLqEd3G5g3hwuoN4cLqDeHC6g3hwuoN4"
    "cLqDeHC6g3hwuoN4cLqDeHC6g3hwuoN4cLqDeHC6hHdxuYN4cLqHe3Kqin10eIh8dikAAAAAAAAAAAAAAAEAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAGqVVUDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKpVVQMAAAABAAAAAAAAAAAAAAAAKAAAADAAAABgAAAAAQAgAAAA"
    "AAAAJAAAxA4AAMQOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABqqqqA6pVVQMAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVVVVA39/fwQAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAH9/fwIAAAAAAAAAAAAAAACZmX8Khn9xJId8cjGHfHIxh3xyMYd8cjGHfHIxh3xyMYd8"
    "cjGHfHIxh3xyMYd8cjGHfHIxh3xyMYd8cjGHfHIxh3xyMYd8cjGHfHIxh3xyMYd8cjGHfHIxh3xyMYd8cjGHfHIxh3xyMYl8"
    "dSWUf38MAAAAAAAAAAAAAAAAVVVVAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqqpVAwAA"
    "AAB/fz8Ei3xzVop9da2HfHPjhnpy/Il8dP+IfHT/iXx0/4l8dP+JfHT/iXx0/4l8dP+JfHT/iXx0/4l8dP+JfHT/iXx0/4l8"
    "dP+JfHT/iXx0/4l8dP+JfHT/iXx0/4l8dP+JfHT/iXx0/4l8dP+IfHT/iXx0/4Z7c/yHe3Plin12sYp/d1ptbW0HAAAAAKpV"
    "VQMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACqqqoDAAAAAIV5cUGJfXTMjYB3/4Z5cP+Ac2r/fXFo/3xw"
    "aP98cGj/fHBo/3xwaP98cGj/fHBo/3xwaP98cGj/fHBo/3xwaP98cGj/fHBo/3xwaP98cGj/fHBo/3xwaP98cGj/fHBo/3xw"
    "aP98cGj/fHBo/3xwaP98cGj/fHBo/31xaP9/c2r/hnlw/42AeP+JfHXRiHpyRwAAAACqVVUDAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAH9/fwQAAAAAh3lybYl9dP6JfXX/gHRs/J+Wj/ywp6H9rqWe/q6ln/+upZ//rqWf/66ln/+upZ//rqWf/66l"
    "n/+upZ//rqWf/66ln/+upZ//rqWf/66ln/+upZ//rqWf/66ln/+upZ//rqWf/66ln/+upZ//rqWf/66ln/+upZ//rqWf/66l"
    "nv6vpqD+oZiR/IF1bfyJfHT/in51/4d6cXcAAAAAqqqqAwAAAAAAAAAAAAAAAAAAAAAAAAAAqqpVAwAAAACEeHFsjoF4/4Z5"
    "cf1+cmn8t66p//Tx7v/x7uv/8u7s//Lv7P/y7+z/8u/s//Lv7P/y7+z/8u/s//Lv7P/y7+z/8u/s//Lv7P/y7+z/8u/s//Lv"
    "7P/y7+z/8u/s//Lv7P/y7+z/8u/s//Lv7P/y7+z/8u/s//Lv7P/y7+z/8u/s//Lv7P/x7uv/9PHv/7u0rv99cWn9hXlx/I+C"
    "ef+EeHF3AAAAAKpVVQMAAAAAAAAAAAAAAABVVVUDAAAAAIp9dDmIfHT+hXlx/IJ2bv6Ge3P/4t3a/+zo5f/n4+D/6eTh/+nk"
    "4f/p5OH/6eTh/+nk4f/p5OH/6eTh/+nk4f/p5OH/6eTh/+nk4f/p5OH/6eTh/+nk4f/p5OH/6eTh/+nk4f/p5OH/6eTh/+nk"
    "4f/p5OH/6eTh/+nk4f/p5OH/6eTh/+nk4f/o4+D/6+fk/+Xh3f+JfXb/gnZu/oV5cfuKfnb/hXlyQwAAAABVVVUDAAAAAAAA"
    "AAF/f38Cf39/BIR4cM6KfXX/g3dw/IV5cf+BdW3/083I//bz8P/t6uf/7+vo/+/r6P/v6+j/7+vo/+/r6P/v6+j/7+vo/+/r"
    "6P/v6+j/7+vo/+/r6P/v6+j/7+vo/+/r6P/v6+j/7+vo/+/r6P/v6+j/7+vo/+/r6P/v6+j/7+vo/+/r6P/v6+j/7+vo/+/r"
    "6P/u6uf/9fLv/9fRzf+Ddm7/hHhw/4R4cPyJfXT/hHhw139/fwj///8BAAAAAX9/fwQAAAAAh3pwTYt/d/+Dd2/8hHhw/4V5"
    "cf+BdW3/kYd//8/IxP/b1dL/2dTQ/9rU0f/a1NH/2tTR/9rU0f/a1NH/2tTR/9rU0f/a1NH/2tTR/9rU0f/a1NH/29XS/9vV"
    "0v/a1NH/2tTR/9rU0f/a1NH/2tTR/9rU0f/a1NH/2tTR/9rU0f/a1NH/2tTR/9nU0P/b1dL/0crG/5SJgv+BdGz/hXlx/4R4"
    "cP+Dd2/8jIB3/4N4clkAAAAAf39/BKqqVQMAAAAAhXlxqIx/d/6Ed2/7hHhw/4R4cP+FeXH/gXVt/39zav+EeHD/g3dv/4N3"
    "b/+Dd2//g3dv/4N3b/+Dd2//g3dv/4N3b/+Dd2//g3dw/4N3b/+FeXH/gHRs/4B0bP+FeXH/g3dv/4N3cP+Dd2//g3dv/4N3"
    "b/+Dd2//g3dv/4N3b/+Dd2//g3dv/4N3b/+EeHD/f3Nr/4F0bP+FeXH/hHhw/4R4cP+Ed3D7jH92/oV5cbMAAAAAVVVVAwAA"
    "AAB/f38GhHlx34h7c/+Ed2/9hHhw/4R4cP+EeHD/hXlx/4V5cf+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4Z6cv9+cmn/lIqD/5aMhf9+cWn/hnpy/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hXlx/4V5cf+EeHD/hHhw/4R4cP+Dd2/+h3py/4R4cOeLc3MLAAAAAAAAAACMe3IdhXhw94V5cf+EeHD+hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hnpy/4B0bP+NgXr/4t7a/+bh"
    "3v+QhX3/f3Nr/4Z6cv+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD+hHhw/4R3cP2GeHImAAAAAAAAAACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+GenL/gHRs/4uAeP/f2tb/7+vo/+7q6P/i3dr/joN8/39za/+GenL/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAA"
    "AACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4Z6"
    "cv+AdGz/in53/9zX0//w7er/6eXi/+nl4v/w7On/39rW/42Cev+AdGv/hnpy/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAAAACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hXly/4F1bf+IfHX/2dTQ//Hu6//p5eL/6+fk/+vn"
    "5P/p5eL/8O3q/93Y1P+Lf3f/gXVs/4V6cv+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAAAACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+FeXL/gXVt/4Z6cv/Y0s7/8u7r/+nl4v/r5+T/6+fk/+vn5P/r5+T/6eXi//Ht6v/b1tL/iHx1/4F1"
    "bP+GenL/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAA"
    "AACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4V5cf+Cdm7/hXlx/9XP"
    "y//y7uv/6eXi/+vn5P/r5+T/6+fk/+vn5P/r5+T/6+fk/+nl4v/x7ev/2dPP/4d8dP+BdW3/hXlx/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAAAACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hXlx/4J2bv+EeG//0szH//Lv7P/p5eL/6+fk/+vn5P/r5+T/6+fk/+vn"
    "5P/r5+T/6+fk/+vn5P/p5eL/8u7r/9XQzP+GenL/gnZu/4V5cf+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAAAACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+FeXH/g3dv/4J2bv/QysX/8u/s/+nl4v/r5+T/6+fk/+vn5P/r5+T/6+fk/+vn5P/r5+T/6+fk/+vn5P/r5+T/6eXi//Lu"
    "7P/Uzsr/hHhw/4J2bv+FeXH/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAA"
    "AACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4V5cf+Dd2//gXVt/83Hwv/y7+z/6eXi/+vn"
    "5P/r5+T/6+fk/+vn5P/r5+T/6+fk/+vn5P/r5+T/6+fk/+vn5P/r5+T/6+fk/+nl4v/y7uz/0cvH/4N3b/+Cdm7/hXlx/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAAAACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hXlx/4R3b/+AdGz/ycO+//Pv7f/p5eL/6+fk/+vn5P/r5+T/6+fk/+vn5P/r5+T/6+fk/+vn"
    "5P/r5+T/6+fk/+vn5P/r5+T/6+fk/+vn5P/p5eL/8+/t/87Hw/+Cdm7/g3dv/4V5cf+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAAAACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4cP+EeHD/hHhw/4R4cP+FeXH/hHhw/39z"
    "av/HwLz/8/Dt/+nl4v/r5+T/6+fk/+vn5P/r5+T/6+fk/+vn5P/r5+T/6+fk/+vn5P/r5+T/6+fk/+vn5P/r5+T/6+fk/+vn"
    "5P/r5+T/6eXh//Pw7f/LxcD/gHRs/4R3cP+FeXH/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAA"
    "AACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4cP+EeHD/hHhw/4V5cf+EeHD/fnFp/8S9uP/y7+z/6eTh/+vn5P/r5+T/6+fk/+vn"
    "5P/r5+T/6+fk/+vn5P/r5+T/6+fk/+vn5P/r5+T/6+fk/+vn5P/r5+T/6+fk/+vn5P/r5+T/6+fk/+jk4f/y7+z/yMK9/39z"
    "av+Ed2//hXlx/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAAAACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP9/c2v/wru2//Tx7v/r5+T/7Ojm/+zo5v/s6Ob/7Ojm/+zo5v/s6OX/6+fk/+vn5P/r5+T/6+fk/+vn"
    "5P/r5+T/6+fk/+vn5P/s6OX/7Onm/+zo5v/s6Ob/7Ojm/+zp5v/q5uP/9PHu/8bAu/+BdGz/g3dv/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAAAACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4cP+EeHD/hXlx/4B0bP+5sav/7uvo/+Tg"
    "3P/m4d7/5uHe/+bh3v/m4d7/5uHe/+bh3v/m4t//6+fk/+vn5P/r5+T/6+fk/+vn5P/r5+T/6+fk/+vn5P/m4t//5uHe/+bh"
    "3v/m4d7/5uHe/+bh3v/m4t7/5N/c/+7r6P+8tbD/gXVt/4V5cf+EeHD/hHhw/4R4cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAA"
    "AACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4cP+EeHD/hHhw/4V5cf+Rhn7/jYF6/42Cev+Ngnr/jYJ6/42Cev+Ngnr/jYJ6/4uA"
    "eP+Th4H/5N/c/+3p5v/q5uP/6+fk/+vn5P/r5+T/7Ojm/+fi3/+Vi4P/i4B4/46De/+Ngnr/jYJ6/42Cev+Ngnr/jYJ6/4yB"
    "ef+Rhn7/hXlx/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAAAACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+BdW3/gnVt/4J2bv+Cdm3/gnZt/4J2bf+Cdm3/gnZt/4B0a/+IfHX/497b/+3p5v/q5uP/6+fk/+vn"
    "5P/r5+T/7Ojm/+bh3v+LgHj/gHRq/4N3b/+Cdm3/gnZt/4J2bf+Cdm3/gnZt/4J2bf+BdW3/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAAAACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4cP+EeHD/hHhw/4R4cP+EeXH/hXlx/4V5"
    "cf+FeXH/hXlx/4V5cf+FeXH/hXlx/4N3b/+Lf3j/497b/+3p5v/q5uP/6+fk/+vn5P/r5+T/7Ojm/+bh3v+Og3v/g3du/4Z6"
    "cv+FeXH/hXlx/4V5cf+FeXH/hXlx/4V5cf+FeXH/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAA"
    "AACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4J2"
    "bv+Kfnf/497b/+3p5v/q5uP/6+fk/+vn5P/r5+T/7Ojm/+bh3v+Ngnr/gnZt/4V5cf+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAAAACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4J2bv+Kfnf/497b/+3p5v/q5uP/6+fk/+vn"
    "5P/r5+T/7Ojm/+bh3v+Ngnr/gnZt/4V5cf+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAAAACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4J2bv+Kfnf/497b/+3p5v/q5uP/6+fk/+vn5P/r5+T/7Ojm/+bh3v+Ngnr/gnZt/4V5"
    "cf+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAA"
    "AACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4J2"
    "bv+Kfnf/497b/+3p5v/q5uP/6+fk/+vn5P/r5+T/7Ojm/+bh3v+Ngnr/gnZt/4V5cf+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAAAACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4J2bv+Kfnf/497b/+3p5v/q5uP/6+fk/+vn"
    "5P/r5+T/7Ojm/+bh3v+Ngnr/gnZt/4V5cf+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAAAACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4J2bv+Kfnf/497b/+3p5v/q5uP/6+fk/+vn5P/r5+T/7Ojm/+bh3v+Ngnr/gnZt/4V5"
    "cf+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAA"
    "AACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4J2"
    "bv+Kfnf/497b/+3p5v/q5uP/6+fk/+vn5P/r5+T/7Ojm/+bh3v+Ngnr/gnZt/4V5cf+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAAAACCfG8nhHhw/4R4cP+EeHD+hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4J2bv+Kfnf/497b/+3p5v/q5uP/6+fk/+vn"
    "5P/r5+T/7Ojm/+bh3v+Ngnr/gnZt/4V5cf+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4d7cv+HfHIxAAAAAAAAAACIf3YchHlw9oV5cf+EeHD+hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4J2bv+Kfnf/497b/+3p5v/q5uP/6+fk/+vn5P/r5+T/7Ojm/+bh3v+Ngnr/gnZt/4V5"
    "cf+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD+hHhw/4R4cPyCdW4lAAAAAAAA"
    "AACZmWYFhHlx3Yh7c/+Ed2/9hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4J2"
    "bv+Kfnf/497b/+3p5v/q5uP/6+fk/+vn5P/r5+T/7Ojm/+bh3v+Ngnr/gnZt/4V5cf+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+Dd2/+h3ty/4V5cOWZf2YKAAAAAKqqqgMAAAAAhHpwpYyAd/6Ed2/7hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4J2bv+Kfnf/5N/c/+7q6P/r5+X/7Ojm/+zo"
    "5v/s6Ob/7eno/+fi3/+Ngnr/gnZt/4V5cf+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+Ed2/7jH92/oV5cbAAAAAAVVVVA6qqqgMAAAAAhntxSIt/dv+Dd2/8hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4J2bv+Kfnf/3tnW/+jj4P/l4d3/5uHe/+bh3v/m4d7/5+Pg/+Hc2f+Ngnr/gnZt/4V5"
    "cf+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+Dd2/8jH93/4V5cFQAAAAAf39/BAAA"
    "AAF/f38CVVVVA4R5cciKfnb/g3dv/IR4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+FeHH/jIF5/42Cev+Ngnr/jYJ6/42Cev+Ngnr/jYJ6/42Bev+FeXH/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4N3b/yKfXX/hHhw0n9/fwb///8BAAAAAQAAAAB/f38CAAAAAId9czOJe3T7hnhx/YR3"
    "b/2EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/gnZu/4J2bf+Cdm3/gnZt/4J2"
    "bf+Cdm3/gnZt/4J2bv+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHdv/YV5"
    "cfyJfHT/iHtyPAAAAABVVVUDAAAAAAAAAAAAAAAAqlVVAwAAAACFeXFjjIB3/4V4cP6Dd2/8hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hXlx/4V5cf+FeXH/hXlx/4V5cf+FeXH/hXlx/4V5cf+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+Dd2/8hXhw/Y6BeP+FeXBtAAAAAKqqVQMAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAKqqqgMAAAAAhHpyZIl8dPmLfnX/g3dv/IN3b/yEd2/9hHhw/oR4cP6EeHD+hHhw/oR4cP6EeHD+hHhw/oR4"
    "cP6EeHD+hHhw/oR4cP6EeHD+hHhw/oR4cP6EeHD+hHhw/oR4cP6EeHD+hHhw/oR4cP6EeHD+hHhw/oR4cP6EeHD+hHhw/oR4"
    "cP6Ed2/9g3dv/IN3b/yKfnX/iXx0/YZ6cWwAAAAAqqqqAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACqVVUDAAAAAIZ4"
    "czeKfHTCi352/4x/d/+IfHP/hXlx/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4V5cf+Ie3P/jH93/4x/dv+JfHTIh3tzPgAA"
    "AACqqlUDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqlVVAwAAAAAAAAAAiH1zS4l9c6GGenLahXlx9YR4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4R4"
    "cP+EeHD/hHhw/4R4cP+EeHD/hHhw/4Z5cfWGenLciHtzpYp9d09/fwACAAAAAKqqVQMAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAH9/fwIAAAAAAAAAAAAAAAC/f38EjYR6G4J8byeCfG8ngnxvJ4J8byeCfG8ngnxvJ4J8"
    "byeCfG8ngnxvJ4J8byeCfG8ngnxvJ4J8byeCfG8ngnxvJ4J8byeCfG8ngnxvJ4J8byeCfG8ngnxvJ4J8byeCfG8ngnxvJ5F/"
    "dhyZmZkFAAAAAAAAAAAAAAAAf39/AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAABqqqqA6qqqgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqqqqA6qqqgMAAAABAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)

ICON_APP_B64 = (
    "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"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPmReFv/pIf//6SH//mReFsAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAA/6pVA/+ZmQX/mWYF9Zp/HP2XfML9l3zC9Zp/HP+ZZgX/mZkF/6pVAwAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP//"
    "AAH//wAB//8AAf//AAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAADAAAABgAAAAAQAgAAAA"
    "AAAAJAAAxA4AAMQOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAD/f38C/6pVA/+qVQP/qlUD/6pVA/+qVQP/qlUD/6pVA/+qVQP/qlUD/6pVA/+qVQP/qlUD/6pVA/+q"
    "VQP/f38CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/39/AgAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/AAABAAAAAAAAAADzmXwt+pB4NfWTdTT6k3o0+pN6NPqTejT6k3o0+pN6NPqT"
    "ejT6k3o0+pN6NPqTejT6k3o09ZN1NPqXejb2lHsfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAD/f38C/6pVA/uVeqD/nIH//5d8//+Xff//mH3//5h9//+Yff//mH3//5h9//+Yff//mH3//5h9//+Yff//mH3//5d9//+Y"
    "ff//m4D0/Jh7VwAAAAD/VVUDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP9/fwIAAAAA951/Iv+af///lXr7/5V7+f+U"
    "e/r/lHv6/5R7+v+Ue/r/lHv6/5R7+v+Ue/r/lHv6/5R7+v+Ue/r/lHv6/5R7+v+Ve/b/nYL//JV8yQAAAAD/f38CAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAP8AAAH///8B6ZR/DPyVe9L/pIf//56D//+fhP//n4T//5+E//+fhP//n4T//5+E//+f"
    "hP//n4T//5+E//+fhP//n4T//5+D//+egv//pYj//ZV8hQAAAAD/qqoDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAD///8BAAAAAP+Tfxr8m4Bx/Jd8e/yWfXr6l3x7+pd8e/qXfHv6l3x7+pd8e/qXfHv6l3x7+pd8e/qXfHv6l3x7+pZ9evqa"
    "f3z8ln5d/6pVA/8AAAH/AAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///wH/f38E/39/BP9/fwT/f38E/39/BP+ZZgX/f38CAAAAAAAA"
    "AAD/f38C/5lmBf9/fwT/f38E/39/BP9/fwS/f38E/wAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/39/AgAAAAD/jXEJ/Jh9aPyZfmf/jXEJAAAAAP9/fwIAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "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"
    "e/3/lXr99Y16GwAAAAABAAAAAAAAAP+qVQP/AAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAP8AAAH/AAAB/6pVA/9/fwL9lXud/6GF//+hhf/7lHqe/39/Av+qVQP/AAAB/wAAAQAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAA/wAAAQAAAAAAAAAA+5Z6SfuWfUkAAAAAAAAAAP8AAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/6qqA/+qqgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)


if __name__ == "__main__":
    App().run()
