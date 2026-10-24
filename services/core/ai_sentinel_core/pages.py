from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

STATES = {
    "queued": "В очереди",
    "processing": "Обрабатывается",
    "completed": "Готов вердикт",
    "failed": "Не удалось оценить",
}
ACTIONS = {
    "event_accepted": "Событие принято",
    "processing": "Начата обработка",
    "verdict_created": "Вердикт сохранён",
    "guard_checked": "Prompt Guard проверен",
    "fallback_warning": "Предупреждение: резервный анализ",
    "completed": "Обработка завершена",
    "failed": "Не удалось оценить",
}
ENV = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(["html"]),
)


def date(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).strftime("%d.%m.%Y %H:%M:%S UTC")


ENV.filters["date"] = date


def login_page() -> str:
    return ENV.get_template("login.html").render(title="Вход в AI-Sentinel Core")


LOGIN_SCRIPT = """
document.getElementById("login").addEventListener("submit", async (event) => {
  event.preventDefault();
  const message = document.getElementById("message");
  try {
    const response = await fetch("/login", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({password: document.getElementById("password").value})
    });
    document.getElementById("password").value = "";
    if (response.ok) window.location.assign("/tasks");
    else message.textContent = "Вход не выполнен. Проверьте пароль.";
  } catch { message.textContent = "Сервис недоступен. Повторите попытку."; }
});"""


def task_list(
    rows: list[dict[str, Any]], logins: list[float], role: str = "SecOps"
) -> str:
    for row in rows:
        row["severity"] = (
            json.loads(row["verdict"])["severity"] if row["verdict"] else "—"
        )
    return ENV.get_template("tasks.html").render(
        title="Список задач",
        rows=rows,
        logins=logins,
        states=STATES,
        refresh=True,
        role=role,
    )


def task_page(item: dict[str, Any], role: str = "SecOps") -> str:
    return ENV.get_template("task.html").render(
        title="Задача " + item["task_id"],
        item=item,
        states=STATES,
        actions=ACTIONS,
        role=role,
        refresh=item["state"] in ("queued", "processing"),
    )


TASK_SCRIPT = """
document.querySelectorAll('[data-raw-url]').forEach(link => {
  link.addEventListener('click', async event => {
    event.preventDefault();
    const output = document.getElementById(link.dataset.output);
    output.hidden = false;
    output.textContent = 'Загрузка исходной записи…';
    try {
      const response = await fetch(link.dataset.rawUrl, {cache: 'no-store'});
      if (response.status === 410) {
        const section = link.closest('[data-evidence]');
        const fragment = section.querySelector('[data-source-fragment]');
        if (fragment) fragment.remove();
        link.remove();
        const command = document.querySelector('[data-command-text]');
        if (command) command.textContent = 'Текст команды недоступен: источник удалён.';
        output.textContent = 'Источник удалён.';
        return;
      }
      output.textContent = response.ok
        ? await response.text()
        : 'Исходная запись недоступна. Повторите позже или проверьте сеанс.';
    } catch {
      output.textContent = 'Сервис чтения недоступен. Повторите позже.';
    }
  });
});
"""
