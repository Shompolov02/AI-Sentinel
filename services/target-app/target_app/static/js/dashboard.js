"use strict";

document.querySelectorAll("[data-api-form]").forEach((form) => {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector("button");
    const result = form.parentElement.querySelector(".result");
    const field = form.querySelector("input");
    button.disabled = true;
    result.className = "result";
    result.textContent = "Запрос выполняется…";
    try {
      const response = await fetch(form.action, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ [field.name]: field.value }),
      });
      const body = await response.json();
      result.textContent = JSON.stringify(body, null, 2);
      result.classList.add(response.ok ? "success" : "error");
    } catch {
      result.textContent = "Ошибка запроса. Проверьте подключение к сервису.";
      result.classList.add("error");
    } finally {
      button.disabled = false;
    }
  });
});
