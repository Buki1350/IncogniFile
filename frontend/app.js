import {
  MAX_FILE,
  newKey,
  parseKey,
  to_base64,
  from_base64,
  encrypt,
  decrypt,
  lockKey,
  unlockKey,
} from "./crypto.js";
const $ = (id) => document.getElementById(id);
const VAULT = "incognifile.vault.v1";
let token = null,
  userId = null,
  key = null,
  downloaded = null;
function status(message, bad = false) {
  $("status").textContent = message;
  $("status").classList.toggle("error", bad);
}
function clearPreview() {
  downloaded = null;
  $("preview").textContent = "";
  $("opened").hidden = true;
  $("download").hidden = true;
}
function setKey(value) {
  if (key) key.fill(0);
  key = value;
  $("key-state").textContent = key ? "Klucz gotowy do użycia" : "Brak klucza w tej karcie";
  clearPreview();
}
function reset() {
  token = null;
  userId = null;
  setKey(null);
  $("sent").replaceChildren();
  $("received").replaceChildren();
  $("workspace").hidden = true;
  $("logout").hidden = true;
  $("auth").hidden = false;
  $("password").value = "";
  $("vault-password").value = "";
  $("content").value = "";
  $("upload").value = "";
}
async function api(path, method = "GET", body) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const r = await fetch(`/api${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "omit",
    cache: "no-store",
    redirect: "error",
    // Allow a sleeping demo instance to wake, but do not lock the UI indefinitely.
    signal: AbortSignal.timeout(90_000),
  });
  const value = await r.json().catch(() => ({ message: `HTTP ${r.status}` }));
  if (!r.ok) {
    if (r.status === 401 && token) reset();
    if (value.verification_required || (path === "/register" && r.status === 503)) $("resend").hidden = false;
    throw new Error(value.message || `HTTP ${r.status}`);
  }
  return value;
}
let operationPending = false;
function guard(fn) {
  return async (event) => {
    event?.preventDefault();
    if (operationPending) return;
    // Validate before disabling fields: disabled fields skip browser validation.
    const target = event?.currentTarget;
    const form = target?.tagName === "FORM" ? target : target?.form;
    if (form && !form.reportValidity()) return;
    operationPending = true;
    // Serialize form submissions and key changes during asynchronous operations.
    const controls = [...document.querySelectorAll("button, input, textarea, select")]
      .filter(control => !control.disabled);
    controls.forEach(control => { control.disabled = true; });
    try {
      await fn(event);
    } catch (e) {
      status(e.message || "Operacja nie powiodła się.", true);
    } finally {
      controls.forEach(control => { control.disabled = false; });
      operationPending = false;
    }
  };
}
function needKey() {
  if (!key) throw new Error("Najpierw wygeneruj lub odblokuj klucz.");
  return key;
}
function save(bytes, name) {
  const url = URL.createObjectURL(
    new Blob([bytes], { type: "application/octet-stream" }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function credentials() {
  return { email: $("email").value, password: $("password").value };
}
$("auth-form").addEventListener(
  "submit",
  guard(async () => {
    const result = await api("/login", "POST", credentials());
    token = result.token;
    userId = result.user_id;
    $("password").value = "";
    $("auth").hidden = true;
    $("workspace").hidden = false;
    $("logout").hidden = false;
    status("Zalogowano. Wczytaj klucz lub utwórz nowy.");
    await refresh();
  }),
);
$("register").onclick = guard(async () => {
  const result = await api("/register", "POST", credentials());
  $("resend").hidden = !result.verification_required;
  status(result.message);
});
$("logout").onclick = guard(async () => {
  try {
    await api("/logout", "POST");
  } catch {
    reset();
    throw new Error(
      "Wyczyszczono tę kartę. Serwer nie potwierdził unieważnienia sesji; może ona pozostać ważna do godziny.",
    );
  }
  reset();
  status("Wylogowano. Sesja została unieważniona, zapisana kopia klucza pozostała w przeglądarce.");
});
$("generate").onclick = guard(async () => {
  if (
    key &&
    !confirm(
      "Zastąpić aktywny klucz? Zapisz jego kopię, aby zachować dostęp do dotychczasowych wiadomości.",
    )
  )
    return;
  setKey(newKey());
  status("Nowy klucz gotowy. Zapisz kopię w pliku albo zabezpiecz ją hasłem w przeglądarce.");
});
$("export").onclick = guard(async () => {
  save(to_base64(needKey()), "incognifile.key");
  status("Zapisano jawny klucz do pliku. Przechowuj go osobno od danych.");
});
$("import").onchange = guard(async () => {
  const f = $("import").files[0];
  if (!f) return;
  try {
    if (f.size > 100) throw new Error("Nieprawidłowy plik klucza.");
    setKey(parseKey(await f.text()));
    status("Klucz wczytany lokalnie.");
  } finally {
    $("import").value = "";
  }
});
$("lock").onclick = guard(async () => {
  setKey(null);
  $("vault-password").value = "";
  status("Klucz i podgląd usunięte z pamięci aplikacji.");
});
$("remember").onclick = guard(async () => {
  const current = needKey().slice();
  try {
    const v = await lockKey(current, $("vault-password").value);
    localStorage.setItem(VAULT, JSON.stringify(v));
    status("Zapisano zaszyfrowany klucz w tej przeglądarce.");
  } finally {
    current.fill(0);
    $("vault-password").value = "";
  }
});
$("unlock").onclick = guard(async () => {
  const v = localStorage.getItem(VAULT);
  if (!v) throw new Error("Brak zapisanego klucza.");
  try {
    setKey(await unlockKey(JSON.parse(v), $("vault-password").value));
    status("Klucz odblokowany.");
  } catch {
    throw new Error("Nie udało się wczytać klucza. Sprawdź hasło.");
  } finally {
    $("vault-password").value = "";
  }
});
$("forget").onclick = guard(async () => {
  localStorage.removeItem(VAULT);
  setKey(null);
  $("vault-password").value = "";
  status("Usunięto zapisaną kopię i aktywny klucz.");
});
$("secret-form").addEventListener(
  "submit",
  guard(async () => {
    const current = needKey().slice();
    try {
      const file = $("upload").files[0],
        text = $("content").value;
      if (file && text.trim()) throw new Error("Wybierz wiadomość albo plik.");
      if (!file && !text.trim())
        throw new Error("Wpisz wiadomość lub wybierz plik.");
      if (file && (file.size > MAX_FILE || file.name.length > 255))
        throw new Error("Limit pliku: 512 KiB i 255 znaków nazwy.");
      const value = file
        ? {
            v: 1,
            kind: "file",
            name: file.name,
            data: to_base64(await file.arrayBuffer()),
          }
        : { v: 1, kind: "note", data: text };
      const envelope = await encrypt(current, value);
      const result = await api("/secrets", "POST", {
        ...envelope,
        recipient: $("recipient").value || null,
        ttl_seconds: Number($("ttl").value),
        one_time: $("one-time").checked,
      });
      $("content").value = "";
      $("upload").value = "";
      status(
        `Zapisano wiadomość #${result.id}. Klucz nie został wysłany na serwer.`,
      );
      await refresh();
    } finally {
      current.fill(0);
    }
  }),
);
async function refresh() {
  const result = await api("/secrets");
  $("sent").replaceChildren();
  $("received").replaceChildren();
  for (const [id, rows, empty] of [
    ["sent", result.secrets.filter(m => m.owner_id === userId), "Nie masz wysłanych wiadomości."],
    ["received", result.secrets.filter(m => m.owner_id !== userId), "Nie masz odebranych wiadomości."]
  ]) {
    if (!rows.length) { const p = document.createElement("p"); p.className="hint"; p.textContent=empty; $(id).append(p); }
  }
  for (const secret of result.secrets) {
    const row = document.createElement("article");
    row.className = "secret";
    const title = document.createElement("strong");
    title.textContent = `Wiadomość #${secret.id}${secret.one_time ? " · jednorazowa" : ""}`;
    const info = document.createElement("p");
    info.textContent = `${secret.owner_id === userId ? `Do: ${secret.recipient_email || "tylko Ty"}` : `Od: ${secret.owner_email}`} · wygasa ${new Date(secret.expires_at).toLocaleString("pl-PL")}`;
    const actions = document.createElement("div");
    actions.className = "actions";
    const read = document.createElement("button");
    read.textContent = "Odszyfruj";
    read.onclick = guard(async () => {
      const current = needKey().slice();
      clearPreview();
      if (
        secret.one_time &&
        !confirm(
          "Pierwszy odczyt usunie wiadomość, również przy błędnym kluczu. Kontynuować?",
        )
      ) {
        current.fill(0);
        return;
      }
      try {
        const envelope = await api(`/secrets/${secret.id}/read`, "POST");
        let value;
        try {
          value = await decrypt(current, envelope);
        } catch {
          throw new Error(
            "Nie można odszyfrować: niewłaściwy klucz, zmienione dane lub nieprawidłowy format." +
              (secret.one_time ? " Jednorazowa wiadomość została usunięta." : ""),
          );
        }
        $("opened").hidden = false;
        if (value.kind === "note") $("preview").textContent = value.data;
        else {
          downloaded = value;
          $("preview").textContent = `Plik: ${value.name}`;
          $("download").hidden = false;
        }
        status(`Odszyfrowano wiadomość #${secret.id} lokalnie.`);
      } finally {
        current.fill(0);
        await refresh();
      }
    });
    actions.append(read);
    if (secret.owner_id === userId) {
      const remove = document.createElement("button");
      remove.textContent = "Usuń";
      remove.className = "danger";
      remove.onclick = guard(async () => {
        await api(`/secrets/${secret.id}`, "DELETE");
        clearPreview();
        await refresh();
        status("Wiadomość usunięta.");
      });
      actions.append(remove);
    }
    row.append(title, info, actions);
    $(secret.owner_id === userId ? "sent" : "received").append(row);
  }
}
$("refresh").onclick = guard(refresh);
$("close").onclick = clearPreview;
$("download").onclick = guard(async () => {
  if (downloaded)
    save(
      from_base64(downloaded.data),
      downloaded.name.replace(/[\\/\x00-\x1f\x7f]/g, "_"),
    );
});
window.addEventListener("pagehide", () => {
  reset();
});
if (!globalThis.crypto?.subtle) {
  $("auth-form")
    .querySelectorAll("button")
    .forEach((b) => (b.disabled = true));
  status("Ta przeglądarka wymaga HTTPS lub localhost dla Web Crypto.", true);
}

$("resend").onclick = guard(async () => {
  const result = await api("/resend-verification", "POST", credentials());
  status(result.message);
});

// URL fragment stays in the browser and is removed before verification
let verificationToken = null;
function readVerificationLink() {
  const value = new URLSearchParams(location.hash.slice(1)).get("verify");
  if (!value) return;
  verificationToken = value;
  history.replaceState(null, "", location.pathname + location.search);
  $("verification").hidden = false;
}
readVerificationLink();
window.addEventListener("hashchange", readVerificationLink);
$("verify").onclick = guard(async () => {
  const result = await api("/verify-email", "POST", {token: verificationToken});
  verificationToken = null;
  $("verification").hidden = true;
  $("resend").hidden = true;
  status(result.message);
});
