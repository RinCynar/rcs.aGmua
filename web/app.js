const DEFAULT_KEY = "DEF-4164E792FC9AD1C9C866B3D6DCC79A27";
const APP_VERSION = "2.0.0";
const GITHUB_RELEASE_API = "https://api.github.com/repos/RinCynar/rcs.aGmua/releases/latest";
const LEGACY_DOWNLOADS = [
  { label: "Legacy Python", description: "Original CLI client", url: "https://aGmua.dpdns.org/file/aGmua.py" },
  { label: "Legacy bundle", description: "Original version archive", url: "https://aGmua.dpdns.org/file/aGmua.zip" }
];

const state = {
  username: "",
  storageKey: "",
  keys: [DEFAULT_KEY],
  history: [],
  release: null,
};

const $ = (id) => document.getElementById(id);

function utf16Bytes(value) {
  const bytes = new Uint8Array(2 + value.length * 2);
  bytes[0] = 0xff;
  bytes[1] = 0xfe;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    bytes[2 + index * 2] = code & 0xff;
    bytes[3 + index * 2] = code >> 8;
  }
  return bytes;
}

function utf16Text(bytes) {
  let offset = 0;
  let littleEndian = true;
  if (bytes[0] === 0xff && bytes[1] === 0xfe) offset = 2;
  if (bytes[0] === 0xfe && bytes[1] === 0xff) {
    offset = 2;
    littleEndian = false;
  }
  const units = [];
  for (let index = offset; index + 1 < bytes.length; index += 2) {
    units.push(littleEndian ? bytes[index] | (bytes[index + 1] << 8) : (bytes[index] << 8) | bytes[index + 1]);
  }
  let result = "";
  for (let index = 0; index < units.length; index += 4096) result += String.fromCharCode(...units.slice(index, index + 4096));
  return result;
}

function rc4(key, data) {
  if (!key.length) throw new Error("RC4 requires a non-empty key");
  const box = Array.from({ length: 256 }, (_, index) => index);
  let j = 0;
  for (let i = 0; i < 256; i += 1) {
    j = (j + box[i] + key[i % key.length]) & 255;
    [box[i], box[j]] = [box[j], box[i]];
  }
  const result = new Uint8Array(data.length);
  let i = 0;
  j = 0;
  for (let index = 0; index < data.length; index += 1) {
    i = (i + 1) & 255;
    j = (j + box[i]) & 255;
    [box[i], box[j]] = [box[j], box[i]];
    result[index] = data[index] ^ box[(box[i] + box[j]) & 255];
  }
  return result;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("").toUpperCase();
}

function hexToBytes(value) {
  const compact = value.replace(/\s+/g, "");
  if (!compact || compact.length % 2 || !/^[0-9a-f]+$/i.test(compact)) throw new Error("Invalid hexadecimal ciphertext");
  const bytes = new Uint8Array(compact.length / 2);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = parseInt(compact.slice(index * 2, index * 2 + 2), 16);
  return bytes;
}

function encryptValue(key, plaintext) {
  return bytesToHex(rc4(utf16Bytes(key), utf16Bytes(plaintext)));
}

function decryptValue(key, ciphertext) {
  return utf16Text(rc4(utf16Bytes(key), hexToBytes(ciphertext)));
}

function identityFor(username) {
  return bytesToHex(rc4(utf16Bytes(username), utf16Bytes(username)));
}

function saveVault() {
  localStorage.setItem(state.storageKey, JSON.stringify({ keys: state.keys, history: state.history }));
}

function loadVault(username) {
  state.username = username.trim();
  state.storageKey = `rcs.v2.${identityFor(state.username)}`;
  const stored = JSON.parse(localStorage.getItem(state.storageKey) || "null");
  state.keys = [DEFAULT_KEY, ...(stored?.keys || []).filter((key) => key && key !== DEFAULT_KEY && key !== state.username)];
  state.keys = [...new Set(state.keys)];
  state.history = Array.isArray(stored?.history) ? stored.history : [];
  saveVault();
}

function addHistory(kind, text) {
  state.history.unshift({ kind, text, time: new Date().toISOString() });
  state.history = state.history.slice(0, 100);
  saveVault();
}

function renderKeys() {
  $("key-count").textContent = String(state.keys.length);
  const list = $("key-list");
  list.replaceChildren();
  state.keys.forEach((key, index) => {
    const row = document.createElement("div");
    row.className = "key-row";
    const value = document.createElement("code");
    value.textContent = `${index}: ${key}`;
    row.append(value);
    if (index > 0) {
      const remove = document.createElement("button");
      remove.type = "button";
      remove.textContent = "Delete";
      remove.addEventListener("click", () => {
        state.keys.splice(index, 1);
        saveVault();
        renderKeys();
      });
      row.append(remove);
    }
    list.append(row);
  });
}

function renderHistory() {
  const list = $("history-list");
  list.replaceChildren();
  $("empty-history").classList.toggle("hidden", state.history.length > 0);
  state.history.forEach((record) => {
    const item = document.createElement("li");
    item.textContent = record.text;
    const time = document.createElement("time");
    time.textContent = new Date(record.time).toLocaleString();
    item.append(time);
    list.append(item);
  });
}

function setStatus(text, isError = false) {
  $("operation-status").textContent = text;
  $("operation-status").style.color = isError ? "var(--danger)" : "var(--success)";
}

function selectedKeys() {
  const raw = $("key-index").value.trim();
  if (!raw) return state.keys;
  const index = Number(raw);
  if (!Number.isInteger(index) || !state.keys[index]) throw new Error("Invalid key index");
  return [state.keys[index]];
}

function openTool(username) {
  loadVault(username);
  $("active-username").textContent = state.username;
  $("login-panel").classList.add("hidden");
  $("tool-panel").classList.remove("hidden");
  renderKeys();
  renderHistory();
}

function showView(view) {
  document.querySelectorAll(".view").forEach((item) => item.classList.toggle("active", item.id === `${view}-view`));
  document.querySelectorAll(".nav-button").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
  if (view === "downloads") loadRelease();
}

function assetMatches(name, target) {
  const normalized = name.toLowerCase();
  return target.patterns.some((pattern) => normalized.includes(pattern));
}

function renderAssets(release) {
  const targets = [
    { label: "Windows x86", description: "Tauri executable", patterns: ["windows-x86", "win-x86"] },
    { label: "Windows x64", description: "Tauri executable", patterns: ["windows-x64", "win-x64"] },
    { label: "Windows arm64", description: "Tauri executable", patterns: ["windows-arm64", "win-arm64"] },
    { label: "Linux x86 source", description: "Source ZIP", patterns: ["linux-x86-source"] },
    { label: "Linux x64 source", description: "Source ZIP", patterns: ["linux-x64-source"] },
    { label: "Linux arm64 source", description: "Source ZIP", patterns: ["linux-arm64-source"] },
    { label: "Android x86", description: "APK", patterns: ["android-x86.apk"] },
    { label: "Android x64", description: "APK", patterns: ["android-x64.apk", "android-x86_64.apk"] },
    { label: "Android armv7", description: "APK", patterns: ["android-armv7.apk"] },
    { label: "Android armv8", description: "APK", patterns: ["android-armv8.apk", "android-arm64.apk"] },
  ];
  const grid = $("asset-grid");
  grid.replaceChildren();
  targets.forEach((target) => {
    const asset = release.assets.find((item) => assetMatches(item.name, target));
    const card = document.createElement("article");
    card.className = "asset-card";
    const title = document.createElement("h3");
    title.textContent = target.label;
    const description = document.createElement("p");
    description.textContent = asset ? `${target.description} · ${asset.name}` : "Not attached to this release";
    card.append(title, description);
    if (asset) {
      const link = document.createElement("a");
      link.className = "primary-button link-button";
      link.href = asset.url;
      link.target = "_blank";
      link.rel = "noreferrer";
      link.textContent = "Download";
      card.append(link);
    }
    grid.append(card);
  });
}

async function fetchRelease() {
  try {
    const response = await fetch(GITHUB_RELEASE_API, { headers: { Accept: "application/vnd.github+json" }, cache: "no-store" });
    if (!response.ok) throw new Error(`GitHub API ${response.status}`);
    const data = await response.json();
    const version = (data.tag_name || data.name || "").match(/\d+(?:\.\d+){1,2}/)?.[0];
    if (!version) throw new Error("Release has no version");
    return { version, url: data.html_url, assets: (data.assets || []).map((asset) => ({ name: asset.name, url: asset.browser_download_url })), source: "GitHub Releases" };
  } catch (error) {
    const response = await fetch("https://aGmua.dpdns.org", { cache: "no-store" });
    const text = await response.text();
    const version = text.match(/(?<!\d)\d+(?:\.\d+){1,2}(?!\d)/)?.[0] || APP_VERSION;
    return { version, url: "https://aGmua.dpdns.org", assets: LEGACY_DOWNLOADS, source: "legacy endpoint" };
  }
}

async function loadRelease() {
  $("release-message").textContent = "Loading release assets...";
  try {
    state.release = await fetchRelease();
    $("release-version").textContent = `v${state.release.version}`;
    $("release-strip-version").textContent = `v${state.release.version} · ${state.release.source}`;
    $("release-page").href = state.release.url;
    $("release-message").textContent = "Choose a platform to download the matching artifact.";
    renderAssets(state.release);
  } catch (error) {
    $("release-message").textContent = "Release data is unavailable. Use the legacy links below or open GitHub directly.";
    $("release-version").textContent = "Unavailable";
    $("release-strip-version").textContent = "Release check unavailable";
  }
}

async function checkUpdate() {
  $("update-status").textContent = "Checking...";
  try {
    const release = await fetchRelease();
    const current = APP_VERSION.split(".").map(Number);
    const remote = release.version.split(".").map(Number);
    const newer = remote.some((value, index) => value > (current[index] || 0)) && !remote.every((value, index) => value === (current[index] || 0));
    $("update-status").textContent = newer ? `New version v${release.version}: ${release.url}` : `You are using v${APP_VERSION}.`;
  } catch (error) {
    $("update-status").textContent = "Update check failed; try the Releases page.";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  if (localStorage.getItem("rcs.theme") === "dark") document.body.classList.add("dark");
  $("theme-toggle").addEventListener("click", () => {
    document.body.classList.toggle("dark");
    localStorage.setItem("rcs.theme", document.body.classList.contains("dark") ? "dark" : "light");
    $("theme-toggle").textContent = document.body.classList.contains("dark") ? "Light mode" : "Dark mode";
  });
  document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => showView(button.dataset.view)));
  $("release-strip-button").addEventListener("click", () => showView("downloads"));
  $("login-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const username = $("username").value.trim();
    if (username) openTool(username);
  });
  $("change-user").addEventListener("click", () => {
    $("tool-panel").classList.add("hidden");
    $("login-panel").classList.remove("hidden");
    $("username").focus();
  });
  $("encrypt-button").addEventListener("click", () => {
    try {
      const index = Number($("key-index").value || 0);
      if (!Number.isInteger(index) || !state.keys[index]) throw new Error("Invalid key index");
      const result = encryptValue(state.keys[index], $("plaintext").value);
      $("ciphertext").value = result;
      addHistory("encrypt", `Encrypted text: ${result} with key ${state.keys[index].slice(0, 3)}`);
      renderHistory();
      setStatus("Encrypted");
    } catch (error) { setStatus(error.message, true); }
  });
  $("decrypt-button").addEventListener("click", () => {
    try {
      const results = selectedKeys().map((key) => {
        try { return `Decrypted text with key ${key.slice(0, 3)}: ${decryptValue(key, $("ciphertext").value)}`; }
        catch (error) { return `Decryption failed with key ${key.slice(0, 3)}`; }
      });
      $("plaintext").value = results.join("\n");
      results.forEach((result) => addHistory("decrypt", result));
      renderHistory();
      setStatus("Decrypted");
    } catch (error) { setStatus(error.message, true); }
  });
  $("add-key-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const key = $("new-key").value.trim();
    if (key && !state.keys.includes(key)) {
      state.keys.push(key);
      saveVault();
      renderKeys();
      $("new-key").value = "";
    }
  });
  $("clear-history").addEventListener("click", () => { state.history = []; saveVault(); renderHistory(); });
  $("reset-button").addEventListener("click", () => {
    if (!window.confirm("Reset this vault and remove its local history?")) return;
    state.keys = [DEFAULT_KEY];
    state.history = [];
    saveVault();
    renderKeys();
    renderHistory();
  });
  $("check-update").addEventListener("click", checkUpdate);
  loadRelease();
});

