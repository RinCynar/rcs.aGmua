const DEFAULT_KEY = "DEF-4164E792FC9AD1C9C866B3D6DCC79A27";
const APP_VERSION = "2.0.0";
const GITHUB_REPOSITORY = "RinCynar/rcs.aGmua";
const GITHUB_RELEASE_API = `https://api.github.com/repos/${GITHUB_REPOSITORY}/releases/latest`;
const GITHUB_RELEASE_LIST_API = `https://api.github.com/repos/${GITHUB_REPOSITORY}/releases?per_page=10`;
const GITHUB_RELEASE_PAGE = `https://github.com/${GITHUB_REPOSITORY}/releases`;
const LEGACY_UPDATE_URL = "https://aGmua.dpdns.org";
const LEGACY_DOWNLOADS = [
  { labelKey: "legacyPython", descriptionKey: "legacyPythonDescription", url: "https://aGmua.dpdns.org/file/aGmua.py" },
  { labelKey: "allLegacyFiles", descriptionKey: "legacyBundleDescription", url: "https://aGmua.dpdns.org/file/aGmua.zip" },
];

const TRANSLATIONS = {
  en: {
    appTitle: "RCS.aGmua",
    metaDescription: "RCS.aGmua text encryption utility and release downloads",
    primaryNavigation: "Primary navigation",
    language: "Language",
    tool: "Tool",
    downloads: "Downloads",
    darkMode: "Dark mode",
    lightMode: "Light mode",
    latestRelease: "Latest release",
    checkingReleases: "Checking GitHub Releases...",
    viewDownloads: "View downloads",
    localWorkspace: "Local workspace",
    workspaceTitle: "Encrypt and manage text",
    workspaceDescription: "Use the browser tool with a username-scoped local vault.",
    openVault: "Open a vault",
    usernameDescription: "Your username identifies the local vault. Nothing is sent to the server.",
    usernamePlaceholder: "Username",
    openTool: "Open tool",
    activeVault: "Active vault",
    changeUser: "Change user",
    cipherWorkspace: "Cipher workspace",
    encryptDecrypt: "Encrypt or decrypt",
    ready: "Ready",
    plainText: "Plain text",
    plainTextPlaceholder: "Enter text to encrypt",
    keyIndex: "Key index",
    keyIndexPlaceholder: "All for decrypt",
    encrypt: "Encrypt",
    decryptHex: "Decrypt hex",
    hexCiphertext: "Hex ciphertext",
    hexPlaceholder: "Paste hexadecimal ciphertext here",
    keyRing: "Key ring",
    savedKeys: "Saved keys",
    addKey: "Add a key",
    newKeyPlaceholder: "New key",
    add: "Add",
    resetVault: "Reset vault",
    encryptedLocalLog: "Encrypted local log",
    history: "History",
    clearHistory: "Clear history",
    noHistory: "No history records yet.",
    updates: "Updates",
    keepCurrent: "Keep the tool current",
    checkUpdates: "Check for updates",
    githubReleases: "GitHub Releases",
    downloadCurrent: "Download the current release",
    releaseDescription: "Assets are read from the latest public release. Legacy links remain available as a fallback.",
    currentVersion: "Current version",
    checking: "Checking...",
    releasePage: "Release page",
    loadingAssets: "Loading release assets...",
    compatibility: "Compatibility",
    legacyDownloads: "Legacy downloads",
    legacyDescription: "These links keep older update clients working while releases move to GitHub.",
    allLegacyFiles: "All legacy files",
    legacyPython: "Legacy Python tool",
    legacyPythonDescription: "Original Python CLI client",
    legacyBundleDescription: "Original version archive",
    sourceGithub: "Source on GitHub",
    mitLicense: "MIT License",
    keyItem: "{index}: {key}",
    delete: "Delete",
    download: "Download",
    tauriExecutable: "Tauri executable",
    sourceZip: "Source ZIP",
    apk: "APK",
    notAttached: "Not attached to this release",
    windowsX86: "Windows x86",
    windowsX64: "Windows x64",
    windowsArm64: "Windows arm64",
    linuxX86Source: "Linux x86 source",
    linuxX64Source: "Linux x64 source",
    linuxArm64Source: "Linux arm64 source",
    androidX86: "Android x86",
    androidX64: "Android x64",
    androidArmv7: "Android armv7",
    androidArmv8: "Android armv8",
    githubSource: "GitHub Releases",
    legacySource: "legacy endpoint",
    releaseStatus: "v{version} · {source}",
    releaseReady: "Choose a platform to download the matching artifact.",
    releaseNoAssets: "Release v{version} was found, but no downloadable assets are attached yet.",
    legacyStatus: "GitHub Releases is unavailable; showing legacy downloads.",
    legacyMessage: "GitHub Releases could not be reached. Use the compatibility links below.",
    noReleaseStatus: "No public GitHub Release found yet.",
    noReleaseMessage: "The release workflow has not published an asset yet. Legacy downloads remain available below.",
    unexpectedStatus: "Release data could not be loaded.",
    unavailable: "Unavailable",
    updateChecking: "Checking...",
    updateNew: "New version v{version}: {url}",
    updateCurrent: "You are using v{version}.",
    updateLegacy: "Using the legacy update endpoint (v{version}).",
    updateNoRelease: "No public Release is available yet.",
    updateFailed: "Update check failed; try the Releases page.",
    invalidKey: "Invalid key index",
    encrypted: "Encrypted",
    decrypted: "Decrypted",
    encryptionHistory: "Encrypted text: {cipher} with key {key}",
    decryptionHistory: "Decrypted text with key {key}: {text}",
    decryptionFailed: "Decryption failed with key {key}",
    resetConfirm: "Reset this vault and remove its local history?",
  },
  zh: {
    appTitle: "RCS.aGmua",
    metaDescription: "RCS.aGmua 文本加密工具和版本下载",
    primaryNavigation: "主导航",
    language: "语言",
    tool: "工具",
    downloads: "下载",
    darkMode: "深色模式",
    lightMode: "浅色模式",
    latestRelease: "最新版本",
    checkingReleases: "正在检查 GitHub Release……",
    viewDownloads: "查看下载",
    localWorkspace: "本地工作区",
    workspaceTitle: "加密并管理文本",
    workspaceDescription: "使用按用户名区分的本地数据空间。",
    openVault: "打开数据空间",
    usernameDescription: "用户名用于标识本地数据空间，不会发送到服务器。",
    usernamePlaceholder: "用户名",
    openTool: "打开工具",
    activeVault: "当前数据空间",
    changeUser: "切换用户",
    cipherWorkspace: "加密工作区",
    encryptDecrypt: "加密或解密",
    ready: "就绪",
    plainText: "明文",
    plainTextPlaceholder: "输入要加密的文本",
    keyIndex: "密钥编号",
    keyIndexPlaceholder: "解密时留空表示全部",
    encrypt: "加密",
    decryptHex: "解密十六进制",
    hexCiphertext: "十六进制密文",
    hexPlaceholder: "粘贴十六进制密文",
    keyRing: "密钥环",
    savedKeys: "已保存密钥",
    addKey: "添加密钥",
    newKeyPlaceholder: "新密钥",
    add: "添加",
    resetVault: "重置数据空间",
    encryptedLocalLog: "加密本地记录",
    history: "历史记录",
    clearHistory: "清空历史",
    noHistory: "暂无历史记录。",
    updates: "更新",
    keepCurrent: "保持工具最新",
    checkUpdates: "检查更新",
    githubReleases: "GitHub Releases",
    downloadCurrent: "下载当前版本",
    releaseDescription: "从最新公开 Release 读取文件；同时保留旧版下载链接。",
    currentVersion: "当前版本",
    checking: "检查中……",
    releasePage: "Release 页面",
    loadingAssets: "正在加载 Release 文件……",
    compatibility: "兼容性",
    legacyDownloads: "旧版下载",
    legacyDescription: "这些链接用于继续支持旧版本更新客户端。",
    allLegacyFiles: "全部旧版文件",
    legacyPython: "旧版 Python 工具",
    legacyPythonDescription: "原版 Python 命令行工具",
    legacyBundleDescription: "原版文件压缩包",
    sourceGithub: "在 GitHub 查看源码",
    mitLicense: "MIT 许可证",
    keyItem: "{index}：{key}",
    delete: "删除",
    download: "下载",
    tauriExecutable: "Tauri 可执行文件",
    sourceZip: "源码 ZIP",
    apk: "APK",
    notAttached: "此 Release 尚未附加",
    windowsX86: "Windows x86",
    windowsX64: "Windows x64",
    windowsArm64: "Windows arm64",
    linuxX86Source: "Linux x86 源码",
    linuxX64Source: "Linux x64 源码",
    linuxArm64Source: "Linux arm64 源码",
    androidX86: "Android x86",
    androidX64: "Android x64",
    androidArmv7: "Android armv7",
    androidArmv8: "Android armv8",
    githubSource: "GitHub Releases",
    legacySource: "旧版接口",
    releaseStatus: "v{version} · {source}",
    releaseReady: "选择平台下载对应文件。",
    releaseNoAssets: "已找到 v{version}，但暂时没有可下载文件。",
    legacyStatus: "GitHub Releases 暂不可用，正在显示旧版下载。",
    legacyMessage: "无法访问 GitHub Releases，请使用下方兼容链接。",
    noReleaseStatus: "尚未找到公开的 GitHub Release。",
    noReleaseMessage: "发布流程还没有上传文件；下方仍提供旧版下载。",
    unexpectedStatus: "无法加载 Release 数据。",
    unavailable: "不可用",
    updateChecking: "检查中……",
    updateNew: "发现新版本 v{version}：{url}",
    updateCurrent: "当前已经是 v{version}。",
    updateLegacy: "正在使用旧版更新接口（v{version}）。",
    updateNoRelease: "目前还没有公开 Release。",
    updateFailed: "更新检查失败，请打开 Releases 页面。",
    invalidKey: "密钥编号无效",
    encrypted: "已加密",
    decrypted: "已解密",
    encryptionHistory: "已加密文本：{cipher}，使用密钥 {key}",
    decryptionHistory: "使用密钥 {key} 解密：{text}",
    decryptionFailed: "使用密钥 {key} 解密失败",
    resetConfirm: "确定要重置数据空间并删除本地历史吗？",
  },
  ja: {
    appTitle: "RCS.aGmua",
    metaDescription: "RCS.aGmua テキスト暗号化ツールとリリースのダウンロード",
    primaryNavigation: "メインナビゲーション",
    language: "言語",
    tool: "ツール",
    downloads: "ダウンロード",
    darkMode: "ダークモード",
    lightMode: "ライトモード",
    latestRelease: "最新リリース",
    checkingReleases: "GitHub Releases を確認中…",
    viewDownloads: "ダウンロードを見る",
    localWorkspace: "ローカルワークスペース",
    workspaceTitle: "テキストを暗号化・管理",
    workspaceDescription: "ユーザー名ごとのローカル保管領域でツールを使用します。",
    openVault: "保管領域を開く",
    usernameDescription: "ユーザー名はローカル保管領域の識別にのみ使われ、サーバーには送信されません。",
    usernamePlaceholder: "ユーザー名",
    openTool: "ツールを開く",
    activeVault: "使用中の保管領域",
    changeUser: "ユーザーを変更",
    cipherWorkspace: "暗号ワークスペース",
    encryptDecrypt: "暗号化または復号",
    ready: "準備完了",
    plainText: "平文",
    plainTextPlaceholder: "暗号化するテキストを入力",
    keyIndex: "キー番号",
    keyIndexPlaceholder: "復号時は空欄で全キー",
    encrypt: "暗号化",
    decryptHex: "16進数を復号",
    hexCiphertext: "16進数の暗号文",
    hexPlaceholder: "16進数の暗号文を貼り付け",
    keyRing: "キーリング",
    savedKeys: "保存済みキー",
    addKey: "キーを追加",
    newKeyPlaceholder: "新しいキー",
    add: "追加",
    resetVault: "保管領域をリセット",
    encryptedLocalLog: "暗号化されたローカル記録",
    history: "履歴",
    clearHistory: "履歴を消去",
    noHistory: "履歴はまだありません。",
    updates: "更新",
    keepCurrent: "ツールを最新に保つ",
    checkUpdates: "更新を確認",
    githubReleases: "GitHub Releases",
    downloadCurrent: "最新リリースをダウンロード",
    releaseDescription: "最新の公開リリースからファイルを読み込み、旧版リンクも残します。",
    currentVersion: "現在のバージョン",
    checking: "確認中…",
    releasePage: "Release ページ",
    loadingAssets: "Release ファイルを読み込み中…",
    compatibility: "互換性",
    legacyDownloads: "旧版ダウンロード",
    legacyDescription: "旧バージョンの更新クライアントを引き続き利用するためのリンクです。",
    allLegacyFiles: "旧版ファイル一式",
    legacyPython: "旧版 Python ツール",
    legacyPythonDescription: "旧版 Python コマンドラインツール",
    legacyBundleDescription: "旧版ファイルのアーカイブ",
    sourceGithub: "GitHub のソースコード",
    mitLicense: "MIT ライセンス",
    keyItem: "{index}：{key}",
    delete: "削除",
    download: "ダウンロード",
    tauriExecutable: "Tauri 実行ファイル",
    sourceZip: "ソース ZIP",
    apk: "APK",
    notAttached: "この Release に添付されていません",
    windowsX86: "Windows x86",
    windowsX64: "Windows x64",
    windowsArm64: "Windows arm64",
    linuxX86Source: "Linux x86 ソース",
    linuxX64Source: "Linux x64 ソース",
    linuxArm64Source: "Linux arm64 ソース",
    androidX86: "Android x86",
    androidX64: "Android x64",
    androidArmv7: "Android armv7",
    androidArmv8: "Android armv8",
    githubSource: "GitHub Releases",
    legacySource: "旧版エンドポイント",
    releaseStatus: "v{version} · {source}",
    releaseReady: "プラットフォームを選んで対応ファイルをダウンロードしてください。",
    releaseNoAssets: "v{version} は見つかりましたが、ダウンロードファイルはまだ添付されていません。",
    legacyStatus: "GitHub Releases を利用できないため、旧版ダウンロードを表示しています。",
    legacyMessage: "GitHub Releases に接続できません。下の互換リンクを使用してください。",
    noReleaseStatus: "公開された GitHub Release はまだありません。",
    noReleaseMessage: "リリースワークフローはまだファイルを公開していません。下に旧版ダウンロードがあります。",
    unexpectedStatus: "Release データを読み込めませんでした。",
    unavailable: "利用できません",
    updateChecking: "確認中…",
    updateNew: "新しい v{version} があります：{url}",
    updateCurrent: "現在 v{version} を使用しています。",
    updateLegacy: "旧版更新エンドポイントを使用中です（v{version}）。",
    updateNoRelease: "公開された Release はまだありません。",
    updateFailed: "更新確認に失敗しました。Releases ページを確認してください。",
    invalidKey: "キー番号が無効です",
    encrypted: "暗号化しました",
    decrypted: "復号しました",
    encryptionHistory: "暗号化済みテキスト：{cipher}（キー {key}）",
    decryptionHistory: "キー {key} で復号：{text}",
    decryptionFailed: "キー {key} で復号できませんでした",
    resetConfirm: "この保管領域をリセットしてローカル履歴を削除しますか？",
  },
};

const state = {
  username: "",
  storageKey: "",
  keys: [DEFAULT_KEY],
  history: [],
  release: null,
  language: detectLanguage(),
  operationStatus: { key: "ready", vars: {}, error: false },
};

const $ = (id) => document.getElementById(id);

function detectLanguage() {
  const saved = localStorage.getItem("rcs.language");
  if (saved && TRANSLATIONS[saved]) return saved;
  const languages = navigator.languages || [navigator.language || "en"];
  for (const language of languages) {
    const prefix = language.toLowerCase().split("-")[0];
    if (TRANSLATIONS[prefix]) return prefix;
  }
  return "en";
}

function localeFor(language = state.language) {
  return { zh: "zh-CN", ja: "ja-JP", en: "en-US" }[language] || "en-US";
}

function t(key, vars = {}) {
  const template = TRANSLATIONS[state.language]?.[key] || TRANSLATIONS.en[key] || key;
  return Object.entries(vars).reduce((value, [name, replacement]) => value.replaceAll(`{${name}}`, String(replacement)), template);
}

function applyTranslations() {
  document.documentElement.lang = state.language === "zh" ? "zh-CN" : state.language === "ja" ? "ja-JP" : "en";
  document.title = t("appTitle");
  document.querySelectorAll("[data-i18n]").forEach((element) => { element.textContent = t(element.dataset.i18n); });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((element) => { element.placeholder = t(element.dataset.i18nPlaceholder); });
  document.querySelectorAll("[data-i18n-aria-label]").forEach((element) => { element.setAttribute("aria-label", t(element.dataset.i18nAriaLabel)); });
  document.querySelectorAll("[data-i18n-content]").forEach((element) => { element.setAttribute("content", t(element.dataset.i18nContent)); });
  $("language-select").value = state.language;
  $("theme-toggle").textContent = document.body.classList.contains("dark") ? t("lightMode") : t("darkMode");
  renderOperationStatus();
  if (state.release) renderRelease(state.release);
}

function setLanguage(language) {
  if (!TRANSLATIONS[language]) return;
  state.language = language;
  localStorage.setItem("rcs.language", language);
  applyTranslations();
  renderKeys();
  renderHistory();
  $("update-status").textContent = "";
}

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
    value.textContent = t("keyItem", { index, key });
    row.append(value);
    if (index > 0) {
      const remove = document.createElement("button");
      remove.type = "button";
      remove.textContent = t("delete");
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
    time.textContent = new Date(record.time).toLocaleString(localeFor());
    item.append(time);
    list.append(item);
  });
}

function renderOperationStatus() {
  const status = state.operationStatus;
  $("operation-status").textContent = t(status.key, status.vars);
  $("operation-status").style.color = status.error ? "var(--danger)" : "var(--success)";
}

function setStatus(key, vars = {}, error = false) {
  state.operationStatus = { key, vars, error };
  renderOperationStatus();
}

function selectedKeys() {
  const raw = $("key-index").value.trim();
  if (!raw) return state.keys;
  const index = Number(raw);
  if (!Number.isInteger(index) || !state.keys[index]) throw new Error(t("invalidKey"));
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
  if (view === "downloads" && !state.release) loadRelease();
}

function assetMatches(name, target) {
  const normalized = name.toLowerCase();
  return target.patterns.some((pattern) => normalized.includes(pattern));
}

function renderAssets(release) {
  const targets = [
    { labelKey: "windowsX86", descriptionKey: "tauriExecutable", patterns: ["windows-x86", "win-x86"] },
    { labelKey: "windowsX64", descriptionKey: "tauriExecutable", patterns: ["windows-x64", "win-x64"] },
    { labelKey: "windowsArm64", descriptionKey: "tauriExecutable", patterns: ["windows-arm64", "win-arm64"] },
    { labelKey: "linuxX86Source", descriptionKey: "sourceZip", patterns: ["linux-x86-source"] },
    { labelKey: "linuxX64Source", descriptionKey: "sourceZip", patterns: ["linux-x64-source"] },
    { labelKey: "linuxArm64Source", descriptionKey: "sourceZip", patterns: ["linux-arm64-source"] },
    { labelKey: "androidX86", descriptionKey: "apk", patterns: ["android-x86.apk"] },
    { labelKey: "androidX64", descriptionKey: "apk", patterns: ["android-x64.apk", "android-x86_64.apk"] },
    { labelKey: "androidArmv7", descriptionKey: "apk", patterns: ["android-armv7.apk"] },
    { labelKey: "androidArmv8", descriptionKey: "apk", patterns: ["android-armv8.apk", "android-arm64.apk"] },
  ];
  const grid = $("asset-grid");
  grid.replaceChildren();
  targets.forEach((target) => {
    const asset = release.assets.find((item) => assetMatches(item.name, target));
    const card = document.createElement("article");
    card.className = "asset-card";
    const title = document.createElement("h3");
    title.textContent = t(target.labelKey);
    const description = document.createElement("p");
    description.textContent = asset ? `${t(target.descriptionKey)} · ${asset.name}` : t("notAttached");
    card.append(title, description);
    if (asset) {
      const link = document.createElement("a");
      link.className = "primary-button link-button";
      link.href = asset.url;
      link.target = "_blank";
      link.rel = "noreferrer";
      link.textContent = t("download");
      card.append(link);
    }
    grid.append(card);
  });
}

function parseRelease(payload, sourceKey) {
  const tag = Array.isArray(payload) ? payload[0]?.tag_name || payload[0]?.name : payload?.tag_name || payload?.name;
  const version = String(tag || "").match(/\d+(?:\.\d+){1,2}/)?.[0];
  if (!version) return null;
  const data = Array.isArray(payload) ? payload[0] : payload;
  return {
    status: "release",
    version,
    url: data.html_url || GITHUB_RELEASE_PAGE,
    assets: (data.assets || []).map((asset) => ({ name: asset.name, url: asset.browser_download_url })).filter((asset) => asset.name && asset.url),
    sourceKey,
  };
}

async function fetchJson(url) {
  const separator = url.includes("?") ? "&" : "?";
  const response = await fetch(`${url}${separator}_=${Date.now()}`, {
    headers: { Accept: "application/vnd.github+json" },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`Release API ${response.status}`);
  return response.json();
}

async function fetchLegacyRelease() {
  const response = await fetch(LEGACY_UPDATE_URL, { cache: "no-store" });
  if (!response.ok) throw new Error(`Legacy endpoint ${response.status}`);
  const text = await response.text();
  const version = text.match(/(?<!\d)\d+(?:\.\d+){1,2}(?!\d)/)?.[0] || APP_VERSION;
  return { status: "legacy", version, url: LEGACY_UPDATE_URL, assets: [], sourceKey: "legacySource" };
}

async function fetchRelease() {
  try {
    const latest = parseRelease(await fetchJson(GITHUB_RELEASE_API), "githubSource");
    if (latest) return latest;
  } catch (error) {
    // The list endpoint can still work when /latest returns 404 or is rate limited.
  }

  try {
    const list = await fetchJson(GITHUB_RELEASE_LIST_API);
    const published = Array.isArray(list) ? list.filter((release) => !release.draft) : [];
    const release = parseRelease(published, "githubSource");
    if (release) return release;
    return { status: "none", version: "", url: GITHUB_RELEASE_PAGE, assets: [], sourceKey: "githubSource" };
  } catch (error) {
    try {
      return await fetchLegacyRelease();
    } catch (legacyError) {
      return { status: "none", version: "", url: GITHUB_RELEASE_PAGE, assets: [], sourceKey: "githubSource" };
    }
  }
}

function renderRelease(release) {
  $("release-page").href = release.url || GITHUB_RELEASE_PAGE;
  if (release.status === "release") {
    $("release-version").textContent = `v${release.version}`;
    $("release-strip-version").textContent = t("releaseStatus", { version: release.version, source: t(release.sourceKey) });
    $("release-message").textContent = release.assets.length ? t("releaseReady") : t("releaseNoAssets", { version: release.version });
  } else if (release.status === "legacy") {
    $("release-version").textContent = `v${release.version}`;
    $("release-strip-version").textContent = t("legacyStatus");
    $("release-message").textContent = t("legacyMessage");
  } else {
    $("release-version").textContent = t("unavailable");
    $("release-strip-version").textContent = t("noReleaseStatus");
    $("release-message").textContent = t("noReleaseMessage");
  }
  renderAssets(release);
}

async function loadRelease() {
  $("release-message").textContent = t("loadingAssets");
  try {
    state.release = await fetchRelease();
    renderRelease(state.release);
  } catch (error) {
    state.release = { status: "none", version: "", url: GITHUB_RELEASE_PAGE, assets: [], sourceKey: "githubSource" };
    $("release-strip-version").textContent = t("unexpectedStatus");
    $("release-version").textContent = t("unavailable");
    $("release-message").textContent = t("noReleaseMessage");
    renderAssets(state.release);
  }
}

function compareVersions(left, right) {
  const a = left.split(".").map(Number);
  const b = right.split(".").map(Number);
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
    if ((a[index] || 0) !== (b[index] || 0)) return (a[index] || 0) > (b[index] || 0) ? 1 : -1;
  }
  return 0;
}

async function checkUpdate() {
  $("update-status").textContent = t("updateChecking");
  try {
    const release = await fetchRelease();
    if (release.status === "none") {
      $("update-status").textContent = t("updateNoRelease");
    } else if (release.status === "legacy") {
      $("update-status").textContent = t("updateLegacy", { version: release.version });
    } else if (compareVersions(release.version, APP_VERSION) > 0) {
      $("update-status").textContent = t("updateNew", { version: release.version, url: release.url });
    } else {
      $("update-status").textContent = t("updateCurrent", { version: APP_VERSION });
    }
  } catch (error) {
    $("update-status").textContent = t("updateFailed");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  if (localStorage.getItem("rcs.theme") === "dark") document.body.classList.add("dark");
  applyTranslations();
  $("language-select").addEventListener("change", (event) => setLanguage(event.target.value));
  $("theme-toggle").addEventListener("click", () => {
    document.body.classList.toggle("dark");
    localStorage.setItem("rcs.theme", document.body.classList.contains("dark") ? "dark" : "light");
    applyTranslations();
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
      if (!Number.isInteger(index) || !state.keys[index]) throw new Error(t("invalidKey"));
      const result = encryptValue(state.keys[index], $("plaintext").value);
      $("ciphertext").value = result;
      addHistory("encrypt", t("encryptionHistory", { cipher: result, key: state.keys[index].slice(0, 3) }));
      renderHistory();
      setStatus("encrypted");
    } catch (error) { setStatus("invalidKey", {}, true); }
  });
  $("decrypt-button").addEventListener("click", () => {
    try {
      const results = selectedKeys().map((key) => {
        try { return t("decryptionHistory", { key: key.slice(0, 3), text: decryptValue(key, $("ciphertext").value) }); }
        catch (error) { return t("decryptionFailed", { key: key.slice(0, 3) }); }
      });
      $("plaintext").value = results.join("\n");
      results.forEach((result) => addHistory("decrypt", result));
      renderHistory();
      setStatus("decrypted");
    } catch (error) { setStatus("invalidKey", {}, true); }
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
    if (!window.confirm(t("resetConfirm"))) return;
    state.keys = [DEFAULT_KEY];
    state.history = [];
    saveVault();
    renderKeys();
    renderHistory();
  });
  $("check-update").addEventListener("click", checkUpdate);
  loadRelease();
});
