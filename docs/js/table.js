import { loadConfig } from "./config.js";
import { searchFragment } from "./searchFragment.js";
let config = null;

let tableInitialized = false;
let preloadingStarted = false;
let preloadedData = null;
let preloadingPromise = null;
let dataReady = false;

// Kick off background data fetch as early as possible (before any UI work)
if (!localStorage.getItem("loggedIn")) {
  console.info("[preload] early data fetch: starting");
  preloadingPromise = fetch("https://evolve-dzlb.onrender.com/clients")
    .then((r) => r.json())
    .then((d) => {
      preloadedData = d;
      console.info(
        "[preload] early data fetch: resolved",
        Array.isArray(d) ? d.length : d
      );
      return d;
    })
    .catch((e) => {
      console.warn("[preload] early data fetch failed:", e);
      return null;
    });
}

(async () => {
  config = await loadConfig();
})();

// SHA-256 helper
async function sha256(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Encryption helpers (AES-GCM) **/
function hexToBytes(hex) {
  if (!hex || hex.length % 2 !== 0) throw new Error("Invalid hex string");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function bytesToHex(buf) {
  const a = new Uint8Array(buf);
  return Array.from(a)
    .slice(0, 16)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
function guessMimeFromBytes(buf) {
  const a = new Uint8Array(buf);
  if (a[0] === 0x89 && a[1] === 0x50 && a[2] === 0x4e && a[3] === 0x47)
    return "image/png"; // PNG
  if (a[0] === 0xff && a[1] === 0xd8 && a[2] === 0xff) return "image/jpeg"; // JPEG
  return "application/octet-stream";
}

async function tryDecryptWithLayout(encBuffer, keyBytes, layout) {
  // layout: "iv|cipher|tag" or "iv|tag|cipher"
  const total = encBuffer.byteLength;
  if (total < 12 + 16)
    throw new Error("Encrypted buffer too short (<28 bytes).");
  let iv, ciphertext, tag;
  if (layout === "iv|cipher|tag") {
    iv = encBuffer.slice(0, 12);
    tag = encBuffer.slice(total - 16, total);
    ciphertext = encBuffer.slice(12, total - 16);
  } else if (layout === "iv|tag|cipher") {
    iv = encBuffer.slice(0, 12);
    tag = encBuffer.slice(12, 28); // 12..28
    ciphertext = encBuffer.slice(28);
  } else {
    throw new Error("Unknown layout");
  }

  console.log(
    `[tryDecrypt] layout=${layout} total=${total} iv_len=${iv.byteLength} cipher_len=${ciphertext.byteLength} tag_len=${tag.byteLength}`
  );
  console.log(
    `[tryDecrypt] iv(hex)=${bytesToHex(iv)} tag(hex)=${bytesToHex(tag)}`
  );

  // WebCrypto expects ciphertext||tag as input
  const cView = new Uint8Array(ciphertext);
  const tView = new Uint8Array(tag);
  const combined = new Uint8Array(cView.length + tView.length);
  combined.set(cView, 0);
  combined.set(tView, cView.length);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(iv) },
    cryptoKey,
    combined.buffer
  );
  return plain; // ArrayBuffer (throws if auth fails)
}

async function decryptImageFromUrl(url, hexKey) {
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
  const encBuffer = await resp.arrayBuffer();
  const keyBytes = hexToBytes(hexKey);
  if (![16, 24, 32].includes(keyBytes.length))
    throw new Error("Key must be 16/24/32 bytes (32/48/64 hex chars)");

  let plainBuffer = null;
  try {
    plainBuffer = await tryDecryptWithLayout(
      encBuffer,
      keyBytes,
      "iv|cipher|tag"
    );
  } catch (e1) {
    try {
      plainBuffer = await tryDecryptWithLayout(
        encBuffer,
        keyBytes,
        "iv|tag|cipher"
      );
    } catch (e2) {
      throw new Error("Decryption failed for both layouts");
    }
  }

  const mime = guessMimeFromBytes(plainBuffer);
  const blob = new Blob([plainBuffer], { type: mime });
  return URL.createObjectURL(blob);
}

// Fallback avatar (inline SVG) shown while decrypting or if decrypt fails
const FALLBACK_AVATAR =
  "data:image/svg+xml;utf8,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Ccircle cx='32' cy='32' r='32' fill='%23374151'/%3E%3Ccircle cx='32' cy='24' r='12' fill='%239CA3AF'/%3E%3Cpath d='M12 54c4-10 16-14 20-14s16 4 20 14' fill='%239CA3AF'/%3E%3C/svg%3E";

async function setDecryptedImg(imgEl, encUrl, hexKey) {
  try {
    imgEl.src = FALLBACK_AVATAR;
    await loadImage(encUrl, hexKey, imgEl);
  } catch (e) {
    console.warn("Image decrypt failed:", e);
    imgEl.src = FALLBACK_AVATAR;
  }
}

// Optional demo helper from snippet; unused here but kept for parity
async function loadImage(urlOverride, hexKeyOverride, imgElOverride) {
  const url = urlOverride ?? document.getElementById("urlInput")?.value?.trim();
  const hexKey =
    hexKeyOverride ?? document.getElementById("keyInput")?.value?.trim();
  const imgEl = imgElOverride ?? document.getElementById("outImg");
  if (!url || !hexKey || !imgEl) {
    throw new Error("Missing URL, hex key or target <img> element");
  }

  try {
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
    const encBuffer = await resp.arrayBuffer();
    console.log("[loadImage] fetched bytes:", encBuffer.byteLength);

    const keyBytes = hexToBytes(hexKey);
    if (![16, 24, 32].includes(keyBytes.length))
      throw new Error("Key must be 16/24/32 bytes (32/48/64 hex chars)");

    let plainBuffer = null;
    let usedLayout = null;
    try {
      plainBuffer = await tryDecryptWithLayout(
        encBuffer,
        keyBytes,
        "iv|cipher|tag"
      );
      usedLayout = "iv|cipher|tag";
    } catch (e1) {
      console.warn(
        "[loadImage] decrypt with iv|cipher|tag failed:",
        e1.message
      );
      try {
        plainBuffer = await tryDecryptWithLayout(
          encBuffer,
          keyBytes,
          "iv|tag|cipher"
        );
        usedLayout = "iv|tag|cipher";
      } catch (e2) {
        console.error("[loadImage] fallback decrypt failed:", e2);
        throw new Error(
          "Decryption failed for both common layouts. See console for details."
        );
      }
    }

    console.log(`[loadImage] decryption succeeded using layout=${usedLayout}`);
    const mime = guessMimeFromBytes(plainBuffer);
    console.log("[loadImage] guessed mime", mime);

    const blob = new Blob([plainBuffer], { type: mime });
    imgEl.src = URL.createObjectURL(blob);
  } catch (e) {
    console.error(e);
    // No alert in app flow; bubble up to caller
    throw e;
  }
}

// DOM elements
const loginModal = document.getElementById("loginModal");
const errorModal = document.getElementById("errorModal");
const errorCloseBtn = document.getElementById("errorCloseBtn");
const passwordInput = document.getElementById("passwordInput");
const loginBtn = document.getElementById("loginBtn");
const loader = document.getElementById("loader");
const app = document.getElementById("app");
const navbar = document.getElementById("navbar");

// Image Preview Modal elements
const imageModal = document.getElementById("imageModal");
const modalImage = document.getElementById("modalImage");
const closeImageModal = document.getElementById("closeImageModal");

// ✅ Open image modal with decrypted image
async function openImageModal(encUrl, hexKey) {
    try {
        modalImage.src = FALLBACK_AVATAR;
        const decryptedUrl = await decryptImageFromUrl(encUrl, hexKey);
        modalImage.src = decryptedUrl;
        imageModal.classList.remove("hidden");
    } catch (e) {
        console.warn("Failed to decrypt image for modal:", e);
    }
}

// ✅ Close image modal
function closeImageModalHandler() {
    imageModal.classList.add("hidden");
    modalImage.src = "";
}

// Close modal on button click
if (closeImageModal) {
    closeImageModal.addEventListener("click", closeImageModalHandler);
}

// Close modal on background click
if (imageModal) {
    imageModal.addEventListener("click", (e) => {
        if (e.target === imageModal) {
            closeImageModalHandler();
        }
    });
}

// Close modal on Escape key
document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && imageModal && !imageModal.classList.contains("hidden")) {
        closeImageModalHandler();
    }
});

// ✅ Setup avatar click handlers (works for both table and mobile cards)
function setupAvatarClickHandlers() {
    const hexKey = (config && config.HEX_KEY) || "29cd3a5128416c678ac33b459f5c466c23913446d8666463b5d867c94c6bf944";
    
    // Use event delegation on document for dynamically added elements
    document.addEventListener("click", (e) => {
        if (e.target.classList.contains("enc-img")) {
            const encUrl = e.target.dataset.encUrl;
            if (encUrl) {
                openImageModal(encUrl, hexKey);
            }
        }
    });
}

// ✅ Load table.html + after loading, fetch API automatically
async function loadTablePage(options = {}) {
  const background = !!options.background;
  if (!background) loader.classList.remove("hidden");

  const response = await fetch("table.html");
  let html = await response.text();
  if (background) {
    // Strip the login-guard redirect from table.html so we can preload while not logged in
    // This removes the first <script> block that checks localStorage.getItem("loggedIn")
    html = html.replace(/<script>[\s\S]*?localStorage\.getItem\(\s*"loggedIn"\s*\)[\s\S]*?<\/script>/, "");
    console.info("[preload] stripped login guard from table.html");
  }
  app.innerHTML = html;
  console.info("[preload] table.html injected (background:", background, ")");

  // ✅ Inject search UI from JS template (avoid Live Server HTML injection)
  const searchContainer = document.getElementById("searchContainer");
  if (searchContainer) {
    searchContainer.innerHTML = searchFragment;

    // Wire up search input to filter as you type
    const searchInput = document.getElementById("searchInput");
    if (searchInput) {
      searchInput.addEventListener("input", window.filterTable);
    }

    // Wire up filter form submit and reset to do row-level filtering only
    const filterForm = document.getElementById("filterSection");
    if (filterForm) {
      filterForm.addEventListener("submit", (e) => {
        e.preventDefault();
        window.filterTable();
      });
      filterForm.addEventListener("reset", () => {
        // Let the browser reset inputs, then apply filter
        setTimeout(() => window.filterTable(), 0);
      });
    }

    // Wire up date pickers to filter on selection as well
    const startDateInput = document.getElementById("datepicker-range-start");
    const endDateInput = document.getElementById("datepicker-range-end");
    if (startDateInput) {
      startDateInput.addEventListener("change", window.filterTable);
      startDateInput.addEventListener("input", window.filterTable);
    }
    if (endDateInput) {
      endDateInput.addEventListener("change", window.filterTable);
      endDateInput.addEventListener("input", window.filterTable);
    }

    // Wire up gender select to filter on selection as well
    const genderSelect = document.getElementById("genderSelect");
    if (genderSelect) {
      genderSelect.addEventListener("change", window.filterTable);
      genderSelect.addEventListener("input", window.filterTable);
    }
  }

  // Defensive binding for Date and Name header click (in case inline onclick is blocked)
  const dateHeader = document.getElementById("dateHeader");
  if (dateHeader) {
    dateHeader.addEventListener("click", window.sortDateColumn);
  }
  const nameHeader = document.getElementById("nameHeader");
  if (nameHeader) {
    nameHeader.addEventListener("click", window.sortNameColumn);
  }

  // ✅ Initialize filter toggle script AFTER loading HTML
  initFilterToggle();

  // ✅ Initialize Flowbite date range picker for dynamically injected content
  initDatepickers();

  if (!background) loader.classList.add("hidden");

  // ✅ Now fetch API data
  fetchTableData();
  tableInitialized = true;
  
  // ✅ Initialize avatar click handlers
  setupAvatarClickHandlers();
}

// ✅ Toggle filter dropdown (after HTML is loaded)
function initFilterToggle() {
  const toggleBtn = document.getElementById("toggleFilters");
  const filterSection = document.getElementById("filterSection");
  const chevronIcon = document.getElementById("chevronIcon");

  if (!toggleBtn || !filterSection || !chevronIcon) return; // Prevent crash

  // Ensure collapsed section doesn't intercept clicks and hides overflow
  filterSection.style.overflow = "hidden";
  filterSection.style.pointerEvents = "none";

  let isOpen = false;

  toggleBtn.addEventListener("click", () => {
    isOpen = !isOpen;

    if (isOpen) {
      filterSection.style.maxHeight = filterSection.scrollHeight + "px";
      filterSection.style.opacity = "1";
      filterSection.style.pointerEvents = "auto";
      chevronIcon.style.transform = "rotate(180deg)";
    } else {
      filterSection.style.maxHeight = "0";
      filterSection.style.opacity = "0";
      filterSection.style.pointerEvents = "none";
      chevronIcon.style.transform = "rotate(0deg)";
    }
  });
}

// ✅ Initialize date pickers for dynamically loaded search form
function initDatepickers() {
  try {
    const startEl = document.getElementById("datepicker-range-start");
    const endEl = document.getElementById("datepicker-range-end");

    if (!startEl || !endEl) {
      console.warn("Datepicker inputs missing");
      return;
    }

    // Always initialize two single pickers to guarantee UI shows
    if (window.Datepicker) {
      const opts = {
        format: "dd-mm-yyyy",
        autohide: true,
        container: document.body, // render dropdown at body level
        orientation: "bottom left",
      };

      const dpStart = new window.Datepicker(startEl, opts);
      const dpEnd = new window.Datepicker(endEl, opts);

      // Show on focus to make it obvious
      startEl.addEventListener("focus", () => dpStart.show());
      endEl.addEventListener("focus", () => dpEnd.show());
    } else if (window.DateRangePicker) {
      // As a fallback, try range mode (some builds only ship DateRangePicker)
      new window.DateRangePicker(document.getElementById("date-range-picker"), {
        format: "dd-mm-yyyy",
        autohide: true,
      });
    } else {
      console.warn("Flowbite Datepicker library not found on window");
    }
  } catch (e) {
    console.error("Datepicker init error:", e);
  }
}

// ✅ Fetch API data and render table rows + mobile cards
async function fetchTableData() {
  const tableBody = document.querySelector("#userTable tbody");
  const mobileList = document.querySelector("#mobileList"); // ✅ Add this div in table.html
  if (!tableBody) return;

  try {
    let data = null;

    if (preloadingPromise) {
      try {
        console.info("[fetch] awaiting preloadingPromise...");
        data = await preloadingPromise;
        console.info(
          "[fetch] preloadingPromise resolved",
          Array.isArray(data) ? data.length : data
        );
      } catch (e) {
        console.warn("Background data promise failed:", e);
        data = null;
      }
    }

    if (!data && preloadedData) {
      data = preloadedData;
      console.info(
        "[fetch] using cached preloadedData",
        Array.isArray(data) ? data.length : data
      );
    }

    if (!data) {
      console.info("[fetch] performing live fetch (no preloaded data)");
      const res = await fetch("https://evolve-dzlb.onrender.com/clients");
      data = await res.json();
      preloadedData = data;
      console.info(
        "[fetch] live fetch resolved",
        Array.isArray(data) ? data.length : data
      );
    }

    tableBody.innerHTML = "";
    if (mobileList) mobileList.innerHTML = "";

    const hexKey =
      (config && config.HEX_KEY) ||
      "29cd3a5128416c678ac33b459f5c466c23913446d8666463b5d867c94c6bf944";

    data.forEach((item, index) => {
      const statusLower = (item.status || "").toLowerCase();
      const isActive = statusLower === "active";
      const endDateRaw = item.end_date;
      const endDateStr =
        endDateRaw && String(endDateRaw).toLowerCase() !== "null"
          ? String(endDateRaw)
          : "";
      const endDateDisplay = endDateStr || "-";

      const imgUrl = `https://cdn.jsdelivr.net/gh/mramitdas/evolve@latest/docs/images/${item.image_url}.enc`;

      /* ✅ DESKTOP TABLE ROWS */
      const row = `
                <tr class="border-b bg-gray-800 border-gray-700" data-status="${
                  isActive ? "active" : "inactive"
                }" data-date="${endDateStr}" data-gender="${(
        item.gender || ""
      ).toLowerCase()}" data-index="${index}">
                    <td class="px-6 py-4 serial">${index + 1}</td>

                    <th class="flex items-center px-6 py-4 whitespace-nowrap text-white">
                        <img class="w-10 h-10 rounded-full enc-img" data-enc-url="${imgUrl}" src="${FALLBACK_AVATAR}" alt="avatar"/>
                        <div class="pl-3">
                            <div class="text-base font-semibold name">${
                              item.name
                            }</div>
                            <div class="text-gray-400 phone">${
                              item.phone_number
                            }</div>
                        </div>
                    </th>

                    <td class="px-6 py-4">${endDateDisplay}</td>

                    <td class="px-6 py-4 status">
                        <div class="flex items-center gap-2">
                            <span class="h-3 w-3 rounded-full ${
                              isActive ? "bg-green-500" : "bg-red-500"
                            }"></span>
                            <span class="status-text ${
                              isActive ? "text-green-400" : "text-red-400"
                            }">
                                ${isActive ? "Active" : "Inactive"}
                            </span>
                        </div>
                    </td>
                </tr>
            `;
      tableBody.insertAdjacentHTML("beforeend", row);
      // Decrypt and set desktop avatar (target the just-inserted row safely)
      try {
        const insertedRow = tableBody.lastElementChild;
        const lastRowImg = insertedRow?.querySelector("img.enc-img");
        if (lastRowImg) setDecryptedImg(lastRowImg, imgUrl, hexKey);
      } catch {}

      /* ✅ MOBILE CARD VIEW */
      if (mobileList) {
        const card = `
          <div class="bg-gray-800 rounded-xl p-4 shadow flex items-center gap-4" data-status="${
            isActive ? "active" : "inactive"
          }" data-date="${endDateStr}" data-gender="${(
          item.gender || ""
        ).toLowerCase()}">
              <div class="serial text-gray-400 font-bold text-lg w-6">${
                index + 1
              }</div>

              <img data-enc-url="${imgUrl}" src="${FALLBACK_AVATAR}" class="w-12 h-12 rounded-full object-cover enc-img" alt="avatar"/>

              <div class="text-left">
                  <p class="text-white font-semibold text-lg">${item.name}</p>
                  <p class="phone-mobile text-gray-400 text-sm">${
                    item.phone_number
                  }</p>
                  <p class="${
                    isActive ? "text-green-400" : "text-red-400"
                  } text-xs mt-1">${endDateDisplay}</p>
              </div>
          </div>
        `;
        mobileList.insertAdjacentHTML("beforeend", card);
        // Decrypt and set mobile avatar (target the just-inserted card safely)
        try {
          const insertedCard = mobileList.lastElementChild;
          const imgEl = insertedCard?.querySelector("img.enc-img");
          if (imgEl) setDecryptedImg(imgEl, imgUrl, hexKey);
        } catch {}
      }
    });
    console.info(
      "[render] rendered rows:",
      Array.isArray(data) ? data.length : 0,
      "cards:",
      mobileList ? (Array.isArray(data) ? data.length : 0) : 0
    );
    dataReady = true;
  } catch (err) {
    console.error("API Load Error:", err);
  }
}

// ✅ LOGIN handler
loginBtn.onclick = async () => {
  const pass = passwordInput.value.trim();
  const hash = await sha256(pass);

  if (hash === config.ADMIN_PASSWORD_HASH) {
    loginModal.classList.add("hidden");
    app.classList.remove("blurred");
    navbar.classList.remove("hidden");
    localStorage.setItem("loggedIn", "true");

    if (!tableInitialized) {
      await loadTablePage({ background: false });
    }
  } else {
    errorModal.classList.remove("hidden");
  }
};

errorCloseBtn.onclick = () => {
  errorModal.classList.add("hidden");
  passwordInput.value = "";
};

// ✅ DARK MODE
// document.getElementById("modeToggle").onclick = () => {
//   document.documentElement.classList.toggle("dark");
// };

// ✅ LOGOUT
document.getElementById("logoutBtn").onclick = () => {
  localStorage.removeItem("loggedIn");
  window.location.reload();
};

// ✅ Combined Search + Status + Date Range filter (row-level only)
window.filterTable = function () {
  const inputEl = document.getElementById("searchInput");
  const statusEl = document.getElementById("statusSelect");
  const startEl = document.getElementById("datepicker-range-start");
  const endEl = document.getElementById("datepicker-range-end");
  const genderEl = document.getElementById("genderSelect");

  const query = (inputEl?.value || "").toLowerCase().trim();
  const status = (statusEl?.value || "").toLowerCase().trim(); // "" = All
  const gender = (genderEl?.value || "").toLowerCase().trim(); // "" = All

  const startStr = (startEl?.value || "").trim();
  const endStr = (endEl?.value || "").trim();

  function normalizeYMD(d) {
    // zero out time to ensure date-only compare
    return d ? new Date(d.getFullYear(), d.getMonth(), d.getDate()) : null;
  }
  function parseDMY(str) {
    const s = (str || "").trim();
    if (!s) return null;
    // Accept dd-mm-yyyy, dd/mm/yyyy, dd.mm.yyyy (and spaces)
    const m = s.match(/^(\d{1,2})[\/\-\.\s](\d{1,2})[\/\-\.\s](\d{2,4})$/);
    if (!m) return null;
    let dd = parseInt(m[1], 10);
    let mm = parseInt(m[2], 10);
    let yyyy = parseInt(m[3], 10);
    if (yyyy < 100) yyyy += 2000; // normalize 2-digit years
    const d = new Date(yyyy, mm - 1, dd);
    return isNaN(d.getTime()) ? null : normalizeYMD(d);
  }
  function parseDateFlexible(str) {
    const s = (str || "").trim();
    if (!s) return null;
    // Try dd-mm-yyyy first (and variants)
    const d1 = parseDMY(s);
    if (d1) return d1;
    // Try ISO-like yyyy-mm-dd (and variants with / . or spaces)
    const mIso = s.match(/^(\d{4})[\/\-\.\s](\d{1,2})[\/\-\.\s](\d{1,2})$/);
    if (mIso) {
      const yyyy = parseInt(mIso[1], 10);
      const mm = parseInt(mIso[2], 10);
      const dd = parseInt(mIso[3], 10);
      const d = new Date(yyyy, mm - 1, dd);
      if (!isNaN(d.getTime())) return normalizeYMD(d);
    }
    // Fallback to native Date parser
    const d2 = new Date(s);
    return isNaN(d2.getTime()) ? null : normalizeYMD(d2);
  }

  const startDate = parseDMY(startStr);
  const endDate = parseDMY(endStr);

  // ✅ Desktop table rows
  const rows = document.querySelectorAll("#userTable tbody tr");
  rows.forEach((row) => {
    const name = row.querySelector(".name")?.textContent.toLowerCase() || "";
    const phone = row.querySelector(".phone")?.textContent.toLowerCase() || "";
    const rowStatus = (
      row.dataset.status ||
      row.querySelector(".status-text")?.textContent ||
      ""
    ).toLowerCase();

    // Prefer data-date; if missing, try to read the 3rd cell text
    const rowDateStr =
      row.dataset.date ||
      row.querySelector("td:nth-child(3)")?.textContent?.trim() ||
      "";
    const rowDate = parseDateFlexible(rowDateStr);

    const matchesQuery =
      !query || name.includes(query) || phone.includes(query);
    const matchesStatus = !status || rowStatus === status;
    const rowGender = (row.dataset.gender || "").toLowerCase();
    const matchesGender = !gender || rowGender === gender;

    let matchesDate = true;
    if (startDate || endDate) {
      if (!rowDate) {
        matchesDate = false;
      } else {
        if (startDate && rowDate < startDate) matchesDate = false;
        if (endDate && rowDate > endDate) matchesDate = false;
      }
    }

    row.style.display =
      matchesQuery && matchesStatus && matchesDate && matchesGender
        ? ""
        : "none";
  });

  // ✅ Mobile cards
  const cards = document.querySelectorAll("#mobileList > div");
  cards.forEach((card) => {
    const name =
      card.querySelector(".text-white")?.textContent.toLowerCase() || "";
    const phone =
      card.querySelector(".phone-mobile")?.textContent.toLowerCase() || "";
    const cardStatus = (card.dataset.status || "").toLowerCase();
    const cardDateStr = (card.dataset.date || "").trim();
    const cardDate = parseDateFlexible(cardDateStr);

    const matchesQuery =
      !query || name.includes(query) || phone.includes(query);
    const matchesStatus = !status || cardStatus === status;
    const cardGender = (card.dataset.gender || "").toLowerCase();
    const matchesGender = !gender || cardGender === gender;

    let matchesDate = true;
    if (startDate || endDate) {
      if (!cardDate) {
        matchesDate = false;
      } else {
        if (startDate && cardDate < startDate) matchesDate = false;
        if (endDate && cardDate > endDate) matchesDate = false;
      }
    }

    card.style.display =
      matchesQuery && matchesStatus && matchesDate && matchesGender
        ? "flex"
        : "none";
  });

  // Renumber serials after any filter change
  renumberSerials();
};

function renumberSerials() {
  try {
    // Desktop table: renumber only visible rows
    const visibleRows = Array.from(
      document.querySelectorAll("#userTable tbody tr")
    ).filter((r) => r.style.display !== "none");
    visibleRows.forEach((tr, i) => {
      const serialCell = tr.querySelector("td:nth-child(1)");
      if (serialCell) serialCell.textContent = String(i + 1);
    });

    // Mobile cards: renumber only visible cards
    const visibleCards = Array.from(
      document.querySelectorAll("#mobileList > div")
    ).filter((c) => c.style.display !== "none");
    visibleCards.forEach((card, i) => {
      const serialEl =
        card.querySelector(".serial") ||
        card.querySelector(".text-gray-400.font-bold.text-lg.w-6");
      if (serialEl) serialEl.textContent = String(i + 1);
    });
  } catch (e) {
    console.warn("renumberSerials failed:", e);
  }
}

// ✅ Sort Status column (Active / Inactive)
let statusAsc = true;
window.sortStatusColumn = function () {
  const table = document.getElementById("userTable");
  if (!table) return;

  const rows = Array.from(table.querySelectorAll("tbody tr"));

  rows.sort((a, b) => {
    const aStatus = a.querySelector(".status-text")?.textContent.trim() || "";
    const bStatus = b.querySelector(".status-text")?.textContent.trim() || "";

    return statusAsc
      ? aStatus.localeCompare(bStatus)
      : bStatus.localeCompare(aStatus);
  });

  statusAsc = !statusAsc;

  const tbody = table.querySelector("tbody");
  rows.forEach((r) => tbody.appendChild(r));
};

// ✅ Sort Date column (dd-mm-yyyy)
let dateAsc = true;
let isSortingDate = false;
window.sortDateColumn = function () {
  if (isSortingDate) return;
  isSortingDate = true;

  const table = document.getElementById("userTable");
  if (!table) {
    isSortingDate = false;
    return;
  }
  const tbody = table.querySelector("tbody");
  const rows = Array.from(tbody.querySelectorAll("tr"));

  const normalizeYMD = (d) =>
    d ? new Date(d.getFullYear(), d.getMonth(), d.getDate()) : null;

  function parseDate(str) {
    const s = (str || "").trim();
    if (!s || s === "-") return null;

    // dd-mm-yyyy, dd/mm/yyyy, dd.mm.yyyy, dd mm yyyy
    let m = s.match(/^(\d{1,2})[\/\-\.\s](\d{1,2})[\/\-\.\s](\d{2,4})$/);
    if (m) {
      let dd = parseInt(m[1], 10);
      let mm = parseInt(m[2], 10);
      let yyyy = parseInt(m[3], 10);
      if (yyyy < 100) yyyy += 2000;
      const d = new Date(yyyy, mm - 1, dd);
      return isNaN(d.getTime()) ? null : normalizeYMD(d);
    }

    // yyyy-mm-dd (allow / . or space)
    m = s.match(/^(\d{4})[\/\-\.\s](\d{1,2})[\/\-\.\s](\d{1,2})$/);
    if (m) {
      const yyyy = parseInt(m[1], 10);
      const mm = parseInt(m[2], 10);
      const dd = parseInt(m[3], 10);
      const d = new Date(yyyy, mm - 1, dd);
      return isNaN(d.getTime()) ? null : normalizeYMD(d);
    }

    // ISO with time, e.g., 2025-11-10T00:00:00Z
    const dIso = new Date(s);
    return isNaN(dIso.getTime()) ? null : normalizeYMD(dIso);
  }

  const keyed = rows.map((el, idx) => {
    const raw =
      el.dataset.date ||
      el.querySelector("td:nth-child(3)")?.textContent?.trim() ||
      "";
    const dt = parseDate(raw);
    const origIdx = parseInt(el.dataset.index ?? idx, 10);
    return { el, dt, origIdx };
  });

  keyed.sort((a, b) => {
    const aNull = a.dt === null;
    const bNull = b.dt === null;

    if (aNull && bNull) {
      // Stable for two nulls
      return a.origIdx - b.origIdx;
    }
    if (aNull || bNull) {
      // Asc: nulls at end; Desc: nulls at start
      if (dateAsc) return aNull ? 1 : -1;
      return aNull ? -1 : 1;
    }

    const diff = a.dt - b.dt;
    if (diff === 0) {
      // Stable tie-breaker by original index
      return a.origIdx - b.origIdx;
    }
    return dateAsc ? diff : -diff;
  });

  // Apply new order
  keyed.forEach(({ el }) => tbody.appendChild(el));

  // Renumber the serial column (#) after sorting so it reflects the new order
  Array.from(tbody.querySelectorAll("tr")).forEach((tr, i) => {
    const serialCell = tr.querySelector("td:nth-child(1)");
    if (serialCell) serialCell.textContent = String(i + 1);
  });

  // Toggle direction for the next click and release guard
  dateAsc = !dateAsc;
  isSortingDate = false;
};

// ✅ Sort Name column (alphabetical, stable, case-insensitive)
let nameAsc = true;
let isSortingName = false;
window.sortNameColumn = function () {
  if (isSortingName) return;
  isSortingName = true;

  const table = document.getElementById("userTable");
  if (!table) {
    isSortingName = false;
    return;
  }
  const tbody = table.querySelector("tbody");
  const rows = Array.from(tbody.querySelectorAll("tr"));

  const keyed = rows.map((el, idx) => {
    const nameText = el.querySelector(".name")?.textContent?.trim() || "";
    const key = nameText.toLowerCase();
    const origIdx = parseInt(el.dataset.index ?? idx, 10);
    return { el, key, origIdx };
  });

  keyed.sort((a, b) => {
    const aEmpty = !a.key;
    const bEmpty = !b.key;

    if (aEmpty && bEmpty) {
      // Keep original relative order for two empties
      return a.origIdx - b.origIdx;
    }
    if (aEmpty || bEmpty) {
      // Asc: empty at end; Desc: empty at start
      if (nameAsc) return aEmpty ? 1 : -1;
      return aEmpty ? -1 : 1;
    }

    const cmp = a.key.localeCompare(b.key, undefined, {
      sensitivity: "base",
      numeric: true,
    });
    if (cmp === 0) {
      // Stable tie-breaker
      return a.origIdx - b.origIdx;
    }
    return nameAsc ? cmp : -cmp;
  });

  // Apply new order
  keyed.forEach(({ el }) => tbody.appendChild(el));

  // Renumber the serial column (#) after sorting
  Array.from(tbody.querySelectorAll("tr")).forEach((tr, i) => {
    const serialCell = tr.querySelector("td:nth-child(1)");
    if (serialCell) serialCell.textContent = String(i + 1);
  });

  nameAsc = !nameAsc;
  isSortingName = false;
};

function startBackgroundPreload() {
  if (!localStorage.getItem("loggedIn") && !preloadingStarted) {
    preloadingStarted = true;
    console.info("[preload] DOM ready: injecting table in background");
    loadTablePage({ background: true })
      .then(() => console.info("[preload] background UI ready"))
      .catch((e) => console.warn("Background preload failed:", e));
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", startBackgroundPreload);
} else {
  // DOM is already ready (module at end of body); start immediately
  startBackgroundPreload();
}
