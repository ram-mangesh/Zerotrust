/**
 * Zero Trust Network Access (ZTNA) Browser SDK
 * Zero-dependency client-side WebCrypto ECDSA P-256 device binding & passive biometrics
 */
(function (window) {
  "use strict";

  const DB_NAME = "ZTNADeviceBinding";
  const STORE_NAME = "keys";
  const KEY_ID = "ztna-ecdsa-p256";

  let keyPair = null;
  let pubKeyB64 = null;
  let deviceFingerprint = null;
  let keystrokes = [];
  let mousePositions = [];
  let lastMouseTime = Date.now();

  function openDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE_NAME);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function getOrCreateKeyPair() {
    if (keyPair) return keyPair;

    const db = await openDB();
    const stored = await new Promise((resolve) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const req = tx.objectStore(STORE_NAME).get(KEY_ID);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    });

    if (stored) {
      keyPair = stored;
    } else {
      keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign", "verify"]
      );
      await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, "readwrite");
        const req = tx.objectStore(STORE_NAME).put(keyPair, KEY_ID);
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
      });
    }

    const rawPub = await crypto.subtle.exportKey("raw", keyPair.publicKey);
    pubKeyB64 = btoa(String.fromCharCode(...new Uint8Array(rawPub)));
    return keyPair;
  }

  async function getFingerprint() {
    if (deviceFingerprint) return deviceFingerprint;
    try {
      const canvas = document.createElement("canvas");
      const ctx = canvas.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "14px Arial";
      ctx.fillText("ZTNA Hardware Binding 🔒", 2, 2);
      const str = [
        canvas.toDataURL(),
        navigator.userAgent,
        navigator.language,
        screen.width + "x" + screen.height,
        Intl.DateTimeFormat().resolvedOptions().timeZone,
      ].join("||");

      const enc = new TextEncoder().encode(str);
      const hash = await crypto.subtle.digest("SHA-256", enc);
      deviceFingerprint = Array.from(new Uint8Array(hash))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    } catch {
      deviceFingerprint = "default_fingerprint";
    }
    return deviceFingerprint;
  }

  async function signRequest(method, path, timestamp) {
    await getOrCreateKeyPair();
    const message = `${method.toUpperCase()}:${path}:${timestamp}`;
    const enc = new TextEncoder().encode(message);
    const rawSignature = await crypto.subtle.sign(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      keyPair.privateKey,
      enc
    );
    return btoa(String.fromCharCode(...new Uint8Array(rawSignature)));
  }

  window.addEventListener("keydown", (e) => {
    const now = Date.now();
    keystrokes.push(now);
    if (keystrokes.length > 50) keystrokes.shift();
  });

  window.addEventListener("mousemove", (e) => {
    const now = Date.now();
    if (now - lastMouseTime >= 100) {
      mousePositions.push({ x: e.clientX, y: e.clientY, time: now });
      lastMouseTime = now;
      if (mousePositions.length > 20) mousePositions.shift();
    }
  });

  function computeWPM() {
    if (keystrokes.length < 5) return 0.0;
    const durationMin = (keystrokes[keystrokes.length - 1] - keystrokes[0]) / 60000;
    if (durationMin <= 0) return 0.0;
    const words = keystrokes.length / 5.0;
    return Math.min(Math.round((words / durationMin) * 10) / 10, 300.0);
  }

  function computeMouseVelocity() {
    if (mousePositions.length < 3) return 0.0;
    let totalDist = 0;
    let totalTime = 0;
    for (let i = 1; i < mousePositions.length; i++) {
      const dx = mousePositions[i].x - mousePositions[i - 1].x;
      const dy = mousePositions[i].y - mousePositions[i - 1].y;
      const dt = (mousePositions[i].time - mousePositions[i - 1].time) / 1000;
      if (dt > 0) {
        totalDist += Math.sqrt(dx * dx + dy * dy);
        totalTime += dt;
      }
    }
    return totalTime > 0 ? Math.round(totalDist / totalTime) : 0.0;
  }

  const nativeFetch = window.fetch;
  window.fetch = async function (resource, init = {}) {
    try {
      const url = new URL(typeof resource === "string" ? resource : resource.url, window.location.origin);
      const method = (init.method || "GET").toUpperCase();
      const timestamp = Date.now().toString();

      const [fp, sig] = await Promise.all([
        getFingerprint(),
        signRequest(method, url.pathname, timestamp),
      ]);

      const headers = new Headers(init.headers || {});
      headers.set("X-Device-Signature", sig);
      headers.set("X-Device-Timestamp", timestamp);
      headers.set("X-Device-Pubkey", pubKeyB64);
      headers.set("X-Device-Fingerprint", fp);

      init.headers = headers;
    } catch (e) {
      console.debug("[ZTNA SDK] signing fallback:", e);
    }
    return nativeFetch.apply(this, [resource, init]);
  };

  const ZTNA = {
    getPublicKey: async () => {
      await getOrCreateKeyPair();
      return pubKeyB64;
    },
    getFingerprint: async () => await getFingerprint(),
    getBiometrics: () => ({
      wpm: computeWPM(),
      mouse_velocity: computeMouseVelocity(),
    }),
    registerDevice: async (apiBase = "") => {
      const pubkey = await ZTNA.getPublicKey();
      const fp = await ZTNA.getFingerprint();
      return await nativeFetch(`${apiBase}/api/signals/register-device-key`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ecdsa_pubkey: pubkey, device_fingerprint: fp }),
      });
    },
  };

  window.ZTNASDK = ZTNA;
})(window);
