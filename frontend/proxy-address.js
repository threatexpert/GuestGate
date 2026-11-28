"use strict";

// Work on the original spelling, including unfinished input and percent escapes.
function proxySecretRanges(raw) {
  const ranges = [];
  const start = raw.match(/^\s*(?:[a-z][a-z\d+.-]*:\/\/)?/i)[0].length;
  const authority = raw.slice(start).split(/[/?#]/, 1)[0];
  const at = authority.lastIndexOf("@");
  const colon = authority.indexOf(":");
  if (colon >= 0 && colon + 1 < at) ranges.push([start + colon + 1, start + at]);
  const query = raw.indexOf("?");
  if (query >= 0) {
    const params = raw.slice(query + 1);
    for (const m of params.matchAll(/(?:^|&)([^=&]*)=([^&]*)/g)) {
      let key;
      try { key = decodeURIComponent(m[1]); } catch { continue; }
      if (key.toLowerCase() === "psk" && m[2].length) {
        const end = query + 1 + m.index + m[0].length;
        ranges.push([end - m[2].length, end]);
      }
    }
  }
  return ranges;
}

function createProxyEditor(input, toggle, change) {
  const mask = "••••••";
  let raw = "", revealed = false, ranges = [];

  function render() {
    ranges = proxySecretRanges(raw);
    if (!ranges.length) revealed = false;
    let text = raw;
    if (!revealed) {
      for (const [a,b] of ranges.slice().reverse()) text = text.slice(0,a) + mask + text.slice(b);
    }
    if (input.value !== text) input.value = text;
    toggle.hidden = !ranges.length;
    toggle.setAttribute("aria-pressed", String(revealed));
    toggle.title = revealed ? "隐藏代理密钥" : "显示代理密钥";
    toggle.setAttribute("aria-label", toggle.title);
  }
  // Map caret positions between the real URL and its fixed-width masks.
  function position(index, fromDisplay) {
    if (revealed) return index;
    let shift = 0;
    for (const [a,b] of ranges) {
      const start = fromDisplay ? a - shift : a;
      const sourceLength = fromDisplay ? mask.length : b - a;
      const targetLength = fromDisplay ? b - a : mask.length;
      if (index < start) break;
      if (index <= start + sourceLength) return start + shift + Math.round((index-start)*targetLength/sourceLength);
      shift += targetLength - sourceLength;
    }
    return index + shift;
  }
  function commit(value, caret) {
    raw = value;
    render();
    if (caret !== undefined) {
      const offset = position(caret, false);
      input.setSelectionRange(offset, offset);
    }
    change(raw);
  }
  function hide() { revealed = false; render(); }
  toggle.onclick = () => { revealed = !revealed; render(); };
  input.parentElement.addEventListener("focusout", e => {
    if (!input.parentElement.contains(e.relatedTarget)) hide();
  });
  window.addEventListener("blur", hide);
  document.addEventListener("visibilitychange", () => { if (document.hidden) hide(); });

  input.addEventListener("paste", e => {
    if (input.disabled || revealed || !ranges.length || !e.clipboardData) return;
    e.preventDefault();
    const value = e.clipboardData.getData("text/plain").trim();
    if (value && value !== input.value) commit(value, value.length);
  });
  input.addEventListener("beforeinput", e => {
    if (revealed || !ranges.length || !e.cancelable) return;
    // Native editing would splice the displayed bullets into the saved URL.
    e.preventDefault();
    let a = position(input.selectionStart, true), b = position(input.selectionEnd, true);
    let replacement = "";
    if (e.inputType.startsWith("insert") && typeof e.data === "string") {
      replacement = e.data;
    } else if (e.inputType.startsWith("delete")) {
      if (a === b) {
        if (e.inputType === "deleteContentBackward" && a) a -= [...raw.slice(0,a)].pop().length;
        else if (e.inputType === "deleteContentForward" && b < raw.length) b += String.fromCodePoint(raw.codePointAt(b)).length;
        else return;
      }
    } else return;
    commit(raw.slice(0,a) + replacement + raw.slice(b), a + replacement.length);
  });
  input.addEventListener("input", e => {
    e.stopPropagation();
    // Composition and autofill may bypass beforeinput. Keep a masked draft intact.
    if (!revealed && ranges.length) { render(); return; }
    commit(input.value, input.selectionStart);
  });
  return {hide, set(value) {raw = value || ""; hide();}};
}
