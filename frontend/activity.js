"use strict";
{
  const panel = el("activity"), list = el("log-lines"), note = el("log-note");
  let cursor = 0, revision = 0, timer, clearing = false;
  function append(entry) {
    const row = document.createElement("div");
    row.className = "log-line";
    row.dataset.kind = entry.Kind;
    const key = entry.VM.toLowerCase(), vm = machines.get(key)?.vm;
    const source = vm?.Name || entry.VM.split(/[\\/]/).pop() || "GuestGate";
    const timestamp = new Date(entry.Time).toLocaleTimeString("zh-CN", {hour12:false});
    for (const text of [timestamp, source, entry.Kind, entry.Message]) {
      const cell = document.createElement("span");
      cell.textContent = text;
      row.append(cell);
    }
    row.children[1].title = entry.VM || source;
    return row;
  }
  async function read(ticket) {
    try {
      // Leave selected rows in place even when the history reaches its limit.
      if (hasSelectedText(list)) return;
      const batch = await api.ActivitySince(cursor);
      if (ticket !== revision || !panel.open || hasSelectedText(list)) return;
      if (batch.length) {
        const follow = !list.childElementCount || list.scrollHeight-list.scrollTop-list.clientHeight < 24;
        const rows = document.createDocumentFragment();
        for (const entry of batch) rows.append(append(entry));
        list.append(rows);
        cursor = batch[batch.length-1].ID;
        while (list.childElementCount > 1000) list.firstElementChild.remove();
        if (follow) list.scrollTop = list.scrollHeight;
      }
      setLiveText(note, list.childElementCount ? "最近 "+list.childElementCount+" 条" : "暂无活动记录");
    } catch (e) {
      if (ticket === revision) setText(note, "读取日志失败 · "+String(e));
    } finally {
      if (ticket === revision && panel.open) timer = setTimeout(()=>read(ticket), 900);
    }
  }
  function refreshLog() {
    clearTimeout(timer);
    const ticket = ++revision;
    if (panel.open && !clearing) read(ticket);
  }
  panel.ontoggle = refreshLog;
  panel.onkeydown = event => {
    if (event.key === "Escape") { panel.open = false; panel.querySelector("summary").focus(); }
  };
  el("log-copy").onclick = async () => {
    const lines = Array.from(list.children,row => Array.from(row.children,cell=>cell.textContent).join("\t"));
    if (!lines.length) return;
    try { await window.runtime.ClipboardSetText(lines.join("\r\n")); }
    catch(e) { note.textContent = "复制失败 · "+String(e); }
  };
  el("log-clear").onclick = async () => {
    if (clearing) return;
    clearing = true;
    refreshLog();
    try {
      cursor = await api.ClearActivity();
      list.replaceChildren();
    } catch(e) { note.textContent = "清空失败 · "+String(e); }
    finally { clearing = false; refreshLog(); }
  };
}
