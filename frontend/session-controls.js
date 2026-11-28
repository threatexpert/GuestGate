"use strict";

let openRouteDialog;
function initRouteDialog() {
  const dialog = el("route-dialog"), apply = el("route-apply"), cancel = el("route-cancel");
  let target, switching, pending = false, candidate = "";
  const editor = createProxyEditor(el("switch-address"), el("switch-eye"), value => { candidate = value; });
  openRouteDialog = (row, state, change) => {
    if (!row?.loaded || state?.Phase !== "ready") return;
    target = {row, session:state.SessionID};
    switching = change;
    candidate = change ? row.prefs.Proxy : "";
    editor.set(candidate);
    el("switch-verify").checked = !row.prefs.SkipExitConfirmation;
    el("route-fields").hidden = !change;
    setText(el("route-title"), change ? "切换上游代理" : "断开这台虚拟机的全部连接");
    setText(el("route-machine"), row.vm.Name + " · " + displayPath(row.vm.Path));
    setText(el("route-impact"), change
      ? "确认后断开当前 TCP 和 UDP 会话，新连接全部使用新上游。核对期间仍使用原上游；跳过核对将直接切换。"
      : "将断开这台虚拟机的所有连接（含筛选范围外的连接及 SOCKS5 的 UDP 控制连接）。虚拟机网关继续运行，应用可通过当前上游重新连接。");
    setText(el("route-error"), "");
    setText(apply, change ? "继续切换" : "断开全部连接");
    dialog.showModal();
    cancel.focus();
  };
  cancel.onclick = () => dialog.close();
  dialog.oncancel = event => { if (pending) event.preventDefault(); };
  dialog.onclose = () => { editor.set(""); candidate = ""; };
  el("route-form").onsubmit = async event => {
    event.preventDefault();
    if (pending) return;
    const {row,session} = target, raw = candidate.trim();
    if (switching && !raw) { setText(el("route-error"),"请填写新上游代理地址。"); return; }
    pending = true;
    editor.hide();
    for (const input of [apply,cancel,el("switch-address"),el("switch-eye"),el("switch-verify")]) input.disabled = true;
    try {
      if (switching) {
        const verify = el("switch-verify").checked;
        setText(el("route-error"),verify ? "正在通过新上游查询出口 IP…" : "正在切换…");
        if (!await api.SwitchUpstream(row.vm.Path,session,raw,verify)) {
          setText(el("route-error"),"已取消，仍使用原上游。"); return;
        }
        row.prefs.Proxy = raw;
        if (selected === row.key) paintForm(true);
        try { await save(row); }
        catch(e) {
          const note=cards.get(row.key)?.querySelector(".live-note");
          if (note) { note.dataset.error="true"; setText(note,"上游已切换，但保存配置失败：" + String(e)); }
        }
      } else {
        await api.DisconnectConnections(row.vm.Path,session);
      }
      dialog.close();
      await updateStates();
      if (el("connections-dialog").open) await refreshConnectionList();
    } catch(e) { setText(el("route-error"), String(e)); }
    finally {
      pending = false;
      for (const input of [apply,cancel,el("switch-address"),el("switch-eye"),el("switch-verify")]) input.disabled = false;
    }
  };
}

function bindSessionControls(card,key) {
  const node = selector => card.querySelector(selector);
  const record = node(".record-toggle"), feedback = node(".recording-feedback"), folder = node(".recording-folder");
  folder.onclick = async () => {
    const session = card.dataset.session, directory = folder.dataset.directory;
    if (!directory) return;
    setText(feedback,"");
    try { await api.OpenSessionRecording(machines.get(key)?.vm.Path || key,session,directory); }
    catch(e) {
      if (card.dataset.session === session && folder.dataset.directory === directory) setText(feedback,String(e));
    }
  };
  node(".switch-upstream").onclick = () => openRouteDialog(machines.get(key),states[key],true);
  node(".open-connections").onclick = () => showConnectionList(key);
  record.onclick = async () => {
    const row = machines.get(key), state = states[key];
    if (!row?.loaded || state?.Phase !== "ready") return;
    const enable = !state.Recording;
    record.dataset.pending = enable ? "正在开始录制…" : "正在停止录制…";
    setText(feedback,"");
    paintSessionControls(card,state);
    try {
      await api.SetRecording(row.vm.Path,state.SessionID,row.prefs.RecordingRoot || "",enable);
    } catch(e) {
      if (card.dataset.session === state.SessionID) setText(feedback,String(e));
    } finally {
      try { await updateStates(); }
      catch(e) { if (card.dataset.session === state.SessionID) setText(feedback,String(e)); }
      if (card.dataset.session === state.SessionID) {
        delete record.dataset.pending;
        if (states[key]) paintSessionControls(card,states[key]);
      }
    }
  };
}

function paintSessionControls(card,state) {
  const record = card.querySelector(".record-toggle"), status = card.querySelector(".recording-status");
  const folder = card.querySelector(".recording-folder"), feedback = card.querySelector(".recording-feedback");
  if (card.dataset.session !== state.SessionID) {
    card.dataset.session = state.SessionID;
    delete record.dataset.pending;
    setText(feedback,"");
    setText(card.querySelector(".live-note"),"");
  }
  const ready = state.Running && state.Phase === "ready";
  const directory = state.RecordingDirectory || "";
  card.querySelector(".recording-tools").hidden = !ready && !directory && !state.RecordingError;
  record.hidden = !ready;
  record.disabled = !ready || !!record.dataset.pending;
  setText(record,record.dataset.pending || (state.Recording ? "停止录制" : "开始录制流量并解密 TLS"));
  status.hidden = !directory;
  setText(status.querySelector(".recording-label"),state.Recording ? (state.Phase === "stopping" ? "正在完成录制" : "录制中") : "最近录制");
  if (folder.dataset.directory !== directory) {
    folder.dataset.directory = directory;
    status.title = folder.title = displayPath(directory);
  }
  setText(card.querySelector(".recording-error"),state.RecordingError || "");
  if (state.RecordingError && feedback.textContent === state.RecordingError) setText(feedback,"");
}

let showConnectionList, refreshConnectionList, syncConnectionDialog;
function initConnectionDialog() {
  const dialog = el("connections-dialog"), body = el("connections-body");
  const query = el("connections-query"), kind = el("connections-kind"), status = el("connections-status");
  const prev = el("connections-prev"), next = el("connections-next"), all = el("connections-all");
  let target, revision = 0, offset = 0, timer;
  const live = () => target && states[target.key]?.Phase === "ready" && states[target.key].SessionID === target.session;
  function invalidate() {
    clearTimeout(timer);
    revision++;
    body.replaceChildren();
    prev.disabled = next.disabled = all.disabled = true;
  }
  syncConnectionDialog = () => {
    if (dialog.open && !live()) {
      invalidate();
      setText(el("connections-count"), "");
      setText(status, "此代理会话已结束。");
    }
  };
  refreshConnectionList = async (start = offset) => {
    if (!dialog.open || !live()) return;
    const ticket = ++revision;
    try {
      const page = await api.Connections(target.path,target.session,start,query.value.trim(),kind.value);
      if (ticket !== revision || !live() || !dialog.open) return;
      offset = page.Offset;
      setText(el("connections-count"), "活动连接 "+page.Total+" 条 · 其中 UDP 控制连接 "+page.Controls+" 条");
      const rows = (page.Items || []).map(conn => {
        const tr = document.createElement("tr");
        for (const value of [conn.Kind,conn.Guest || "—",conn.Local,conn.Target,new Date(conn.Since).toLocaleTimeString("zh-CN",{hour12:false})]) {
          tr.insertCell().textContent = value;
        }
        const button = document.createElement("button");
        button.type = "button";
        button.textContent = "断开";
        button.setAttribute("aria-label","断开 "+conn.Kind+" "+conn.Target+"，本地 "+conn.Local);
        button.onclick = async () => {
          const original = target;
          button.disabled = true;
          try {
            await api.DisconnectConnection(original.path,original.session,conn.ID);
            if (target === original) await refreshConnectionList();
          } catch (e) {
            if (target === original && live()) { setText(status,String(e)); button.disabled = false; }
          }
        };
        tr.insertCell().append(button);
        return tr;
      });
      body.replaceChildren(...rows);
      prev.disabled = offset === 0;
      next.disabled = offset + rows.length >= page.Matched;
      all.disabled = page.Total === 0;
      const position = rows.length ? (offset+1)+"–"+(offset+rows.length)+" / "+page.Matched+" 条" : page.Total ? "没有匹配的连接" : "当前没有活动连接";
      setText(status,position+" · 刷新于 "+new Date().toLocaleTimeString("zh-CN",{hour12:false}));
    } catch(e) {
      if (ticket === revision) { invalidate(); setText(el("connections-count"),""); setText(status,String(e)); }
    }
  };
  showConnectionList = key => {
    const row = machines.get(key), state = states[key];
    if (!row || state?.Phase !== "ready") return;
    target = {key, path:row.vm.Path, session:state.SessionID};
    invalidate();
    offset = 0;
    query.value = kind.value = "";
    setText(el("connections-machine"),row.vm.Name+" · "+displayPath(row.vm.Path));
    setText(el("connections-count"),"");
    setText(status,"正在读取活动连接…");
    dialog.showModal();
    query.focus();
    refreshConnectionList(0);
  };
  dialog.onclose = () => { invalidate(); target = null; };
  query.oninput = () => {
    invalidate();
    setText(status,"正在筛选…");
    timer = setTimeout(() => refreshConnectionList(0),150);
  };
  kind.onchange = () => { invalidate(); refreshConnectionList(0); };
  el("connections-refresh").onclick = () => refreshConnectionList();
  prev.onclick = () => refreshConnectionList(Math.max(0,offset-50));
  next.onclick = () => refreshConnectionList(offset+50);
  all.onclick = () => { if (live()) openRouteDialog(machines.get(target.key),states[target.key],false); };
}
