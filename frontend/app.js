"use strict";
const api = window.go.main.App;
const el = id => document.getElementById(id);
const form = el("settings");
const fields = form.elements;
const machines = new Map();
const cards = new Map();
const phaseNames = {starting:"正在启用", ready:"代理运行中", stopping:"正在停止", stopped:"已停止", error:"失败"};
const stepIcons = {
  pending:   {label:"待执行", path:"M10 3a7 7 0 1 0 0 14a7 7 0 1 0 0-14z M10 6v4l3 2"},
  active:    {label:"进行中", path:"M10 3a7 7 0 1 1-7 7"},
  done:      {label:"已完成", path:"m4.5 10 3.5 3.5 7.5-8"},
  skipped:   {label:"已跳过", path:"m5 5 6 5-6 5z M14.5 5v10"},
  cancelled: {label:"已取消", path:"M10 3a7 7 0 1 0 0 14a7 7 0 1 0 0-14z M5 15 15 5"},
  failed:    {label:"失败", path:"m6 6 8 8 M14 6l-8 8"},
  unrun:     {label:"未执行", path:"M10 4a6 6 0 1 0 0 12a6 6 0 1 0 0-12z"}
};
let selected = "", states = {}, refreshBusy = false, stateRequest = 0;
let hasMachineList = false;
let activeOnly = false, formMode = "";

function setText(node, text) {
  if (node.textContent !== text) node.textContent = text;
}

function hasSelectedText(node) {
  const selection = window.getSelection();
  return selection && !selection.isCollapsed && selection.containsNode(node, true);
}

function setLiveText(node, text) {
  if (node.textContent !== text && !hasSelectedText(node)) node.textContent = text;
}

function paintForm(fill = false) {
  const row = machines.get(selected);
  el("config").hidden = !row;
  if (!row) return;
  const vm = row.vm, state = states[row.key];
  const mode = row.key + (state?.Running ? "/active" : "/idle");
  if (mode !== formMode) {
    el("config").open = !state?.Running;
    formMode = mode;
  }
  el("config").classList.toggle("active-config", !!state?.Running);
  setText(el("selected-name"), vm.Name);
  setText(el("selected-path"), vm.Path);
  el("encrypted-note").hidden = !vm.Encrypted;
  const isolated = !row.prefs.AllowHostAccess;
  const switching = vm.NeedsSwitch;
  const needsREST = isolated ? vm.RESTConfigured && !vm.IsOwnNetwork : vm.NeedsRESTPassword;
  const problem = vm.Reason || (!isolated && vm.SharedReason);
  const isolatedNetwork = state?.Running && state.IsolatedNetwork || (vm.IsOwnNetwork && vm.CurrentNetwork);
  setText(el("network"), isolated ? (isolatedNetwork ? "专用隔离网络 · "+isolatedNetwork : "启用时将网卡从 "+vm.CurrentNetwork+" 切换到专用隔离网络，上网必须通过代理。") : switching
    ? "启用时将网卡从 " + vm.CurrentNetwork + " 切换到共享仅主机网络（VMnet1）。"
    : "共享仅主机网络 · " + vm.Network + "　 网卡 " + vm.MAC);
  if (fill) {
    fields.proxy.value = row.prefs.Proxy;
    fields.dns.value = row.prefs.DNS;
    fields.rest.value = row.prefs.RESTPassword;
    fields.blockHost.checked=isolated;
    fields.confirmExit.checked=!row.prefs.SkipExitConfirmation;
  }
  const locked = !row.loaded || row.busy || state?.Running || !row.present;
  for (const input of [fields.proxy, fields.dns, fields.rest, fields.blockHost, fields.confirmExit]) input.disabled = !!locked;
  el("switch-note").hidden = !!state?.Running;
  setText(el("switch-note"), isolated
    ? "停止代理后，虚拟机无法直接上外网，也无法访问宿主机端口。"
    : "停止代理后，虚拟机无法直接上外网，仍可访问宿主机对它开放的端口。");
  el("rest-label").hidden = !needsREST;
  setText(el("save-state"), row.saveStatus);
  setText(el("problem"), row.error || problem || "");
  const start = el("start");
  start.hidden = !!state?.Running;
  start.disabled = !!(locked || problem || !row.prefs.Proxy.trim() || (needsREST && !row.prefs.RESTPassword));
  const startLabel = state?.Running ? phaseNames[state.Phase] : isolated ? "启用隔离网络并代理" : switching ? "切换到仅主机网络并启用代理" : "启用代理";
  setText(start, row.busy && !state?.Running && !row.prefs.SkipExitConfirmation ? "正在确认出口 IP…" : startLabel);
}

function choose(key) {
  selected = key;
  for (const [k,r] of machines) r.tile.setAttribute("aria-pressed",String(k===key));
  paintForm(true);
  drawSessions();
}

function save(row) {
  const snapshot = {...row.prefs};
  const revision = ++row.revision;
  row.saveStatus = "正在保存…";
  row.saves = row.saves.catch(()=>{}).then(()=>api.SavePreferences(row.vm.Path,snapshot));
  row.saves.then(()=>{
    if (row.revision===revision) {
      row.saveStatus="配置已保存";
      if (selected===row.key) paintForm();
    }
  }, e=>{
    if (row.revision===revision) {
      row.saveStatus="保存失败"; row.error=String(e);
      if (selected===row.key) paintForm();
    }
  });
  return row.saves;
}

async function load(row) {
  try {
    const p=await api.LoadPreferences(row.vm.Path);
    if (p) {row.prefs=p;row.saveStatus="已读取保存的配置";}
    else {
      const legacy=localStorage.getItem("dns/"+row.key);
      if (legacy) {
        row.prefs.DNS=legacy;
        await save(row);
        localStorage.removeItem("dns/"+row.key);
      }
    }
    row.loaded=true;
  } catch(e) {row.error="读取配置失败："+String(e);}
  if (selected===row.key) paintForm(true);
}

function add(vm,key) {
  const tile=el("vm-tile").content.firstElementChild.cloneNode(true);
  const row={vm,key,tile,present:true,loaded:false,busy:false,error:"",saveStatus:"",
    prefs:{Proxy:"",DNS:"",RESTPassword:"",AllowHostAccess:false},saves:Promise.resolve(),revision:0};
  machines.set(key,row);
  tile.onclick=()=>choose(key);
  el("machines").append(tile);
  load(row);
  return row;
}

function drawTiles() {
  const names=new Map();
  for (const row of machines.values()) {
    if (row.present || states[row.key]?.Running) names.set(row.vm.Name,1+(names.get(row.vm.Name)||0));
  }
  let count=0,active=0;
  const visible=[];
  for (const row of machines.values()) {
    const {vm,tile,key}=row;
    const running=!!states[key]?.Running;
    if (running) active++;
    tile.hidden=!running && (!row.present || activeOnly);
    if (!running && !row.present) continue;
    count++;
    if (!tile.hidden) visible.push(key);
    tile.classList.toggle("has-session",running);
    tile.title=vm.Path;
    setText(tile.querySelector("strong"), vm.Name);
    setText(tile.querySelector("small"), states[key]?.Running ? sessionBadge(states[key]).text : vm.CurrentNetwork);
    setText(tile.querySelector(".tile-path"), names.get(vm.Name)>1 ? vm.Path : "");
  }
  setText(el("count"), hasMachineList ? String(count) : "");
  setText(el("active-count"), String(active));
  el("no-active").hidden=!hasMachineList || !activeOnly || active>0;
  if (!visible.includes(selected) && (selected || visible.length)) choose(visible[0] || "");
}

function createCard(key,state) {
  const card=el("session").content.firstElementChild.cloneNode(true);
  const list=card.querySelector("ol");
  state.Steps.forEach((_,i)=>{
    const line=el("setup-step").content.firstElementChild.cloneNode(true);
    line.querySelector(".step-no").textContent=String(i+1);
    list.append(line);
  });
  card.querySelector(".stop").onclick=async()=>{
    const row=machines.get(key);
    card.querySelector(".stop").disabled=true;
    try {await api.StopVM(row?.vm.Path || key);await updateStates();}
    catch(e){card.querySelector(".session-error").textContent=String(e);card.querySelector(".stop").disabled=false;}
  };
  const probe=card.querySelector(".probe-upstream");
  probe.onclick=async()=>{
    const error=card.querySelector(".session-error");
    error.textContent="";
    probe.dataset.sending="true";
    probe.disabled=true;
    setText(probe,"探测中…");
    try {await api.ProbeUpstream(machines.get(key)?.vm.Path || key);await updateStates();}
    catch(e){error.textContent="无法发起探测："+String(e);}
    finally {
      delete probe.dataset.sending;
      if (states[key]) showTelemetry(card,states[key]);
    }
  };
  cards.set(key,card);
  el("sessions").prepend(card);
  return card;
}

function formatBytes(bytes) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let level = 0;
  while (bytes >= 1024 && level < units.length - 1) { bytes /= 1024; level++; }
  return bytes.toFixed(level && bytes < 100 ? 1 : 0) + " " + units[level];
}

function sessionBadge(state) {
  if (state.Phase === "starting") return {tone:"waiting", text:"尚未就绪"};
  return {tone:state.Phase, text:state.Phase === "ready" ? "已就绪" : phaseNames[state.Phase]};
}

function showTelemetry(card, state) {
  const panel = card.querySelector(".telemetry"), stats = state.Stats;
  panel.hidden = !state.Running || state.Phase !== "ready" || !stats?.Server;
  if (panel.hidden) return;
  for (const [name, key] of [["up","Up"], ["down","Down"]]) {
    setLiveText(panel.querySelector("."+name+"-rate"), formatBytes(stats[key+"Rate"]) + "/s");
    setLiveText(panel.querySelector("."+name+"-total"), "累计 " + formatBytes(stats[key+"Bytes"]));
  }
  setLiveText(panel.querySelector(".server-address"), stats.Server);
  const health = stats.Health;
  const probe = panel.querySelector(".probe-upstream");
  const probing = !!stats.Probing || !!probe.dataset.sending;
  probe.disabled = probing;
  setText(probe, probing ? "探测中…" : "探测上游代理");
  for (const row of panel.querySelectorAll("[data-check]")) {
    const key = row.dataset.check, result = health?.[key];
    const labels = {ok:key === "Service" ? "正常" : "可用", error:key === "Service" ? "异常" : "探测失败", unsupported:"不支持", blocked:"未执行", probing:"探测中"};
    row.dataset.state = probing ? "probing" : result?.State || "pending";
    setText(row.querySelector("b"), labels[row.dataset.state] || "未探测");
    setText(row.querySelector("small"), probing ? "" : result?.Detail || (result?.State === "blocked" ? "SOCKS5 服务检查失败" : ""));
  }
  const checked = !probing && health?.CheckedAt ? "上次探测 " + new Date(health.CheckedAt * 1000).toLocaleTimeString("zh-CN",{hour12:false}) + " · " : "";
  setLiveText(panel.querySelector(".check-note"), checked + "TCP / UDP 探测目标 " + stats.DNS + ":53");
  setLiveText(panel.querySelector(".dial-error"), stats.LastTCPError ? "最近一次虚拟机 TCP 连接失败 · " + stats.LastTCPError : "");
}

function drawSessions() {
  for (const [key,state] of Object.entries(states)) {
    const row=machines.get(key), vm=row?.vm;
    const card=cards.get(key) || createCard(key,state);
    card.hidden=key!==selected;
    if (card.hidden) continue;
    const setup = card.querySelector(".setup");
    if (card.dataset.phase !== state.Phase) setup.open = state.Phase === "starting" || state.Phase === "error";
    card.dataset.phase=state.Phase;
    setText(card.querySelector("h3"), vm?.Name || key.split(/[\\/]/).pop());
    setText(card.querySelector(".path"), vm?.Path || key);
    const done=state.Steps.filter(s=>s.State==="done" || s.State==="skipped").length;
    const badge = sessionBadge(state);
    card.dataset.tone = badge.tone;
    setText(card.querySelector(".phase"), badge.text);
    card.querySelector(".isolation-status").hidden = !(state.Running && state.Phase === "ready");
    setText(card.querySelector(".isolation-status span"), state.IsolatedNetwork ? "专用隔离网络 · 外网仅经代理，宿主机端口已阻断" : "共享仅主机网络 · 未阻断宿主机端口访问");
    const help = card.querySelector(".guest-help");
    help.hidden = !(state.Phase === "starting" && state.ShowGuestHelp);
    if (!help.hidden) {
      const family = vm?.GuestOSFamily || "other";
      for (const tip of help.querySelectorAll("[data-os]")) tip.hidden = tip.dataset.os !== family;
    }
    setText(setup.querySelector("summary"), "启动步骤 · " + done + "/" + state.Steps.length);
    setText(card.querySelector(".summary"), state.Phase === "ready" ? "" : state.Status);
    showTelemetry(card,state);
    const stop=card.querySelector(".stop");
    stop.hidden=!state.Running;stop.disabled=state.Phase==="stopping";
    setText(stop, stop.disabled ? "正在停止…" : "停止代理");
    state.Steps.forEach((step,i)=>{
      const node=card.querySelector("ol").children[i];
      const status = step.State==="pending" && !state.Running ? "unrun" : step.State;
      if (node.dataset.state !== status) {
        node.dataset.state = status;
        const icon = node.querySelector(".step-state");
        const {label, path} = stepIcons[status];
        icon.title = label;
        icon.setAttribute("aria-label", label);
        icon.querySelector("path").setAttribute("d", path);
      }
      setText(node.children[1], step.Title);
      const plannedSwitch = i===1 && vm && (row?.prefs.AllowHostAccess ? vm.NeedsSwitch : !vm.IsOwnNetwork) && step.State==="pending"
        ? vm.CurrentNetwork+(!row?.prefs.AllowHostAccess ? " → 专用隔离网络" : " → 共享仅主机网络（VMnet1）") : "";
      setLiveText(node.children[3], step.Detail || plannedSwitch);
    });
  }
}

form.oninput=()=>{
  const row=machines.get(selected);
  if (!row?.loaded) return;
  row.prefs={Proxy:fields.proxy.value,DNS:fields.dns.value,RESTPassword:fields.rest.value,AllowHostAccess:!fields.blockHost.checked,SkipExitConfirmation:!fields.confirmExit.checked};
  row.error=""; save(row);paintForm();
};
form.onsubmit=async event=>{
  event.preventDefault();
  const row=machines.get(selected);
  if (!row || el("start").disabled) return;
  row.busy=true;row.error="";paintForm();
  try {
    await save(row);
    await api.StartVMWithHostAccess(row.vm.Path,row.prefs.Proxy,row.prefs.DNS,row.prefs.RESTPassword,!!row.prefs.AllowHostAccess);
    await updateStates();
    cards.get(row.key)?.scrollIntoView({block:"nearest"});
  } catch(e){row.error=String(e);}
  finally {row.busy=false;paintForm();}
};

async function refresh() {
  if (refreshBusy) return;
  const button=el("refresh"), message=el("message"), list=el("machines");
  refreshBusy=button.disabled=true;
  button.title = hasMachineList ? "正在刷新虚拟机列表" : "正在加载虚拟机列表";
  button.setAttribute("aria-label", button.title);
  list.setAttribute("aria-busy","true");
  message.dataset.state="loading";
  message.textContent=hasMachineList ? "正在刷新虚拟机列表…" : "正在查找运行中的虚拟机…";
  try {
    const vms=await api.Machines();
    const found=new Set();
    for (const vm of vms || []) {
      const key=vm.Path.toLowerCase();found.add(key);
      const row=machines.get(key) || add(vm,key);
      row.vm=vm;row.present=true;
      if (!row.loaded && row.error) {row.error="";load(row);}
    }
    for (const row of machines.values()) row.present=found.has(row.key);
    hasMachineList=true;
    drawTiles();paintForm();drawSessions();
    message.dataset.state=found.size ? "ready" : "empty";
    message.textContent=found.size ? "" : "没有运行中的虚拟机。请在 VMware 中启动后刷新。";
  } catch(e){
    message.dataset.state="error";
    message.textContent=(hasMachineList ? "刷新失败，保留上次列表。" : "无法获取虚拟机列表。")+String(e);
  } finally {
    list.setAttribute("aria-busy","false");
    refreshBusy=button.disabled=false;
    button.title = message.dataset.state === "error" ? "重新加载虚拟机列表" : "刷新虚拟机列表";
    button.setAttribute("aria-label", button.title);
  }
}

async function updateStates() {
  const ticket=++stateRequest;
  const next=await api.States();
  if (ticket!==stateRequest) return;
  const networkChanged=Object.entries(next).some(([key,s])=>{
    const old=states[key];
    return (old?.Running && !s.Running) || (s.Steps[1].State==="done" && old?.Steps[1].State!=="done");
  });
  states=next;drawSessions();drawTiles();paintForm();
  if (networkChanged) refresh();
}

async function poll() {
  const message=el("session-message");
  try {await updateStates();message.hidden=true;}
  catch(e){message.hidden=false;setText(message, "无法读取会话状态："+String(e));}
  finally {setTimeout(poll,650);}
}
el("refresh").onclick=refresh;
el("about-version").textContent=el("app-version").textContent;
for (const link of document.querySelectorAll(".header-link")) {
  link.onclick=event=>{
    event.preventDefault();
    el(link.getAttribute("aria-controls")).showModal();
  };
}
el("about-project").onclick=event=>{
  event.preventDefault();
  window.runtime.BrowserOpenURL(event.currentTarget.href);
};
function filterSessions(value) {
  activeOnly=value;
  el("all-vms").setAttribute("aria-pressed",String(!value));
  el("active-vms").setAttribute("aria-pressed",String(value));
  drawTiles();
}
el("all-vms").onclick=()=>filterSessions(false);
el("active-vms").onclick=()=>filterSessions(true);

function showCleanup(report) {
  const dialog=el("closing");
  if (!dialog.open) dialog.showModal();
  const items=Object.entries(report.Sessions).map(([key,status])=>{
    const row=machines.get(key);
    const item=document.createElement("li"), name=document.createElement("strong");
    const path=document.createElement("small"), detail=document.createElement("p");
    name.textContent=row?.vm.Name || key.split(/[\\/]/).pop();
    path.className="path";path.textContent=row?.vm.Path || key;
    detail.textContent=status;
    item.append(name,path,detail);
    return item;
  });
  el("close-list").replaceChildren(...items);
  const failed=report.Done && report.Failed;
  el("close-title").textContent=failed ? "退出清理遇到问题" : "正在退出 GuestGate";
  el("close-note").textContent=failed ? "工作进程已退出，请查看下方错误。" :
    report.Done ? "清理已完成。" : "正在结束代理会话，完成后窗口会自动关闭。";
  el("close-finish").hidden=!failed;
}
el("closing").oncancel=event=>event.preventDefault();
el("close-finish").onclick=()=>window.runtime.Quit();
window.runtime.EventsOn("guestgate:closing",showCleanup);
refresh();poll();
