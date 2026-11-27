"use strict";
const api = window.go.main.App;
const el = id => document.getElementById(id);
const form = el("settings");
const fields = form.elements;
const machines = new Map();
const cards = new Map();
const phaseNames = {starting:"正在启用", ready:"已启用", stopping:"正在停止", stopped:"已停止", error:"失败"};
const stepNames = {pending:"待执行", active:"进行中", done:"已完成", skipped:"已跳过", cancelled:"已取消", failed:"失败"};
let selected = "", states = {}, refreshBusy = false, stateRequest = 0;
let hasMachineList = false;

function paintForm(fill = false) {
  const row = machines.get(selected);
  el("config").hidden = !row;
  if (!row) return;
  const vm = row.vm, state = states[row.key];
  el("selected-name").textContent = vm.Name;
  el("selected-path").textContent = vm.Path;
  const switching = vm.NeedsSwitch;
  el("network").textContent = switching
    ? "启用时将网卡从 " + vm.CurrentNetwork + " 切换到仅主机模式（VMnet1）。停止代理后仍保留仅主机模式。"
    : "仅主机网络 · " + vm.Network + "　 网卡 " + vm.MAC;
  if (fill) {
    fields.proxy.value = row.prefs.Proxy;
    fields.dns.value = row.prefs.DNS;
    fields.rest.value = row.prefs.RESTPassword;
  }
  const locked = !row.loaded || row.busy || state?.Running || !row.present;
  for (const input of [fields.proxy, fields.dns, fields.rest]) input.disabled = !!locked;
  el("rest-label").hidden = !vm.NeedsRESTPassword;
  el("save-state").textContent = row.saveStatus;
  el("problem").textContent = row.error || vm.Reason || "";
  const start = el("start");
  start.disabled = !!(locked || vm.Reason || !row.prefs.Proxy.trim() || !row.prefs.DNS.trim() || (vm.NeedsRESTPassword && !row.prefs.RESTPassword));
  start.textContent = state?.Running ? phaseNames[state.Phase] : switching ? "切换到仅主机并启用代理" : "启用透明代理";
}

function choose(key) {
  selected = key;
  for (const [k,r] of machines) r.tile.setAttribute("aria-pressed",String(k===key));
  paintForm(true);
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
    prefs:{Proxy:"",DNS:"8.8.8.8",RESTPassword:""},saves:Promise.resolve(),revision:0};
  machines.set(key,row);
  tile.onclick=()=>choose(key);
  el("machines").append(tile);
  load(row);
  return row;
}

function drawTiles() {
  const names=new Map();
  for (const row of machines.values()) if (row.present) names.set(row.vm.Name,1+(names.get(row.vm.Name)||0));
  let count=0;
  for (const row of machines.values()) {
    const {vm,tile,key}=row;
    tile.hidden=!row.present;
    if (!row.present) continue;
    count++;
    tile.title=vm.Path;
    tile.querySelector("strong").textContent=vm.Name;
    tile.querySelector("small").textContent=states[key]?.Running ? phaseNames[states[key].Phase] : vm.CurrentNetwork;
    tile.querySelector(".tile-path").textContent=names.get(vm.Name)>1 ? vm.Path : "";
  }
  el("count").textContent=hasMachineList ? String(count) : "";
}

function createCard(key,state) {
  const card=el("session").content.firstElementChild.cloneNode(true);
  const list=card.querySelector("ol");
  state.Steps.forEach((_,i)=>{
    const line=document.createElement("li");
    for (const cls of ["step-no","step-title","step-state","step-detail"]) {
      const cell=document.createElement("span");cell.className=cls;line.append(cell);
    }
    line.firstChild.textContent=String(i+1);
    list.append(line);
  });
  card.querySelector(".stop").onclick=async()=>{
    const row=machines.get(key);
    card.querySelector(".stop").disabled=true;
    try {await api.StopVM(row?.vm.Path || key);await updateStates();}
    catch(e){card.querySelector(".session-error").textContent=String(e);card.querySelector(".stop").disabled=false;}
  };
  cards.set(key,card);
  el("sessions").prepend(card);
  return card;
}

function drawSessions() {
  for (const [key,state] of Object.entries(states)) {
    const row=machines.get(key), vm=row?.vm;
    const card=cards.get(key) || createCard(key,state);
    card.dataset.phase=state.Phase;
    card.querySelector("h3").textContent=vm?.Name || key.split(/[\\/]/).pop();
    card.querySelector(".path").textContent=vm?.Path || key;
    const done=state.Steps.filter(s=>s.State==="done" || s.State==="skipped").length;
    card.querySelector(".phase").textContent=phaseNames[state.Phase]+" · "+done+"/"+state.Steps.length+" 步";
    card.querySelector(".summary").textContent=state.Status;
    const stop=card.querySelector(".stop");
    stop.hidden=!state.Running;stop.disabled=state.Phase==="stopping";
    state.Steps.forEach((step,i)=>{
      const node=card.querySelector("ol").children[i];
      node.dataset.state=step.State;
      node.children[1].textContent=step.Title;
      node.children[2].textContent=step.State==="pending" && !state.Running ? "未执行" : stepNames[step.State];
      const plannedSwitch = i===1 && vm?.NeedsSwitch && step.State==="pending"
        ? vm.CurrentNetwork+" → 仅主机模式（VMnet1）" : "";
      node.children[3].textContent=step.Detail || plannedSwitch;
    });
  }
  el("empty").hidden=!!cards.size;
}

form.oninput=()=>{
  const row=machines.get(selected);
  if (!row?.loaded) return;
  row.prefs={Proxy:fields.proxy.value,DNS:fields.dns.value,RESTPassword:fields.rest.value};
  row.error=""; save(row);paintForm();
};
form.onsubmit=async event=>{
  event.preventDefault();
  const row=machines.get(selected);
  if (!row || el("start").disabled) return;
  row.busy=true;row.error="";paintForm();
  try {
    await save(row);
    await api.StartVM(row.vm.Path,row.prefs.Proxy,row.prefs.DNS,row.prefs.RESTPassword);
    await updateStates();
    cards.get(row.key)?.scrollIntoView({block:"nearest"});
  } catch(e){row.error=String(e);}
  finally {row.busy=false;paintForm();}
};

async function refresh() {
  if (refreshBusy) return;
  const button=el("refresh"), message=el("message"), list=el("machines");
  refreshBusy=button.disabled=true;
  button.textContent=hasMachineList ? "刷新中…" : "加载中…";
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
    if (!found.has(selected)) choose(found.values().next().value || "");
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
    button.textContent=message.dataset.state==="error" ? "重试刷新" : "刷新虚拟机";
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
  catch(e){message.hidden=false;message.textContent="无法读取会话状态："+String(e);}
  finally {setTimeout(poll,650);}
}
el("refresh").onclick=refresh;
refresh();poll();
