"use strict";
{
  const dialog = el("exit-dialog"), cancel = el("exit-cancel"), approve = el("exit-approve");
  let currentID = "", revision = 0, closing = false;

  async function refreshPrompt() {
    const ticket = ++revision;
    try {
      const prompt = await api.PendingExitConfirmation();
      if (closing || ticket !== revision) return;
      if (!prompt) {
        currentID = "";
        if (dialog.open) dialog.close();
        return;
      }
      if (prompt.ID === currentID) return;
      currentID = prompt.ID;
      const vm = machines.get(prompt.VM.toLowerCase())?.vm;
      setText(el("exit-machine"), vm?.Name || prompt.VM.split(/[\\/]/).pop());
      setText(el("exit-path"), prompt.VM);
      setText(el("exit-ip"), prompt.IP);
      setText(el("exit-location"), prompt.Location);
      setText(el("exit-server"), prompt.Server);
      setText(el("exit-source"), prompt.Source);
      setText(el("exit-error"), "");
      approve.disabled = cancel.disabled = false;
      if (!dialog.open) dialog.showModal();
      cancel.focus();
    } catch (e) {
      if (ticket === revision && !closing) {
        const message = dialog.open ? el("exit-error") : el("session-message");
        message.hidden = false;
        setText(message, "读取出口确认信息失败 · "+String(e));
      }
    }
  }

  async function answer(approved) {
    if (!currentID || closing || approve.disabled) return;
    const id = currentID;
    approve.disabled = cancel.disabled = true;
    try { await api.AnswerExitConfirmation(id, approved); }
    catch (e) {
      if (currentID === id && !closing) {
        approve.disabled = cancel.disabled = false;
        setText(el("exit-error"), "提交选择失败 · "+String(e));
      }
    }
  }
  approve.onclick = () => answer(true);
  cancel.onclick = () => answer(false);
  dialog.oncancel = event => { event.preventDefault(); answer(false); };
  window.runtime.EventsOn("guestgate:exit-confirmation", refreshPrompt);
  window.runtime.EventsOn("guestgate:closing", () => {
    closing = true;
    if (dialog.open) dialog.close();
  });
  refreshPrompt();
}
