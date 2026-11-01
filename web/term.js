// hb web shell: xterm.js on one WebSocket. Keys go up as "i<text>", sizes as "r{"c":cols,"r":rows}";
// the shell's output comes down as binary frames. Close code 4001 means the session ended.
(() => {
  "use strict";
  const term = new Terminal({cursorBlink: true, fontSize: 14, scrollback: 5000,
                             fontFamily: "ui-monospace, Menlo, Consolas, 'DejaVu Sans Mono', monospace"});
  const fit = new FitAddon.FitAddon();
  const status = document.getElementById("status");
  const again = document.getElementById("reconnect");
  term.loadAddon(fit);
  term.open(document.getElementById("term"));
  fit.fit();
  let ws = null;
  let opened = false;     // did the latest attempt connect?

  function send(text) {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(text);
  }

  function sendSize() {
    send("r" + JSON.stringify({c: term.cols, r: term.rows}));
  }

  function connect() {
    status.textContent = "connecting";
    again.hidden = true;
    opened = false;
    ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws");
    ws.binaryType = "arraybuffer";
    ws.onopen = () => { opened = true; status.textContent = ""; sendSize(); term.focus(); };
    ws.onmessage = (e) => { if (e.data instanceof ArrayBuffer) term.write(new Uint8Array(e.data)); };
    ws.onclose = (e) => {
      if (e.code === 4001) { location.replace("/"); return; }
      status.textContent = e.code === 1006 ? "disconnected" : "closed (" + e.code + ")";
      // This attempt never connected: likely the session is gone (the daemon restarted, or it expired).
      // Reloading shows the login page if so; a connection that dropped later can simply reconnect.
      again.textContent = opened ? "Reconnect" : "Reload";
      again.hidden = false;
    };
  }

  term.onData((d) => send("i" + d));
  term.onResize(sendSize);
  window.addEventListener("resize", () => fit.fit());
  again.addEventListener("click", () => { if (opened) connect(); else location.reload(); });
  connect();
})();
