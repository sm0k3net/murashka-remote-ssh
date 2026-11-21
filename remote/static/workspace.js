'use strict';
const $ = id => document.getElementById(id);
const state = { session: null, host: null, view: 'terminal', terminals: [], active: null, split: false };
const panes = ['left', 'right'].map(side => ({ root: $(side + '-pane'), host: null, path: '.', sequence: 0 }));
const icon = { folder: '▸ ', file: '· ' };
const grant = new URLSearchParams(location.hash.slice(1)).get('g')?.split('.');
let noticeTimer, dragged;
const endpoint = (host, action, path) => '/api/files/' + host + '/' + action + '?path=' + encodeURIComponent(path);
const join = (folder, name) => folder.replace(/\/$/, '') + '/' + name;

function node(tag, text, className) {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = text;
  if (className) el.className = className;
  return el;
}
function button(label, handler, className) {
  const el = node('button', label, className);
  el.type = 'button';
  el.onclick = async event => {
    try { await handler(event); }
    catch (error) { notify(error.message, true); }
  };
  return el;
}
function notify(message, error = false) {
  $('notice').textContent = message;
  $('notice').className = error ? 'error' : '';
  $('notice').hidden = false;
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => { $('notice').hidden = true; }, 5000);
}
async function request(path, { method = 'GET', body, raw = false, blob = false } = {}) {
  const headers = {};
  if (state.session?.csrf) headers['X-CSRF'] = state.session.csrf;
  if (body !== undefined && !raw) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(body);
  }
  const response = await fetch(path, { method, headers, body });
  if (!response.ok) {
    if (response.status === 401 && state.session) lock();
    throw Error((await response.text()).slice(0, 350) || 'Request failed (' + response.status + ').');
  }
  return blob ? response.blob() : response.json();
}
const post = (path, body) => request(path, { method: 'POST', body });
function dialog(title, content) {
  $('dialog-title').textContent = title;
  $('dialog-body').replaceChildren(content);
  $('dialog-error').textContent = '';
  if (!$('dialog').open) $('dialog').showModal();
}
function field(form, title, name, type = 'text', value = '', required = false) {
  const label = node('label', title);
  const input = node(type === 'textarea' ? 'textarea' : 'input');
  if (type !== 'textarea') input.type = type;
  input.name = name;
  input.value = value;
  input.required = required;
  label.append(input);
  form.append(label);
  return input;
}
function select(options, selected) {
  const el = node('select');
  for (const [value, label] of options) el.add(new Option(label, value));
  if (selected !== undefined && selected !== null) el.value = selected;
  return el;
}
function submit(form, label, handler) {
  const action = node('button', label, 'primary');
  form.append(action);
  form.onsubmit = async event => {
    event.preventDefault();
    action.disabled = true;
    $('dialog-error').textContent = '';
    try { await handler(); }
    catch (error) { $('dialog-error').textContent = error.message; }
    finally { action.disabled = false; }
  };
}
function download(blob, name) {
  const url = URL.createObjectURL(blob);
  const anchor = node('a');
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}
function hostName(id) { return state.session?.targets.find(host => host.id === id)?.name || 'Unknown host'; }
function owner() { return state.session?.role === 'owner'; }
function lock() {
  for (const term of [...state.terminals]) closeTerminal(term);
  state.session = null;
  $('dialog').close();
  $('workspace').hidden = true;
  $('login').hidden = false;
}
async function loadSession() {
  state.session = await request('/api/session');
  const hosts = state.session.targets;
  if (!hosts.some(host => host.id === state.host)) {
    state.host = hosts.find(host => host.id === state.session.target)?.id || hosts[0]?.id || null;
  }
  $('add-host').hidden = !owner();
  $('copy-jobs').hidden = !owner();
  for (const view of ['tunnels', 'security', 'desktop']) $('navigation').querySelector('[data-view='+view+']').hidden = !owner();
  $('hosts').replaceChildren();
  for (const host of hosts) {
    const row = node('div', undefined, 'host-row');
    const item = button(host.name, () => { state.host = host.id; renderSelection(); }, 'host');
    item.dataset.id = host.id;
    item.append(node('small', host.username + '@' + host.host));
    row.append(item);
    if (owner()) {
      const info = button('⋯', () => hostDetails(host));
      info.setAttribute('aria-label', 'Manage ' + host.name);
      row.append(info);
    }
    $('hosts').append(row);
  }
  if (!hosts.length) $('hosts').append(node('p', 'Add your first SSH host.', 'muted'));
  $('login').hidden = true;
  $('workspace').hidden = false;
  showView(!owner() && ['tunnels', 'security', 'desktop'].includes(state.view) ? 'terminal' : state.view);
}
function renderSelection() {
  for (const item of $('hosts').querySelectorAll('.host')) item.setAttribute('aria-pressed', String(Number(item.dataset.id) === state.host));
  $('new-terminal').disabled = !state.host;
  $('add-tunnel').disabled = !state.host;
  $('metrics-refresh').disabled = !state.host;
  if (state.view === 'monitoring') refreshMetrics();
  if (state.view === 'security') refreshReviews();
  if (state.view === 'desktop') refreshDesktop();
}
function hostDetails(host) {
  const body = node('div');
  body.append(node('p', host.username + '@' + host.host + ':' + host.port), node('code', host.fingerprint));
  body.append(node('p', 'Removing a host closes its sessions, removes its saved tunnels and revokes guest access.'));
  body.append(button('Remove host', async () => {
    if (!confirm('Remove ' + host.name + '?')) return;
    await request('/api/targets/' + host.id, { method: 'DELETE' });
    for (const term of state.terminals.filter(item => item.host === host.id)) closeTerminal(term);
    $('dialog').close();
    await loadSession();
  }));
  dialog(host.name, body);
}
function addHost() {
  const form = node('form', undefined, 'stack');
  field(form, 'Display name', 'name', 'text', '', true).maxLength = 60;
  const host = field(form, 'SSH hostname or IP', 'host', 'text', '', true);
  const port = field(form, 'SSH port', 'port', 'number', '22', true);
  port.min = 1; port.max = 65535;
  const user = field(form, 'SSH username', 'username', 'text', '', true);
  const key = field(form, 'Private key (recommended)', 'private_key', 'textarea');
  const passphrase = field(form, 'Key passphrase, if any', 'passphrase', 'password');
  const password = field(form, 'SSH password, if using password authentication', 'ssh_password', 'password');
  const verified = node('div');
  let pinned;
  const reset = () => { pinned = null; verified.replaceChildren(); };
  for (const input of [host, port]) input.addEventListener('input', reset);
  const probe = button('Fetch host fingerprint', async () => {
    reset();
    const address = host.value, number = port.value;
    const candidate = await post('/api/probe', { host: address, port: Number(number), username: user.value });
    if (address !== host.value || number !== port.value) return;
    const label = node('label', undefined, 'check');
    const checkbox = node('input'); checkbox.type = 'checkbox';
    label.append(checkbox, node('span', 'I verified this fingerprint through a trusted channel.'));
    verified.append(node('code', candidate.fingerprint), label);
    pinned = { ...candidate, checkbox };
  });
  form.append(probe, verified);
  submit(form, 'Save host', async () => {
    if (!pinned?.checkbox.checked) throw Error('Fetch and independently verify the host fingerprint.');
    const data = await post('/api/targets', {
      name: form.elements.name.value, host: host.value, port: Number(port.value), username: user.value,
      hostkey: pinned.hostkey, auth: { private_key: key.value, passphrase: passphrase.value, password: password.value },
    });
    state.host = data.id;
    $('dialog').close();
    await loadSession();
  });
  dialog('Add SSH host', form);
}
function showView(view) {
  state.view = view;
  for (const section of document.querySelectorAll('.view')) section.hidden = section.id !== view;
  for (const item of $('navigation').querySelectorAll('button')) {
    if (item.dataset.view === view) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  }
  renderSelection();
  if (view === 'terminal') drawTerminals();
  if (view === 'files') {
    const valid = state.session.targets.map(host => host.id);
    for (const pane of panes) {
      if (!valid.includes(pane.host)) { pane.host = state.host; pane.path = '.'; }
      loadPane(pane);
    }
  }
  if (view === 'tunnels') refreshTunnels();
}
function sendTerminal(term, data) {
  if (term.ws.readyState !== WebSocket.OPEN) return;
  for (let offset = 0; offset < data.length; offset += 4096) term.ws.send(JSON.stringify({ type: 'input', data: data.slice(offset, offset + 4096) }));
}
function drawTerminals() {
  $('terminal-empty').hidden = state.terminals.length > 0;
  $('terminals').classList.toggle('split', state.split);
  $('split').setAttribute('aria-pressed', String(state.split));
  $('terminal-tabs').replaceChildren();
  for (const term of state.terminals) {
    const active = term === state.active;
    const group = node('div', undefined, 'tab-group');
    const tab = button(hostName(term.host) + ' · ' + term.number, () => { state.active = term; drawTerminals(); term.terminal.focus(); }, 'tab');
    tab.setAttribute('aria-selected', String(active));
    const close = button('×', () => closeTerminal(term));
    close.setAttribute('aria-label', 'Close ' + hostName(term.host) + ' terminal ' + term.number);
    group.append(tab, close);
    $('terminal-tabs').append(group);
    term.pane.hidden = state.split ? !active && !state.terminals.filter(item => item !== state.active).slice(0, 3).includes(term) : !active;
    term.pane.classList.toggle('active', active);
    if (!term.pane.hidden && state.view === 'terminal') requestAnimationFrame(() => { if (state.terminals.includes(term)) term.fit.fit(); });
  }
}
let terminalNumber = 0;
function openTerminal() {
  if (!state.host || state.terminals.length >= 8) return notify('Select a host or close one of the eight open terminals.');
  const pane = node('article', undefined, 'terminal-pane');
  const label = node('div', hostName(state.host) + ' · Connecting', 'terminal-label');
  const body = node('div', undefined, 'terminal-body');
  const controls = node('div', undefined, 'terminal-controls');
  pane.append(label, body, controls);
  $('terminals').append(pane);
  const terminal = new Terminal({ cursorBlink: true, fontSize: 14, scrollback: 3000, theme: { background: '#0c131d', foreground: '#eef3fa', cursor: '#b6ef87' } });
  const fit = new FitAddon.FitAddon(), search = new SearchAddon.SearchAddon();
  terminal.loadAddon(fit);
  terminal.loadAddon(search);
  terminal.open(body);
  const ws = new WebSocket('wss://' + location.host + '/ws/' + state.host);
  const term = { terminal, fit, search, ws, pane, host: state.host, number: ++terminalNumber };
  const resize = () => {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'resize', cols: terminal.cols, rows: terminal.rows }));
  };
  const observer = new ResizeObserver(() => { if (body.offsetWidth && !pane.hidden) fit.fit(); });
  observer.observe(body);
  term.observer = observer;
  for (const [label, key] of [['Ctrl C', '\x03'], ['Ctrl D', '\x04'], ['Esc', '\x1b'], ['Tab', '\t'], ['↑', '\x1b[A'], ['↓', '\x1b[B']]) {
    controls.append(button(label, () => sendTerminal(term, key)));
  }
  controls.append(
    button('Copy', () => navigator.clipboard.writeText(terminal.getSelection())),
    button('Paste', async () => sendTerminal(term, await navigator.clipboard.readText()))
  );
  terminal.onData(data => sendTerminal(term, data));
  terminal.onResize(resize);
  ws.onmessage = event => {
    const message = JSON.parse(event.data);
    if (message.type === 'output') terminal.write(message.data);
    if (message.type === 'ready') { label.textContent = hostName(term.host) + ' · Connected'; resize(); }
    if (message.type === 'error') terminal.writeln('\r\n' + message.message);
  };
  ws.onclose = () => { label.textContent = hostName(term.host) + ' · Disconnected'; };
  state.terminals.push(term);
  state.active = term;
  drawTerminals();
  terminal.focus();
}
function closeTerminal(term) {
  term.observer.disconnect();
  term.ws.onmessage = null;
  term.ws.close();
  term.terminal.dispose();
  term.pane.remove();
  state.terminals = state.terminals.filter(item => item !== term);
  if (state.active === term) state.active = state.terminals.at(-1);
  drawTerminals();
}
function size(bytes) {
  const value = Number(bytes);
  if (!Number.isFinite(value)) return '—';
  if (value >= 1024 ** 3) return (value / 1024 ** 3).toFixed(1) + ' GiB';
  if (value >= 1024 ** 2) return (value / 1024 ** 2).toFixed(1) + ' MiB';
  if (value >= 1024) return (value / 1024).toFixed(1) + ' KiB';
  return value + ' B';
}
async function loadPane(pane) {
  const sequence = ++pane.sequence;
  const frame = node('div', undefined, 'file-pane');
  pane.root.replaceChildren(frame);
  if (!pane.host) { frame.append(node('p', 'Add a host to browse its files.')); return; }
  const header = node('div', undefined, 'pane-head');
  const picker = select(state.session.targets.map(host => [host.id, host.name]), pane.host);
  picker.setAttribute('aria-label', pane === panes[0] ? 'Left host' : 'Right host');
  picker.onchange = () => { pane.host = Number(picker.value); pane.path = '.'; loadPane(pane); };
  const upload = node('input'); upload.type = 'file'; upload.hidden = true;
  upload.onchange = async () => {
    const file = upload.files[0];
    if (!file) return;
    try {
      if (file.size > 10 * 1024 ** 2) throw Error('Upload limit is 10 MiB.');
      await request(endpoint(pane.host, 'upload', join(pane.path, file.name)), { method: 'POST', body: file, raw: true });
      notify('Uploaded ' + file.name);
      loadPane(pane);
    } catch (error) { notify(error.message, true); }
  };
  header.append(picker, button('Upload', () => upload.click()), upload);
  const pathRow = node('form', undefined, 'file-path');
  const path = node('input'); path.value = pane.path; path.setAttribute('aria-label', 'Remote directory');
  const go = node('button', 'Go');
  pathRow.append(button('↑', () => { pane.path = pane.parent || '/'; loadPane(pane); }), path, go);
  pathRow.onsubmit = event => { event.preventDefault(); pane.path = path.value || '.'; loadPane(pane); };
  const listing = node('div', undefined, 'file-list');
  frame.append(header, pathRow, listing);
  frame.ondragover = event => { if (owner() && dragged && dragged.pane !== pane) { event.preventDefault(); frame.classList.add('drop'); } };
  frame.ondragleave = event => { if (!frame.contains(event.relatedTarget)) frame.classList.remove('drop'); };
  frame.ondrop = async event => {
    event.preventDefault();
    frame.classList.remove('drop');
    if (owner() && dragged && dragged.pane !== pane) {
      try { await queueCopy(dragged, pane); }
      catch (error) { notify(error.message, true); }
    }
  };
  try {
    const result = await request(endpoint(pane.host, 'list', pane.path));
    if (sequence !== pane.sequence) return;
    pane.path = result.path; pane.parent = result.parent; path.value = result.path;
    if (!result.entries.length) listing.append(node('p', 'This folder is empty.', 'muted'));
    for (const entry of result.entries) {
      const entryPath = join(result.path, entry.name);
      const row = node('div', undefined, 'row file-row');
      const name = button((entry.directory ? icon.folder : icon.file) + entry.name, () => {
        if (entry.directory) { pane.path = entryPath; return loadPane(pane); }
        return editFile(pane.host, entryPath, entry.name);
      }, 'name');
      name.title = entry.name + (entry.directory ? '' : ' · ' + size(entry.size));
      const actions = node('div', undefined, 'tools');
      if (!entry.directory) actions.append(button('Download', async () => {
        const blob = await request(endpoint(pane.host, 'download', entryPath), { blob: true });
        download(blob, entry.name);
      }));
      if (owner() && !entry.symlink) {
        const source = { pane, host: pane.host, path: entryPath, name: entry.name };
        actions.append(button('Copy', () => queueCopy(source, panes.find(item => item !== pane))));
        row.draggable = true;
        row.ondragstart = event => { dragged = source; event.dataTransfer.setData('text/plain', entry.name); event.dataTransfer.effectAllowed = 'copy'; };
        row.ondragend = () => { dragged = null; document.querySelectorAll('.drop').forEach(item => item.classList.remove('drop')); };
      }
      row.append(name, actions);
      listing.append(row);
    }
    if (result.truncated) listing.append(node('p', 'Showing the first 1,000 entries.', 'muted'));
  } catch (error) { if (sequence === pane.sequence) listing.append(node('p', error.message, 'error')); }
}
async function editFile(host, path, name) {
  const file = await request(endpoint(host, 'read', path));
  const form = node('form', undefined, 'stack');
  const editor = node('textarea', undefined, 'editor');
  editor.setAttribute('aria-label', 'File contents');
  editor.spellcheck = false; editor.value = file.text;
  form.append(node('p', file.path, 'muted'), editor);
  submit(form, 'Save changes', async () => {
    const result = await post(endpoint(host, 'save', file.path), { text: editor.value, revision: file.revision });
    file.revision = result.revision;
    notify('File saved.');
  });
  dialog(name, form);
}
async function queueCopy(source, destination) {
  if (!destination.host) throw Error('Select a destination host.');
  const path = join(destination.path, source.name);
  if (!confirm('Copy ' + source.path + ' to ' + hostName(destination.host) + ':' + path + '?')) return;
  await post('/api/copies', { source_host: source.host, source: source.path, destination_host: destination.host, destination: path, confirm: true });
  await showJobs();
}
async function showJobs() {
  const jobs = await request('/api/copies');
  const content = node('div');
  content.append(button('Refresh', async () => { await showJobs(); panes.forEach(loadPane); }));
  if (!jobs.length) content.append(node('p', 'No transfers yet.', 'muted'));
  for (const job of jobs) {
    const row = node('article', undefined, 'card');
    row.append(node('h3', job.state + ' · ' + size(job.bytes_done)), node('p', job.source + ' → ' + job.destination));
    if (job.error) row.append(node('p', job.error, 'error'));
    if (['queued', 'running'].includes(job.state)) row.append(button('Cancel', async () => {
      await post('/api/copies', { action: 'cancel', id: job.id });
      await showJobs();
    }));
    content.append(row);
  }
  dialog('Transfer history', content);
}
async function refreshMetrics() {
  const host = state.host;
  $('metrics').replaceChildren(node('p', host ? 'Reading resources…' : 'Add an SSH host to see resources.', 'muted'));
  if (!host) return;
  try {
    const { sample: sample, checked } = await request('/api/metrics/' + host);
    if (host !== state.host) return;
    const readings = node('div', undefined, 'cards metrics');
    const entries = [
      ['CPU', sample.cpu, sample.cpus + ' logical cores'],
      ['Memory', sample.ram, size(sample.ram_used) + ' used of ' + size(sample.ram_total)],
      ['Disk', sample.disk, size(sample.disk_free) + ' available of ' + size(sample.disk_total)],
    ];
    for (const [label, fraction, details] of entries) {
      const card = node('article', undefined, 'card');
      const meter = node('meter'); meter.min = 0; meter.max = 100; meter.value = Number(fraction) || 0;
      card.append(node('h2', label), node('strong', Number(fraction).toFixed(1) + '%', 'reading'), meter, node('p', details));
      readings.append(card);
    }
    const processes = node('div', undefined, 'card');
    const table = node('table');
    const header = table.createTHead().insertRow();
    ['Process', 'PID', 'CPU', 'RAM'].forEach(label => header.append(node('th', label)));
    for (const item of (Array.isArray(sample.top) ? sample.top : []).slice(0, 10)) {
      const row = table.insertRow();
      [item.name, item.pid, item.cpu + '%', size(item.ram_mb * 1024 ** 2)].forEach(value => { row.insertCell().textContent = value; });
    }
    processes.append(node('h2', 'Top processes by CPU'), table);
    $('metrics').replaceChildren(node('p', hostName(host) + ' · Sampled ' + new Date(checked * 1000).toLocaleTimeString(), 'muted'), readings, processes);
  } catch (error) { if (host === state.host) $('metrics').replaceChildren(node('p', error.message, 'error')); }
}
const kindLabel = { local: 'Reach a remote service', remote: 'Expose a local service on a remote host', socks: 'SOCKS5 proxy' };
async function refreshTunnels() {
  $('tunnel-list').replaceChildren(node('p', 'Loading tunnels…', 'muted'));
  try {
    const profiles = await request('/api/forwards');
    $('tunnel-list').replaceChildren();
    for (const profile of profiles) {
      const card = node('article', undefined, 'card');
      const running = profile.state !== 'stopped';
      const tools = node('div', undefined, 'tools');
      const actions = (action, body = {}) => post('/api/forwards', { action, id: profile.id, ...body });
      card.append(node('h2', profile.name), node('p', kindLabel[profile.kind] + ' · ' + hostName(profile.host)),
        node('p', profile.state + (profile.autostart ? ' · Auto-start' : '')),
        node('code', profile.location + ' · 127.0.0.1:' + (profile.listen_port || profile.port || 'automatic')));
      if (profile.error) card.append(node('p', profile.error, 'error'));
      tools.append(button(running ? 'Stop' : 'Start', async () => { await actions(running ? 'stop' : 'start'); await refreshTunnels(); }));
      if (!running) tools.append(button('Edit', () => tunnelForm(profile)));
      if (profile.state === 'running' && (profile.kind !== 'remote' || profile.endpoint === 'computer')) {
        tools.append(button('Computer bridge', async () => {
          const local = prompt('Local computer port (1024–65535)', profile.kind === 'socks' ? '1080' : String(Math.max(1024, profile.destination_port || 8080)));
          if (!local) return;
          const archive = await request('/api/forwards/bridge', { method: 'POST', body: { id: profile.id, local_port: Number(local) }, blob: true });
          download(archive, 'murashka-tunnel.zip');
        }));
      }
      tools.append(button('Delete', async () => { if (confirm('Delete ' + profile.name + '?')) { await actions('delete'); await refreshTunnels(); } }));
      card.append(tools); $('tunnel-list').append(card);
    }
    if (!profiles.length) $('tunnel-list').append(node('p', 'No tunnels configured.', 'muted'));
  } catch (error) { $('tunnel-list').replaceChildren(node('p', error.message, 'error')); }
}
function tunnelForm(profile = {}) {
  const form = node('form', undefined, 'stack');
  const name = field(form, 'Name', 'name', 'text', profile.name || '', true); name.maxLength = 80;
  const choices = Object.entries(kindLabel).filter(([value]) => value !== 'remote' || state.session.reverse);
  const kind = select(choices, profile.kind);
  const host = select(state.session.targets.map(item => [item.id, item.name]), profile.host || state.host);
  const end = select([['gateway', 'Gateway'], ['computer', 'My computer (bridge)']], profile.endpoint || 'gateway');
  for (const [label, input] of [['Tunnel type', kind], ['SSH host', host], ['Local endpoint', end]]) {
    const wrapper = node('label', label); wrapper.append(input); form.append(wrapper);
  }
  const port = field(form, 'Listen port (0 chooses a port automatically)', 'port', 'number', profile.port ?? 0, true);
  port.min = 0; port.max = 65535;
  const destination = field(form, 'Destination hostname', 'destination', 'text', profile.destination_host || '127.0.0.1', true);
  const servicePort = field(form, 'Destination port', 'servicePort', 'number', profile.destination_port || 8080, true);
  servicePort.min = 1; servicePort.max = 65535;
  const syncFields = () => {
    for (const input of [destination, servicePort]) {
      input.disabled = kind.value === 'socks'; input.parentElement.hidden = input.disabled;
    }
  };
  kind.onchange = syncFields; syncFields();
  const check = node('input'); check.type = 'checkbox'; check.checked = Boolean(profile.autostart);
  const label = node('label', undefined, 'check'); label.append(check, node('span', 'Start automatically and reconnect'));
  form.append(label);
  submit(form, 'Save tunnel', async () => {
    const result = await post('/api/forwards', {
      action: 'save', id: profile.id || '', name: name.value, host: Number(host.value), kind: kind.value,
      endpoint: end.value, port: Number(port.value), destination_host: destination.value,
      destination_port: Number(servicePort.value), autostart: check.checked,
    });
    if (check.checked) await post('/api/forwards', { action: 'start', id: result.id });
    $('dialog').close(); await refreshTunnels();
  });
  dialog(profile.id ? 'Edit tunnel' : 'Add tunnel', form);
}
$('close-dialog').onclick = () => $('dialog').close();
$('dialog').addEventListener('close', () => $('dialog-body').replaceChildren());
$('login-form').onsubmit = async event => {
  event.preventDefault();
  if (grant?.length !== 2) { $('login-error').textContent = 'Open the complete link generated by the local CLI.'; return; }
  try {
    await post('/api/login', { id: grant[0], token: grant[1], password: $('password').value });
    history.replaceState(null, '', '/'); $('password').value = '';
    await loadSession();
  } catch (error) { $('login-error').textContent = error.message; }
};
$('lock').onclick = async () => {
  try { await post('/api/logout', {}); lock(); }
  catch (error) { notify(error.message, true); }
};
$('navigation').onclick = event => { if (event.target.dataset.view) showView(event.target.dataset.view); };
$('add-host').onclick = addHost;
$('new-terminal').onclick = openTerminal;
$('split').onclick = () => { state.split = !state.split; drawTerminals(); };
$('find').onclick = () => { $('search-tools').hidden = !$('search-tools').hidden; if (!$('search-tools').hidden) $('search').focus(); };
const searchTerminal = backwards => {
  const value = $('search').value;
  if (value && state.active) state.active.search[backwards ? 'findPrevious' : 'findNext'](value);
};
$('previous').onclick = () => searchTerminal(true);
$('next').onclick = () => searchTerminal(false);
$('search').onkeydown = event => { if (event.key === 'Enter') searchTerminal(event.shiftKey); };
$('copy-jobs').onclick = () => showJobs().catch(error => notify(error.message, true));
$('metrics-refresh').onclick = refreshMetrics;
$('tunnel-refresh').onclick = refreshTunnels;
$('add-tunnel').onclick = () => tunnelForm();
setInterval(() => {
  if (!state.session) return;
  const minutes = Math.ceil((state.session.expires - Date.now() / 1000) / 60);
  if (minutes <= 0) lock();
  else $('expires').textContent = minutes + ' min left';
}, 1000);
if (!grant) loadSession().catch(() => {});
