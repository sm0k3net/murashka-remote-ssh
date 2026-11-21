'use strict';
const jobTimers = {};
function jobPoll(view, callback) {
  clearTimeout(jobTimers[view]);
  jobTimers[view] = setTimeout(() => {
    if (state.session && state.view === view) callback();
  }, 2500);
}
function jobLine(job) {
  return node('p', job.error || (job.state === 'running' ? 'Operation in progress…' : 'Operation ' + job.state + '.'),
    job.state === 'error' ? 'error' : 'muted');
}
async function refreshReviews() {
  const host = state.host;
  const output = $('review-results');
  $('run-review').disabled = !host;
  if (!host) { output.replaceChildren(node('p', 'Add and select an SSH host first.')); return; }
  try {
    const data = await request('/api/host-review/' + host);
    if (host !== state.host) return;
    output.replaceChildren(node('p', hostName(host), 'muted'));
    $('run-review').disabled = data.job?.state === 'running';
    if (data.job) output.append(jobLine(data.job));
    if (data.job?.state === 'running') jobPoll('security', refreshReviews);
    if (!data.reports.length) output.append(node('p', 'No saved reviews yet.', 'muted'));
    for (const [index, report] of data.reports.entries()) {
      const card = node('article', undefined, 'card report-card');
      const title = new Date(report.created * 1000).toLocaleString();
      card.append(node('h2', title), node('p', report.scope + ' · ' + report.findings.length + ' observation(s)'));
      if (index === 0) {
        for (const item of report.findings.slice(0, 8)) card.append(node('p', item.severity.toUpperCase() + ' · ' + item.title + ' — ' + item.detail));
        card.append(node('p', report.baseline ? report.changes.length + ' configuration change(s) since the accepted baseline.' : 'No baseline was available for this review.'));
        const coverage = node('details');
        coverage.append(node('summary', 'Coverage and limitations'));
        const list = node('ul');
        for (const item of report.coverage) list.append(node('li', item));
        coverage.append(list); card.append(coverage);
      }
      const actions = node('div', undefined, 'tools');
      actions.append(button('Download HTML report', async () => {
        const blob = await request('/api/host-review/' + host + '/report/' + report.id, { blob: true });
        download(blob, 'murashka-security-review.html');
      }));
      if (index === 0) actions.append(button('Accept fingerprint baseline', async () => {
        if (!confirm('Use the selected review’s fingerprints as the baseline for future comparisons? Review the HTML report first.')) return;
        await post('/api/host-review/' + host, {action:'baseline', report:report.id, confirm:true});
        notify('Baseline saved. Run another review to compare against it.');
      }));
      card.append(actions); output.append(card);
    }
  } catch (error) { if (host === state.host) output.replaceChildren(node('p', error.message, 'error')); }
}
async function refreshDesktop() {
  const host = state.host;
  const output = $('desktop-options');
  if (!host) { output.replaceChildren(node('p', 'Add and select an SSH host first.')); return; }
  try {
    const data = await request('/api/desktop/' + host);
    if (host !== state.host) return;
    const card = node('article', undefined, 'card');
    card.append(node('h2', hostName(host)), node('p', 'Managed desktop uses its own unprivileged user. Installation requires Debian or Ubuntu with systemd, working APT repositories and non-interactive administrative access.'));
    if (data.job) card.append(jobLine(data.job));
    if (data.job?.state === 'running') jobPoll('desktop', refreshDesktop);
    const tools = node('div', undefined, 'tools');
    const port = select([[5901, 'VNC display :1'], [5900, 'VNC display :0']], 5901);
    port.setAttribute('aria-label', 'VNC display');
    tools.append(port, button('Open browser desktop', () => window.open('/desktop/' + host + '?port=' + port.value, '_blank', 'noopener')));
    card.append(tools);
    const form = node('div', undefined, 'tools');
    const variant = select([['openbox', 'Openbox · lightweight'], ['xfce', 'Xfce · full desktop']], 'openbox');
    variant.setAttribute('aria-label', 'Desktop profile');
    async function operation(action) {
      const detail = { install: 'Install desktop packages and start a loopback VNC service?', restart: 'Restart the managed desktop and disconnect open clients?', remove: 'Stop and remove the managed VNC service and its credentials? Installed packages and the desktop home stay on the host.' };
      if (!confirm(detail[action])) return;
      await post('/api/desktop/' + host, {action, variant:variant.value, confirm:true});
      await refreshDesktop();
    }
    if (!data.managed_credentials) form.append(variant, button('Install desktop', () => operation('install'), 'primary'));
    form.append(button('Restart managed desktop', () => operation('restart')), button('Remove managed desktop', () => operation('remove')));
    for (const item of form.querySelectorAll('button')) item.disabled = data.job?.state === 'running';
    card.append(form); output.replaceChildren(card);
  } catch (error) { if (host === state.host) output.replaceChildren(node('p', error.message, 'error')); }
}
$('review-refresh').onclick = refreshReviews;
$('desktop-refresh').onclick = refreshDesktop;
$('run-review').onclick = async () => {
  const host = state.host;
  if (!host) return;
  try {
    await post('/api/host-review/' + host, {action:'run'});
    await refreshReviews();
  } catch(error) { notify(error.message, true); }
};
