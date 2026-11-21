'use strict';
const copy = document.getElementById('copy-command');
const status = document.getElementById('copy-result');
if (navigator.clipboard) {
  copy.hidden = false;
  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(document.getElementById('commands').textContent.trim());
      status.textContent = 'Commands copied.';
    } catch {
      status.textContent = 'Clipboard access is unavailable. Select the commands to copy them.';
    }
  });
}
