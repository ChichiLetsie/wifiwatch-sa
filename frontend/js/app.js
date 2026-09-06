document.addEventListener('DOMContentLoaded', async () => {
  const statusEl = document.getElementById('api-status');
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    if (data.status === 'ok') {
      statusEl.textContent = 'Backend Connected: OK (Status 200)';
      statusEl.style.color = '#22c55e';
    } else {
      statusEl.textContent = 'Backend responded with unexpected status.';
    }
  } catch (err) {
    statusEl.textContent = 'Backend offline or unreachable.';
    statusEl.style.color = '#ef4444';
  }
});