document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('btn-gen-qr');
  const qrBlock = document.getElementById('qr-block');
  const qrImg = document.getElementById('qr-img');
  const secretEl = document.getElementById('totp-secret');
  const form = document.getElementById('totp-enable-form');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    try {
      const resp = await fetch('/2fa/setup');
      if (!resp.ok) {
        const text = await resp.text();
        alert('Failed to generate 2FA setup: ' + text);
        return;
      }
      const data = await resp.json();
      secretEl.textContent = data.secret;
      qrImg.src = data.qr_data_url;
      qrBlock.classList.remove('hidden');
    } catch (e) {
      alert('Error generating 2FA QR: ' + e);
    }
  });
  form && form.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const code = document.getElementById('totp-code').value;
      const secret = document.getElementById('totp-secret').textContent;
      const resp = await fetch('/2fa/enable', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ secret, code }) });
      if (resp.ok) { location.reload(); } else { const j = await resp.json().catch(()=>({message:'error'})); alert(j.message || 'Failed to enable 2FA'); }
    } catch (e) {
      alert('Error enabling 2FA: ' + e);
    }
  });
});