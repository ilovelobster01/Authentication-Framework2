(function(){
  function qs(id){ return document.getElementById(id); }
  async function doLogin(){
    const res = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ username: qs('username').value, password: qs('password').value })
    });
    let data;
    try { data = await res.json(); } catch (e) { const t = await res.text(); alert(t || 'Login failed'); return; }
    if (data.status === '2fa_required') {
      qs('totp-form').classList.remove('hidden');
    } else if (data.status === 'ok') {
      window.location = '/admin/';
    } else {
      alert((data && data.message) || 'Login failed');
    }
  }
  async function doVerifyTotp(){
    const res = await fetch('/2fa/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ code: qs('totp').value, remember_device: !!qs('remember-device')?.checked })
    });
    let data;
    try { data = await res.json(); } catch (e) { const t = await res.text(); alert(t || 'Invalid code'); return; }
    if (data.status === 'ok') {
      window.location = '/admin/';
    } else {
      alert('Invalid code');
    }
  }
  document.addEventListener('DOMContentLoaded', function(){
    const bl = qs('btn-login');
    const bv = qs('btn-verify-totp');
    if (bl) bl.addEventListener('click', doLogin);
    if (bv) bv.addEventListener('click', doVerifyTotp);
    const pwd = qs('password');
    if (pwd) pwd.addEventListener('keydown', function(e){ if (e.key === 'Enter') { e.preventDefault(); doLogin(); } });
    const totp = qs('totp');
    if (totp) totp.addEventListener('keydown', function(e){ if (e.key === 'Enter') { e.preventDefault(); doVerifyTotp(); } });
  });
})();
