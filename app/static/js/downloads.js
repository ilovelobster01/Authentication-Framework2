(function(){
  const el = (id)=>document.getElementById(id);
  async function analyze() {
    const showRaw = document.getElementById('show-raw')?.checked;
    const url = el('dl-url').value.trim();
    if (!url) { alert('Enter URL'); return; }
    try {
      const resp = await fetch('/downloads/analyze', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ url, raw: showRaw }), credentials: 'same-origin' });
      if (!resp.ok) { const t = await resp.text(); alert('Analyze failed: '+t); return; }
      const data = await resp.json();
      if (showRaw && data.raw_formats) {
        el('raw-pre').textContent = JSON.stringify(data.raw_formats, null, 2);
        el('raw-formats').classList.remove('hidden');
      } else {
        el('raw-formats').classList.add('hidden');
      }
      el('dl-title').textContent = data.title || '';
      const vf = el('video-format'); const af = el('audio-format'); const cf = el('combined-format');
      const combRow = el('combined-row'); const sepRow = el('separate-row');
      vf.innerHTML = ''; af.innerHTML = ''; cf.innerHTML='';
      // Progressive combined formats
      if ((data.progressive_formats||[]).length) {
        (data.progressive_formats||[]).forEach(f=>{
          const opt = document.createElement('option');
          opt.value = f.format_id; opt.text = `${f.format_id} ${f.height||''}p ${f.fps||''}fps ${f.ext||''}`;
          cf.appendChild(opt);
        });
        combRow.classList.remove('hidden');
      } else {
        combRow.classList.add('hidden');
      }
      // Separate formats
      (data.video_formats||[]).forEach(f=>{
        const opt = document.createElement('option');
        opt.value = f.format_id; opt.text = `${f.format_id} ${f.height||''}p ${f.fps||''}fps ${f.ext||''}`;
        vf.appendChild(opt);
      });
      (data.audio_formats||[]).forEach(f=>{
        const opt = document.createElement('option');
        opt.value = f.format_id; opt.text = `${f.format_id} ${f.ext||''} ${f.acodec||''}`;
        af.appendChild(opt);
      });
      el('analyze-result').classList.remove('hidden');
    } catch (e) {
      alert('Analyze error: '+e);
    }
  }
  function getMode() {
    const radios = document.querySelectorAll('input[name="mode"]');
    for (const r of radios) { if (r.checked) return r.value; }
    return 'both';
  }
  async function enqueue() {
    const url = el('dl-url').value.trim();
    const vf = el('video-format').value;
    const af = el('audio-format').value;
    const cf = el('combined-format').value;
    const filename = el('dl-filename').value.trim();
    const mode = getMode();
    let format = 'bestvideo+bestaudio/best';
    if (mode === 'video') {
      format = vf || 'bestvideo';
    } else if (mode === 'audio') {
      format = af || 'bestaudio';
    } else {
      if (cf) format = cf; // combined progressive selection
      else if (vf && af) format = `${vf}+${af}`;
      else if (vf) format = `${vf}`;
      else if (af) format = `${af}`;
    }
    try {
      const resp = await fetch('/downloads/create', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ url, format, filename }), credentials: 'same-origin' });
      const j = await resp.json().catch(()=>({}));
      if (resp.ok) { alert('Enqueued'); location.reload(); } else { alert('Failed: '+(j.message||resp.status)); }
    } catch (e) {
      alert('Enqueue error: '+e);
    }
  }
  window.addEventListener('DOMContentLoaded', ()=>{
    const ba = document.getElementById('btn-analyze');
    const be = document.getElementById('btn-enqueue');
    if (ba) ba.addEventListener('click', analyze);
    if (be) be.addEventListener('click', enqueue);
  });
})();
