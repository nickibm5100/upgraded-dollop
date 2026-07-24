const STORAGE_KEY = 'vaultkey_data_v1';
 
let sessionKey = null;
let vaultEntries = [];
let editingId = null;
 
function bufToB64(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function b64ToBuf(b64){
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer;
}
 
async function deriveKey(password, saltB64){
  const salt = b64ToBuf(saltB64);
  const enc = new TextEncoder().encode(password);
  const baseKey = await crypto.subtle.importKey('raw', enc, 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name:'PBKDF2', salt, iterations:150000, hash:'SHA-256' },
    baseKey, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']
  );
}
async function encryptData(key, dataObj){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder().encode(JSON.stringify(dataObj));
  const cipher = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, enc);
  return { iv: bufToB64(iv), data: bufToB64(cipher) };
}
async function decryptData(key, ivB64, dataB64){
  const iv = new Uint8Array(b64ToBuf(ivB64));
  const cipherBuf = b64ToBuf(dataB64);
  const plainBuf = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, cipherBuf);
  return JSON.parse(new TextDecoder().decode(plainBuf));
}
 
function loadStore(){ const raw = localStorage.getItem(STORAGE_KEY); return raw ? JSON.parse(raw) : null; }
function saveStore(store){ localStorage.setItem(STORAGE_KEY, JSON.stringify(store)); }
 
const setupScreen = document.getElementById('setupScreen');
const unlockScreen = document.getElementById('unlockScreen');
const vaultScreen = document.getElementById('vaultScreen');
const headerActions = document.getElementById('headerActions');
 
function showScreen(el){
  [setupScreen, unlockScreen, vaultScreen].forEach(s => s.style.display = 'none');
  el.style.display = 'block';
}
function init(){
  const store = loadStore();
  headerActions.style.display = 'none';
  showScreen(store ? unlockScreen : setupScreen);
}
 
// ---------- Master password strength (setup screen) ----------
const masterPw = document.getElementById('masterPw');
const meterFill = document.getElementById('meterFill');
const strengthLabel = document.getElementById('strengthLabel');
masterPw.addEventListener('input', () => {
  const v = masterPw.value;
  let score = 0;
  if(v.length >= 8) score++;
  if(v.length >= 12) score++;
  if(/[A-Z]/.test(v)) score++;
  if(/[0-9]/.test(v)) score++;
  if(/[^A-Za-z0-9]/.test(v)) score++;
  const levels = [
    {l:'Foarte slabă', c:'#ef5c5c', p:15},
    {l:'Slabă', c:'#f5b942', p:35},
    {l:'Medie', c:'#f5b942', p:55},
    {l:'Bună', c:'#4c7cf3', p:78},
    {l:'Excelentă', c:'#2fe6a0', p:100}
  ];
  const idx = v.length === 0 ? -1 : Math.min(score, 4);
  if(idx === -1){ meterFill.style.width='0%'; strengthLabel.textContent=''; return; }
  meterFill.style.width = levels[idx].p + '%';
  meterFill.style.background = levels[idx].c;
  strengthLabel.textContent = levels[idx].l;
  strengthLabel.style.color = levels[idx].c;
});
 
// ---------- SETUP ----------
document.getElementById('createVaultBtn').addEventListener('click', async () => {
  const pw = masterPw.value;
  const pwConfirm = document.getElementById('masterPwConfirm').value;
  const errEl = document.getElementById('setupError');
 
  if(pw.length < 6){ errEl.textContent = 'Parola master trebuie să aibă minim 6 caractere.'; return; }
  if(pw !== pwConfirm){ errEl.textContent = 'Parolele nu coincid.'; return; }
 
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltB64 = bufToB64(salt);
  const key = await deriveKey(pw, saltB64);
  const encrypted = await encryptData(key, []);
 
  saveStore({ salt: saltB64, iv: encrypted.iv, data: encrypted.data });
  sessionKey = key;
  vaultEntries = [];
  errEl.textContent = '';
  enterVault();
});
 
// ---------- UNLOCK ----------
document.getElementById('unlockBtn').addEventListener('click', async () => {
  const store = loadStore();
  const errEl = document.getElementById('unlockError');
  const pw = document.getElementById('unlockPw').value;
  if(!pw){ errEl.textContent = 'Introdu parola master.'; return; }
  try{
    const key = await deriveKey(pw, store.salt);
    const decrypted = await decryptData(key, store.iv, store.data);
    sessionKey = key;
    vaultEntries = decrypted;
    errEl.textContent = '';
    enterVault();
  } catch(e){
    errEl.textContent = 'Parolă incorectă.';
  }
});
 
document.getElementById('resetVaultBtn').addEventListener('click', () => {
  if(confirm('Sigur vrei să ștergi tot seiful? Toate parolele salvate se vor pierde definitiv.')){
    localStorage.removeItem(STORAGE_KEY);
    sessionKey = null;
    vaultEntries = [];
    init();
  }
});
 
// ---------- LOCK ----------
document.getElementById('lockBtn').addEventListener('click', () => {
  sessionKey = null;
  vaultEntries = [];
  document.getElementById('unlockPw').value = '';
  document.getElementById('unlockError').textContent = '';
  init();
});
 
function enterVault(){
  headerActions.style.display = 'flex';
  showScreen(vaultScreen);
  renderEntries();
}
 
async function persistVault(){
  const store = loadStore();
  const encrypted = await encryptData(sessionKey, vaultEntries);
  store.iv = encrypted.iv;
  store.data = encrypted.data;
  saveStore(store);
}
 
// ---------- RENDER ----------
const entryList = document.getElementById('entryList');
const emptyState = document.getElementById('emptyState');
const searchInput = document.getElementById('searchInput');
 
function renderEntries(){
  const q = (searchInput.value || '').toLowerCase().trim();
  const filtered = vaultEntries.filter(e =>
    !q || e.site.toLowerCase().includes(q) || (e.username || '').toLowerCase().includes(q)
  );
 
  entryList.innerHTML = '';
  if(vaultEntries.length === 0){
    emptyState.style.display = 'block';
    emptyState.querySelector('p').textContent = 'Seiful e gol momentan. Adaugă prima ta parolă.';
    return;
  }
  if(filtered.length === 0){
    emptyState.style.display = 'block';
    emptyState.querySelector('p').textContent = 'Niciun rezultat pentru căutarea ta.';
    return;
  }
  emptyState.style.display = 'none';
 
  filtered.forEach(entry => {
    const card = document.createElement('div');
    card.className = 'entry-card';
    card.innerHTML = `
      <div class="entry-icon">${entry.site.charAt(0).toUpperCase()}</div>
      <div class="entry-info">
        <div class="entry-site">${escapeHtml(entry.site)}</div>
        <div class="entry-user">${escapeHtml(entry.username || '—')}</div>
        <div class="entry-pass-row">
          <span class="dots" data-visible="false">••••••••</span>
          <button class="mini-btn toggle-pw" title="Arată/Ascunde">👁</button>
        </div>
      </div>
      <div class="entry-actions">
        <button class="mini-btn copy-pw" title="Copiază parola">📋</button>
        <button class="mini-btn edit-entry" title="Editează">✏️</button>
        <button class="mini-btn danger delete-entry" title="Șterge">🗑</button>
      </div>
    `;
    card.querySelector('.toggle-pw').addEventListener('click', () => {
      const dotsEl = card.querySelector('.dots');
      const visible = dotsEl.dataset.visible === 'true';
      dotsEl.textContent = visible ? '••••••••' : entry.password;
      dotsEl.dataset.visible = visible ? 'false' : 'true';
    });
    card.querySelector('.copy-pw').addEventListener('click', () => {
      navigator.clipboard.writeText(entry.password).catch(()=>{});
      const btn = card.querySelector('.copy-pw');
      const original = btn.textContent;
      btn.textContent = '✓';
      setTimeout(() => btn.textContent = original, 1200);
    });
    card.querySelector('.edit-entry').addEventListener('click', () => openModal(entry));
    card.querySelector('.delete-entry').addEventListener('click', async () => {
      if(confirm(`Ștergi parola pentru "${entry.site}"?`)){
        vaultEntries = vaultEntries.filter(e => e.id !== entry.id);
        await persistVault();
        renderEntries();
      }
    });
    entryList.appendChild(card);
  });
}
searchInput.addEventListener('input', renderEntries);
 
function escapeHtml(str){
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
 
// ---------- MODAL ----------
const modalOverlay = document.getElementById('modalOverlay');
const modalTitle = document.getElementById('modalTitle');
const fSite = document.getElementById('fSite');
const fUser = document.getElementById('fUser');
const fPass = document.getElementById('fPass');
const fNotes = document.getElementById('fNotes');
 
function openModal(entry){
  editingId = entry ? entry.id : null;
  modalTitle.textContent = entry ? 'Editează parola' : 'Adaugă parolă';
  fSite.value = entry ? entry.site : '';
  fUser.value = entry ? entry.username : '';
  fPass.value = entry ? entry.password : '';
  fNotes.value = entry ? (entry.notes || '') : '';
  modalOverlay.style.display = 'flex';
}
function closeModal(){ modalOverlay.style.display = 'none'; }
 
document.getElementById('addEntryBtn').addEventListener('click', () => openModal(null));
document.getElementById('cancelModalBtn').addEventListener('click', closeModal);
 
document.getElementById('genInModal').addEventListener('click', () => {
  const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*';
  const arr = new Uint32Array(18);
  crypto.getRandomValues(arr);
  let pw = '';
  for(let i=0;i<18;i++) pw += charset[arr[i] % charset.length];
  fPass.value = pw;
});
 
document.getElementById('saveEntryBtn').addEventListener('click', async () => {
  const site = fSite.value.trim();
  const username = fUser.value.trim();
  const password = fPass.value;
  const notes = fNotes.value.trim();
  if(!site || !password){ alert('Completează cel puțin site-ul și parola.'); return; }
 
  if(editingId){
    const idx = vaultEntries.findIndex(e => e.id === editingId);
    if(idx > -1) vaultEntries[idx] = { ...vaultEntries[idx], site, username, password, notes };
  } else {
    vaultEntries.push({ id: crypto.randomUUID(), site, username, password, notes });
  }
  await persistVault();
  closeModal();
  renderEntries();
});
 
modalOverlay.addEventListener('click', (e) => { if(e.target === modalOverlay) closeModal(); });
 
init();