// Lore Admin — vanilla JS SPA. No build step; runs from the embedded
// static files served at /admin/. All state lives in memory.

const API = '/admin/api';
let session = null; // { token, expires_at, user }
let me = null;

function $(sel) { return document.querySelector(sel); }
function $$(sel) { return Array.from(document.querySelectorAll(sel)); }

function showToast(msg, kind) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast' + (kind ? ' ' + kind : '');
  t.hidden = false;
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => t.hidden = true, 3500);
}

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (session && session.token) headers['Authorization'] = 'Bearer ' + session.token;
  const r = await fetch(API + path, { ...opts, headers });
  if (r.status === 401) {
    await logout();
    throw new Error('unauthorized');
  }
  if (!r.ok) {
    let body = null;
    try { body = await r.json(); } catch (_) {}
    throw new Error((body && body.error) || `HTTP ${r.status}`);
  }
  if (r.status === 204) return null;
  return r.json();
}

async function login(username, password) {
  const r = await fetch(API + '/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  if (!r.ok) {
    let body = null;
    try { body = await r.json(); } catch (_) {}
    throw new Error((body && body.error) || 'login failed');
  }
  session = await r.json();
  // Cookie set by the server; we also keep the token for explicit Authorization.
  await refreshMe();
  enterApp();
}

async function logout() {
  if (session && session.token) {
    try {
      await fetch(API + '/auth/logout', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + session.token },
      });
    } catch (_) { /* best effort */ }
  }
  session = null;
  me = null;
  document.cookie = 'session=; Path=/; Max-Age=0';
  enterLogin();
}

async function refreshMe() {
  me = await api('/auth/me');
}

function enterLogin() {
  $('#login-screen').hidden = false;
  $('#app-screen').hidden = true;
  $('#who').textContent = '';
  $('#logout').hidden = true;
  $('#login-form').reset();
  $('#login-error').hidden = true;
}

function enterApp() {
  $('#login-screen').hidden = true;
  $('#app-screen').hidden = false;
  const who = me && me.user ? me.user : (session && session.user) || {};
  $('#who').textContent = (who.username || '') + ' · ' + (who.role || '');
  $('#logout').hidden = false;
  refreshUsers();
}

function roleBadge(role) {
  const cls = role === 'Admin' ? 'ok' : role === 'Operator' ? 'warn' : 'muted';
  return `<span class="badge ${cls}">${role}</span>`;
}

async function refreshUsers() {
  const rows = await api('/users');
  const tb = $('#users-tbody');
  tb.innerHTML = '';
  for (const u of rows) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${u.username}</code></td>
      <td>${u.display_name}</td>
      <td>${roleBadge(u.role)}</td>
      <td>${new Date(u.created_at).toLocaleString()}</td>
      <td>${u.disabled ? '<span class="badge warn">disabled</span>' : '<span class="badge ok">active</span>'}</td>
      <td></td>
    `;
    const actions = tr.querySelector('td:last-child');
    const edit = document.createElement('button');
    edit.textContent = 'Edit';
    edit.onclick = () => openUserDialog(u);
    actions.appendChild(edit);

    if (me && me.user && me.user.id !== u.id) {
      const del = document.createElement('button');
      del.textContent = 'Delete';
      del.style.marginLeft = '6px';
      del.onclick = async () => {
        if (!confirm(`Delete user ${u.username}?`)) return;
        try {
          await api('/users/' + u.id, { method: 'DELETE' });
          showToast('Deleted ' + u.username);
          await refreshUsers();
        } catch (e) { showToast(String(e.message || e), 'error'); }
      };
      actions.appendChild(del);
    }
    tb.appendChild(tr);
  }
}

function openUserDialog(user) {
  const dlg = $('#user-dialog');
  const form = $('#user-form');
  form.reset();
  $('#user-form-err').hidden = true;
  if (user) {
    $('#user-dialog-title').textContent = 'Edit user ' + user.username;
    form.elements['id'].value = user.id;
    form.elements['username'].value = user.username;
    form.elements['display_name'].value = user.display_name;
    form.elements['role'].value = user.role;
    form.elements['password'].value = '';
    form.elements['password'].required = false;
  } else {
    $('#user-dialog-title').textContent = 'New user';
    form.elements['id'].value = '';
    form.elements['password'].required = true;
  }
  dlg.showModal();
}

async function saveUser(evt) {
  evt.preventDefault();
  const form = evt.target;
  const id = form.elements['id'].value;
  const payload = {
    username: form.elements['username'].value,
    display_name: form.elements['display_name'].value,
    role: form.elements['role'].value,
  };
  $('#user-dialog').close('save');
  try {
    if (id) {
      const pw = form.elements['password'].value;
      if (pw) {
        await api('/users/' + id + '/password', {
          method: 'POST', body: JSON.stringify({ new_password: pw }),
        });
      }
      await api('/users/' + id, {
        method: 'PATCH', body: JSON.stringify({
          display_name: payload.display_name,
          role: payload.role,
        }),
      });
      showToast('Updated ' + payload.username);
    } else {
      payload.password = form.elements['password'].value;
      await api('/users', { method: 'POST', body: JSON.stringify(payload) });
      showToast('Created ' + payload.username);
    }
    await refreshUsers();
  } catch (e) { showToast(String(e.message || e), 'error'); }
}

async function changeMyPassword(evt) {
  evt.preventDefault();
  const f = evt.target;
  try {
    await api('/auth/me/password', {
      method: 'POST',
      body: JSON.stringify({
        current_password: f.elements['current_password'].value,
        new_password: f.elements['new_password'].value,
      }),
    });
    $('#pw-msg').textContent = 'Password updated.';
    $('#pw-msg').hidden = false;
    f.reset();
    showToast('Password updated');
  } catch (e) {
    $('#pw-msg').textContent = String(e.message || e);
    $('#pw-msg').hidden = false;
  }
}

function bindTabs() {
  $$('.tab').forEach(btn => {
    btn.onclick = () => {
      $$('.tab').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      $$('.tabpane').forEach(p => p.hidden = true);
      const id = 'tab-' + btn.dataset.tab;
      const pane = document.getElementById(id);
      if (pane) pane.hidden = false;
    };
  });
}

document.addEventListener('DOMContentLoaded', () => {
  $('#login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = e.target;
    try {
      await login(f.elements['username'].value, f.elements['password'].value);
    } catch (err) {
      $('#login-error').textContent = String(err.message || err);
      $('#login-error').hidden = false;
    }
  });
  $('#logout').addEventListener('click', logout);
  $('#new-user').addEventListener('click', () => openUserDialog(null));
  $('#user-form').addEventListener('submit', saveUser);
  $('#user-form').addEventListener('cancel', () => $('#user-dialog').close('cancel'));
  $('#user-form').querySelector('menu button[value=cancel]').addEventListener('click', () => $('#user-dialog').close('cancel'));
  $('#change-pw').addEventListener('submit', changeMyPassword);
  bindTabs();

  // Try to auto-resume from existing session
  if (document.cookie.includes('session=')) {
    // Probe /me; if it succeeds, the cookie is good
    api('/auth/me').then(() => {
      enterApp();
    }).catch(() => enterLogin());
  } else {
    enterLogin();
  }
});
