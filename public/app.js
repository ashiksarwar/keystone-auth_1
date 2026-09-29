(function () {
  const $ = id => document.getElementById(id);

  async function api(path, body) {
    const opts = body === undefined
      ? { credentials: 'same-origin' }
      : { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
    let res, data = {};
    try { res = await fetch(path, opts); } catch (e) { return { ok: false, status: 0, data: { error: 'Can’t reach the server. Check your connection and try again.' } }; }
    try { data = await res.json(); } catch (e) {}
    return { ok: res.ok, status: res.status, data };
  }

  function busy(form, on) { const b = form.querySelector('button[type=submit]'); b.disabled = on; }

  // ----- tabs -----
  function show(which) {
    const login = which === 'login';
    $('tabLogin').setAttribute('aria-selected', login); $('tabSignup').setAttribute('aria-selected', !login);
    $('loginForm').hidden = !login; $('signupForm').hidden = login;
    $('brandTitle').textContent = login ? 'Welcome back.' : 'Open your Keystone account.';
    $('brandText').textContent = login ? 'Sign in to reach your account, or create one in under a minute.' : 'One account, one password. You’re signed in as soon as you finish.';
    $('flash').hidden = true;
  }
  $('tabLogin').onclick = () => show('login'); $('tabSignup').onclick = () => show('signup');
  $('toSignup').onclick = () => show('signup'); $('toLogin').onclick = () => show('login');

  document.querySelectorAll('.eye').forEach(b => b.onclick = () => {
    const i = $(b.dataset.for); const s = i.type === 'password'; i.type = s ? 'text' : 'password'; b.textContent = s ? 'Hide' : 'Show';
  });

  function flash(msg, bad) { const f = $('flash'); f.className = 'banner' + (bad ? ' bad' : ''); f.textContent = msg; f.hidden = false; f.style.marginBottom = '18px'; }
  function setErr(inputId, errId, msg) { $(errId).textContent = msg || ''; if (inputId) $(inputId).setAttribute('aria-invalid', msg ? 'true' : 'false'); return !msg; }

  // ----- strength meter -----
  function score(p) { let s = 0; if (p.length >= 8) s++; if (/[a-z]/i.test(p) && /\d/.test(p)) s++; if (/[^a-z0-9]/i.test(p) || (/[a-z]/.test(p) && /[A-Z]/.test(p))) s++; if (p.length >= 12) s++; return s; }
  $('suPass').addEventListener('input', e => {
    const p = e.target.value, s = p ? score(p) : 0;
    const colors = ['var(--bad)', 'var(--bad)', 'var(--warn)', 'var(--ok)', 'var(--ok)'];
    document.querySelectorAll('.meter span').forEach((el, i) => el.style.background = i < s ? colors[s] : 'var(--line)');
    $('strength').textContent = !p ? 'Use 8+ characters with a letter and a number.' : ['Too weak', 'Weak', 'Fair', 'Strong', 'Very strong'][s];
  });

  // ----- sign up -----
  $('signupForm').addEventListener('submit', async e => {
    e.preventDefault();
    const name = $('suName').value.trim(), email = $('suEmail').value.trim(), p = $('suPass').value, p2 = $('suPass2').value;
    let ok = true;
    ok &= setErr('suName', 'suNameErr', name.length < 2 ? 'Enter your full name.' : '');
    ok &= setErr('suEmail', 'suEmailErr', !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) ? 'Enter a valid email, like name@example.com.' : '');
    ok &= setErr('suPass', 'suPassErr', p.length < 8 || !/[a-z]/i.test(p) || !/\d/.test(p) ? 'Use at least 8 characters, including a letter and a number.' : '');
    ok &= setErr('suPass2', 'suPass2Err', p2 !== p ? 'Passwords don’t match.' : '');
    ok &= setErr(null, 'termsErr', !$('terms').checked ? 'Accept the terms to continue.' : '');
    if (!ok) return;
    busy(e.target, true);
    const r = await api('/api/signup', { name, email, password: p });
    busy(e.target, false);
    if (!r.ok) {
      const f = r.data.fields || {};
      if (f.name) setErr('suName', 'suNameErr', f.name);
      if (f.email) setErr('suEmail', 'suEmailErr', f.email);
      if (f.password) setErr('suPass', 'suPassErr', f.password);
      if (!Object.keys(f).length) flash(r.data.error || 'Sign-up failed. Try again.', true);
      return;
    }
    e.target.reset(); $('suPass').dispatchEvent(new Event('input'));
    openDash(r.data.user, 'Account created. Welcome, ' + r.data.user.name.split(' ')[0] + '.');
  });

  // ----- sign in -----
  $('loginForm').addEventListener('submit', async e => {
    e.preventDefault();
    const email = $('loginEmail').value.trim(), password = $('loginPass').value;
    if (!email || !password) { setErr('loginPass', 'loginErr', 'Enter your email and password.'); return; }
    busy(e.target, true);
    const r = await api('/api/login', { email, password });
    busy(e.target, false);
    if (!r.ok) { setErr('loginPass', 'loginErr', r.data.error || 'Sign-in failed. Try again.'); return; }
    setErr('loginPass', 'loginErr', '');
    e.target.reset();
    openDash(r.data.user, 'Signed in. Welcome, ' + r.data.user.name.split(' ')[0] + '.', r.data.user.previousLoginAt);
  });

  // ----- account page -----
  const fmt = t => t ? new Date(t).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'First time';
  function openDash(u, banner, prevLogin) {
    $('authView').hidden = true; $('dashView').hidden = false;
    $('avatar').textContent = u.name.trim()[0].toUpperCase();
    $('dashName').textContent = u.name; $('dashEmail').textContent = u.email;
    $('dashBanner').textContent = banner;
    $('dJoined').textContent = new Date(u.createdAt).toLocaleDateString(undefined, { dateStyle: 'long' });
    $('dLast').textContent = fmt(prevLogin === undefined ? u.lastLoginAt : prevLogin);
    $('dCount').textContent = u.loginCount; $('dId').textContent = u.id;
    $('brandTitle').textContent = 'Hello, ' + u.name.split(' ')[0] + '.';
    $('brandText').textContent = 'Your account details are on the right. Sign out when you’re done.';
  }
  function backToLogin(msg) {
    $('dashView').hidden = true; $('authView').hidden = false; show('login');
    $('deleteForm').reset(); $('delErr').textContent = ''; document.querySelector('.danger').open = false;
    if (msg) flash(msg);
  }
  $('logout').onclick = async () => { await api('/api/logout', {}); backToLogin('You’ve signed out.'); };
  $('logoutAll').onclick = async () => { await api('/api/logout-all', {}); backToLogin('You’ve signed out on every device.'); };
  $('deleteForm').addEventListener('submit', async e => {
    e.preventDefault();
    busy(e.target, true);
    const r = await api('/api/delete-account', { password: $('delPass').value });
    busy(e.target, false);
    if (!r.ok) { $('delErr').textContent = r.data.error || 'Couldn’t delete the account.'; return; }
    backToLogin('Your account has been deleted.');
  });

  // ----- restore session on load -----
  (async () => {
    const r = await api('/api/me');
    if (r.ok) openDash(r.data.user, 'You’re still signed in on this browser.');
  })();
})();
