const $ = (id) => document.getElementById(id);
let mode = 'login';
let currentUser = null;

function showMessage(element, text, success = false) {
  element.textContent = text || '';
  element.className = `message${success ? ' success' : ''}`;
}
async function api(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || 'Request failed. Please try again.');
  return data;
}
function setMode(nextMode) {
  mode = nextMode;
  $('loginTab').classList.toggle('active', mode === 'login');
  $('registerTab').classList.toggle('active', mode === 'register');
  $('nameField').hidden = mode !== 'register';
  $('passwordHint').hidden = mode !== 'register';
  $('formTitle').textContent = mode === 'login' ? 'Sign in to your account' : 'Create your account';
  $('formSubtitle').textContent = mode === 'login' ? 'Enter your credentials to continue.' : 'Fill in your details to get started.';
  $('submitButton').innerHTML = mode === 'login' ? 'Sign in <span>→</span>' : 'Create account <span>→</span>';
  $('password').autocomplete = mode === 'login' ? 'current-password' : 'new-password';
  showMessage($('message'), '');
}
$('loginTab').addEventListener('click', () => setMode('login'));
$('registerTab').addEventListener('click', () => setMode('register'));

$('authForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('submitButton');
  button.disabled = true;
  showMessage($('message'), '');
  const body = { email: $('email').value.trim(), password: $('password').value };
  if (mode === 'register') body.name = $('name').value.trim();
  try {
    const result = await api(mode === 'login' ? '/api/login' : '/api/register', { method: 'POST', body });
    if (result.requires2FA) {
      $('authView').hidden = true;
      $('twoFactorView').hidden = false;
      $('loginCode').focus();
    } else if (mode === 'register') {
      showMessage($('message'), result.message, true);
      $('authForm').reset();
      setMode('login');
      showMessage($('message'), result.message, true);
    } else {
      await showDashboard(result.user);
    }
  } catch (error) { showMessage($('message'), error.message); }
  finally { button.disabled = false; }
});

$('twoFactorForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const result = await api('/api/verify-2fa', { method: 'POST', body: { code: $('loginCode').value.trim() } });
    $('twoFactorView').hidden = true;
    $('authView').hidden = true;
    await showDashboard(result.user);
  } catch (error) { showMessage($('twoFactorMessage'), error.message); }
});

async function showDashboard(user) {
  currentUser = user;
  $('authView').hidden = true;
  $('twoFactorView').hidden = true;
  $('dashboardView').hidden = false;
  $('userName').textContent = user.name;
  $('userEmail').textContent = user.email;
  $('avatar').textContent = user.name.charAt(0).toUpperCase();
  updateTwoFactorUI(user.twoFactorEnabled);
}
function updateTwoFactorUI(enabled) {
  $('twofaStatus').textContent = enabled ? 'Enabled — extra account protection is active' : 'Not enabled — add an authenticator app';
  $('twofaButton').textContent = enabled ? 'Manage 2FA' : 'Set up 2FA';
  $('twofaSetup').hidden = true;
  $('disable2fa').hidden = !enabled;
  $('enable2faForm').reset();
}
$('twofaButton').addEventListener('click', async () => {
  if (currentUser.twoFactorEnabled) {
    $('disable2fa').hidden = false;
    $('disableCode').focus();
    return;
  }
  try {
    const result = await api('/api/2fa/setup', { method: 'POST' });
    $('qrImage').src = result.qrCode;
    $('manualSecret').textContent = result.secret;
    $('twofaSetup').hidden = false;
  } catch (error) { showMessage($('dashboardMessage'), error.message); }
});
$('enable2faForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const result = await api('/api/2fa/enable', { method: 'POST', body: { code: $('enableCode').value.trim() } });
    currentUser.twoFactorEnabled = true;
    updateTwoFactorUI(true);
    showMessage($('dashboardMessage'), result.message, true);
  } catch (error) { showMessage($('dashboardMessage'), error.message); }
});
$('disable2faForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const result = await api('/api/2fa/disable', { method: 'POST', body: { code: $('disableCode').value.trim() } });
    currentUser.twoFactorEnabled = false;
    updateTwoFactorUI(false);
    showMessage($('dashboardMessage'), result.message, true);
  } catch (error) { showMessage($('dashboardMessage'), error.message); }
});
$('logoutButton').addEventListener('click', async () => {
  try {
    await api('/api/logout', { method: 'POST' });
    currentUser = null;
    $('dashboardView').hidden = true;
    $('twoFactorView').hidden = true;
    $('authView').hidden = false;
    $('authForm').reset();
    $('twoFactorForm').reset();
    setMode('login');
  } catch (error) { showMessage($('dashboardMessage'), error.message); }
});

(async function restoreSession() {
  try {
    const result = await api('/api/me');
    await showDashboard(result.user);
  } catch (_) {
    // No active session; leave the sign-in form visible.
  }
})();
