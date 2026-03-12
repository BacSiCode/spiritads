/* ═══════════════════════════════════════════════════════════════
   SpiritAds – api.js
   Centralized API client + auth state management
═══════════════════════════════════════════════════════════════ */

const API_BASE = '/api';

// ─── Auth State ──────────────────────────────────────────────
const Auth = {
  getToken: () => localStorage.getItem('sa_token'),
  getUser: () => {
    try { return JSON.parse(localStorage.getItem('sa_user')); } catch { return null; }
  },
  setSession: (token, user) => {
    localStorage.setItem('sa_token', token);
    localStorage.setItem('sa_user', JSON.stringify(user));
  },
  clearSession: () => {
    localStorage.removeItem('sa_token');
    localStorage.removeItem('sa_user');
  },
  isLoggedIn: () => !!localStorage.getItem('sa_token'),
  isAdmin: () => {
    const u = Auth.getUser();
    return u?.role === 'admin';
  },
  isAdvertiser: () => {
    const u = Auth.getUser();
    return u?.role === 'advertiser' || u?.role === 'admin';
  },
};

// ─── HTTP Client ─────────────────────────────────────────────
const http = async (method, path, body = null, requireAuth = false) => {
  const headers = { 'Content-Type': 'application/json' };
  if (requireAuth || Auth.isLoggedIn()) {
    const token = Auth.getToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
  }

  const config = { method, headers };
  if (body) config.body = JSON.stringify(body);

  try {
    const res = await fetch(`${API_BASE}${path}`, config);
    const data = await res.json();

    if (res.status === 401) {
      Auth.clearSession();
      UI.updateNavForAuth();
    }

    return { ok: res.ok, status: res.status, ...data };
  } catch (error) {
    return { ok: false, success: false, message: 'Không thể kết nối đến máy chủ. Vui lòng thử lại.' };
  }
};

const api = {
  get:    (path, auth = false) => http('GET', path, null, auth),
  post:   (path, body, auth = false) => http('POST', path, body, auth),
  put:    (path, body, auth = true) => http('PUT', path, body, auth),
  patch:  (path, body, auth = true) => http('PATCH', path, body, auth),
  delete: (path, auth = true) => http('DELETE', path, null, auth),
};

// ─── Toast Notification System ───────────────────────────────
const Toast = {
  container: null,

  init() {
    if (this.container) return;
    this.container = document.createElement('div');
    this.container.id = 'toast-container';
    this.container.style.cssText = `
      position: fixed; top: 88px; right: 20px; z-index: 9999;
      display: flex; flex-direction: column; gap: 10px;
      max-width: 380px; pointer-events: none;
    `;
    document.body.appendChild(this.container);
  },

  show(message, type = 'info', duration = 4000) {
    this.init();
    const colors = {
      success: { bg: '#ecfdf5', border: '#6ee7b7', icon: '✅', text: '#065f46' },
      error:   { bg: '#fef2f2', border: '#fca5a5', icon: '❌', text: '#7f1d1d' },
      warning: { bg: '#fffbeb', border: '#fcd34d', icon: '⚠️', text: '#78350f' },
      info:    { bg: '#eff6ff', border: '#93c5fd', icon: 'ℹ️',  text: '#1e3a8a' },
    };
    const c = colors[type] || colors.info;

    const toast = document.createElement('div');
    toast.style.cssText = `
      background: ${c.bg}; border: 1px solid ${c.border};
      border-radius: 12px; padding: 14px 18px;
      display: flex; align-items: flex-start; gap: 10px;
      box-shadow: 0 8px 24px rgba(0,0,0,0.12);
      pointer-events: all; cursor: pointer;
      animation: slideInToast 0.35s cubic-bezier(0.34,1.56,0.64,1);
      max-width: 380px;
    `;
    toast.innerHTML = `
      <span style="font-size:1.1rem;flex-shrink:0;margin-top:1px">${c.icon}</span>
      <span style="font-size:0.88rem;color:${c.text};line-height:1.5;font-family:'DM Sans',sans-serif">${message}</span>
    `;
    toast.onclick = () => this.dismiss(toast);
    this.container.appendChild(toast);

    setTimeout(() => this.dismiss(toast), duration);
    return toast;
  },

  dismiss(toast) {
    toast.style.animation = 'slideOutToast 0.25s ease forwards';
    setTimeout(() => toast.remove(), 250);
  },

  success: (msg, dur) => Toast.show(msg, 'success', dur),
  error:   (msg, dur) => Toast.show(msg, 'error', dur),
  warning: (msg, dur) => Toast.show(msg, 'warning', dur),
  info:    (msg, dur) => Toast.show(msg, 'info', dur),
};

// Inject toast animations
const toastStyle = document.createElement('style');
toastStyle.textContent = `
  @keyframes slideInToast {
    from { opacity: 0; transform: translateX(60px) scale(0.9); }
    to   { opacity: 1; transform: translateX(0) scale(1); }
  }
  @keyframes slideOutToast {
    from { opacity: 1; transform: translateX(0); }
    to   { opacity: 0; transform: translateX(60px); }
  }
`;
document.head.appendChild(toastStyle);

// ─── Loading Spinner ──────────────────────────────────────────
const Loader = {
  show(btn, text = 'Đang xử lý...') {
    if (!btn) return;
    btn._originalHTML = btn.innerHTML;
    btn._originalDisabled = btn.disabled;
    btn.disabled = true;
    btn.innerHTML = `<span style="display:inline-flex;align-items:center;gap:8px">
      <span style="width:16px;height:16px;border:2px solid rgba(255,255,255,0.4);border-top-color:white;border-radius:50%;display:inline-block;animation:spin .7s linear infinite"></span>
      ${text}
    </span>`;
  },
  hide(btn) {
    if (!btn || !btn._originalHTML) return;
    btn.innerHTML = btn._originalHTML;
    btn.disabled = btn._originalDisabled || false;
  },
};
const spinStyle = document.createElement('style');
spinStyle.textContent = `@keyframes spin { to { transform: rotate(360deg); } }`;
document.head.appendChild(spinStyle);

// ─── Modal System ─────────────────────────────────────────────
const Modal = {
  open(id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.style.display = 'flex';
    requestAnimationFrame(() => el.classList.add('modal-visible'));
    document.body.style.overflow = 'hidden';
  },
  close(id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.remove('modal-visible');
    setTimeout(() => {
      el.style.display = 'none';
      document.body.style.overflow = '';
    }, 250);
  },
  closeAll() {
    document.querySelectorAll('.modal-overlay').forEach(el => {
      const id = el.id;
      if (id) Modal.close(id);
    });
  },
};

// ─── UI Helpers ───────────────────────────────────────────────
const UI = {
  formatCurrency(amount) {
    if (!amount && amount !== 0) return '—';
    return new Intl.NumberFormat('vi-VN', { style: 'currency', currency: 'VND' }).format(amount);
  },

  formatNumber(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
    return n?.toLocaleString('vi-VN') || '0';
  },

  formatDate(dateStr) {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleDateString('vi-VN', { day: '2-digit', month: '2-digit', year: 'numeric' });
  },

  statusBadge(status) {
    const map = {
      active:    { label: 'Đang chạy',    color: '#065f46', bg: '#d1fae5' },
      pending:   { label: 'Chờ duyệt',    color: '#92400e', bg: '#fef3c7' },
      draft:     { label: 'Bản nháp',     color: '#374151', bg: '#f3f4f6' },
      paused:    { label: 'Tạm dừng',     color: '#1e40af', bg: '#dbeafe' },
      completed: { label: 'Hoàn thành',   color: '#5b21b6', bg: '#ede9fe' },
      rejected:  { label: 'Từ chối',      color: '#7f1d1d', bg: '#fee2e2' },
    };
    const s = map[status] || { label: status, color: '#374151', bg: '#f3f4f6' };
    return `<span style="
      background:${s.bg}; color:${s.color};
      font-size:0.72rem; font-weight:700;
      padding:4px 10px; border-radius:99px;
      letter-spacing:0.02em; white-space:nowrap;
    ">${s.label}</span>`;
  },

  roleBadge(role) {
    const map = {
      admin:      { label: 'Admin',      color: '#5b21b6', bg: '#ede9fe' },
      advertiser: { label: 'Nhà QC',     color: '#1e40af', bg: '#dbeafe' },
      user:       { label: 'Người dùng', color: '#374151', bg: '#f3f4f6' },
    };
    const r = map[role] || map.user;
    return `<span style="
      background:${r.bg}; color:${r.color};
      font-size:0.72rem; font-weight:700;
      padding:3px 9px; border-radius:99px;
    ">${r.label}</span>`;
  },

  // Update navbar based on auth state
  updateNavForAuth() {
    const user = Auth.getUser();
    const ctaEl = document.querySelector('.nav-cta');
    if (!ctaEl) return;

    if (user) {
      const initials = user.fullName?.split(' ').map(w => w[0]).slice(-2).join('').toUpperCase() || '?';
      ctaEl.innerHTML = `
        <div class="user-menu-wrap" style="position:relative">
          <button class="user-avatar-btn" onclick="UI.toggleUserMenu()" style="
            display:flex; align-items:center; gap:10px;
            background: var(--blue-50); border: 1.5px solid var(--blue-100);
            padding: 8px 16px 8px 8px; border-radius: var(--radius-md);
            cursor:pointer; transition: all 0.2s; font-family:'DM Sans',sans-serif;
          " onmouseenter="this.style.borderColor='var(--blue-400)'"
             onmouseleave="this.style.borderColor='var(--blue-100)'">
            <div style="
              width:30px; height:30px;
              background:var(--gradient-blue); border-radius:50%;
              display:flex; align-items:center; justify-content:center;
              color:white; font-weight:700; font-size:0.75rem;
              box-shadow:0 2px 8px rgba(37,99,235,0.35);
            ">${initials}</div>
            <span style="font-size:0.85rem; font-weight:600; color:var(--blue-700)">${user.fullName?.split(' ').slice(-1)[0]}</span>
            <span style="color:var(--gray-400); font-size:0.7rem">▾</span>
          </button>
          <div id="userDropdown" style="
            display:none; position:absolute; top:calc(100% + 8px); right:0;
            background:white; border:1px solid var(--gray-100);
            border-radius:var(--radius-lg); padding:8px;
            box-shadow:var(--shadow-xl); min-width:200px; z-index:9999;
          ">
            <div style="padding:8px 12px 12px; border-bottom:1px solid var(--gray-100); margin-bottom:4px;">
              <div style="font-weight:700; font-size:0.9rem; color:var(--blue-900)">${user.fullName}</div>
              <div style="font-size:0.75rem; color:var(--gray-500)">${user.email}</div>
            </div>
            <a onclick="App.showDashboard()" style="display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:var(--radius-sm);color:var(--gray-700);font-size:0.85rem;cursor:pointer;text-decoration:none" onmouseenter="this.style.background='var(--blue-50)'" onmouseleave="this.style.background=''">
              📊 Dashboard của tôi
            </a>
            ${Auth.isAdmin() ? `<a onclick="App.showAdmin()" style="display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:var(--radius-sm);color:var(--gray-700);font-size:0.85rem;cursor:pointer;text-decoration:none" onmouseenter="this.style.background='var(--blue-50)'" onmouseleave="this.style.background=''">⚙️ Admin Panel</a>` : ''}
            <a onclick="App.showProfile()" style="display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:var(--radius-sm);color:var(--gray-700);font-size:0.85rem;cursor:pointer;text-decoration:none" onmouseenter="this.style.background='var(--blue-50)'" onmouseleave="this.style.background=''">
              👤 Hồ sơ cá nhân
            </a>
            <div style="border-top:1px solid var(--gray-100); margin-top:4px; padding-top:4px;">
              <a onclick="App.logout()" style="display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:var(--radius-sm);color:#dc2626;font-size:0.85rem;cursor:pointer;text-decoration:none" onmouseenter="this.style.background='#fef2f2'" onmouseleave="this.style.background=''">
                🚪 Đăng xuất
              </a>
            </div>
          </div>
        </div>
      `;
    } else {
      ctaEl.innerHTML = `
        <button class="btn-outline" onclick="Modal.open('loginModal')">Đăng nhập</button>
        <button class="btn-primary" onclick="Modal.open('registerModal')">Đăng ký miễn phí</button>
      `;
    }
  },

  toggleUserMenu() {
    const dd = document.getElementById('userDropdown');
    if (!dd) return;
    dd.style.display = dd.style.display === 'none' ? 'block' : 'none';
  },
};

// Close user dropdown on outside click
document.addEventListener('click', (e) => {
  if (!e.target.closest('.user-menu-wrap')) {
    const dd = document.getElementById('userDropdown');
    if (dd) dd.style.display = 'none';
  }
});
