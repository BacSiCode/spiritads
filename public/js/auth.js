/* ═══════════════════════════════════════════════════════════════
   SpiritAds – auth.js
   Login, Register modals and handlers
═══════════════════════════════════════════════════════════════ */

// ─── Inject Modal HTML into page ─────────────────────────────
const authModalHTML = `
<!-- MODAL OVERLAY STYLES -->
<style>
.modal-overlay {
  display: none; position: fixed; inset: 0; z-index: 10000;
  background: rgba(10,22,40,0.6); backdrop-filter: blur(6px);
  align-items: center; justify-content: center; padding: 20px;
  opacity: 0; transition: opacity 0.25s ease;
}
.modal-overlay.modal-visible { opacity: 1; }
.modal-box {
  background: white; border-radius: 24px;
  padding: 40px; width: 100%; max-width: 460px;
  box-shadow: 0 24px 80px rgba(10,22,40,0.35);
  transform: translateY(20px) scale(0.97);
  transition: all 0.3s cubic-bezier(0.34,1.56,0.64,1);
  max-height: 90vh; overflow-y: auto;
}
.modal-visible .modal-box { transform: translateY(0) scale(1); }
.modal-title {
  font-family: 'Playfair Display', serif;
  font-size: 1.7rem; font-weight: 700;
  color: var(--blue-900); margin-bottom: 6px;
}
.modal-sub { font-size: 0.88rem; color: var(--gray-500); margin-bottom: 28px; }
.form-field { margin-bottom: 18px; }
.form-field label {
  display: block; font-size: 0.82rem; font-weight: 600;
  color: var(--gray-700); margin-bottom: 7px;
}
.form-field input, .form-field select {
  width: 100%; padding: 12px 16px;
  border: 1.5px solid var(--gray-200); border-radius: var(--radius-md);
  font-size: 0.9rem; color: var(--gray-900); background: white;
  transition: all 0.2s ease; outline: none;
  font-family: 'DM Sans', sans-serif;
}
.form-field input:focus, .form-field select:focus {
  border-color: var(--blue-400);
  box-shadow: 0 0 0 3px rgba(37,99,235,0.1);
}
.form-field input.error { border-color: #ef4444; }
.field-error { font-size:0.75rem; color:#ef4444; margin-top:4px; }
.modal-divider {
  text-align: center; color: var(--gray-400); font-size: 0.82rem;
  margin: 20px 0; position: relative;
}
.modal-divider::before, .modal-divider::after {
  content:''; position:absolute; top:50%; width:42%; height:1px;
  background: var(--gray-200);
}
.modal-divider::before { left:0; }
.modal-divider::after { right:0; }
.modal-close {
  position: absolute; top: 16px; right: 16px;
  width: 34px; height: 34px; border-radius: 50%;
  border: none; background: var(--gray-100);
  cursor: pointer; font-size: 1.1rem; display: flex;
  align-items: center; justify-content: center;
  transition: all 0.2s; color: var(--gray-500);
}
.modal-close:hover { background: var(--gray-200); color: var(--gray-800); }
.modal-box { position: relative; }
.password-wrap { position: relative; }
.password-wrap input { padding-right: 44px; }
.pass-toggle {
  position: absolute; right: 14px; top: 50%; transform: translateY(-50%);
  background: none; border: none; cursor: pointer; font-size: 1rem;
  color: var(--gray-400); padding: 4px; transition: color 0.2s;
}
.pass-toggle:hover { color: var(--gray-700); }
.switch-modal { text-align: center; margin-top: 20px; font-size: 0.85rem; color: var(--gray-500); }
.switch-modal a { color: var(--blue-500); font-weight: 600; cursor: pointer; text-decoration: none; }
.switch-modal a:hover { text-decoration: underline; }
.role-tabs { display: flex; gap: 8px; margin-bottom: 24px; }
.role-tab {
  flex: 1; padding: 10px; border-radius: var(--radius-md);
  border: 1.5px solid var(--gray-200); background: white;
  cursor: pointer; font-size: 0.85rem; font-weight: 600;
  color: var(--gray-500); transition: all 0.2s;
  font-family: 'DM Sans', sans-serif; text-align: center;
}
.role-tab.active {
  background: var(--blue-50); border-color: var(--blue-400);
  color: var(--blue-600);
}
</style>

<!-- LOGIN MODAL -->
<div class="modal-overlay" id="loginModal" onclick="if(event.target===this)Modal.close('loginModal')">
  <div class="modal-box">
    <button class="modal-close" onclick="Modal.close('loginModal')">✕</button>
    <div style="text-align:center; margin-bottom:24px;">
      <div style="width:52px;height:52px;background:var(--gradient-blue);border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:1.5rem;margin:0 auto 16px;box-shadow:0 8px 20px rgba(37,99,235,0.35)">🍶</div>
      <div class="modal-title">Đăng nhập</div>
      <div class="modal-sub">Chào mừng trở lại SpiritAds</div>
    </div>
    <form id="loginForm" onsubmit="Auth.handleLogin(event)">
      <div class="form-field">
        <label>Email</label>
        <input type="email" id="loginEmail" placeholder="email@congty.com" required autocomplete="email">
        <div class="field-error" id="loginEmailError"></div>
      </div>
      <div class="form-field">
        <label>Mật khẩu</label>
        <div class="password-wrap">
          <input type="password" id="loginPassword" placeholder="••••••••" required autocomplete="current-password">
          <button type="button" class="pass-toggle" onclick="Auth.togglePassword('loginPassword', this)">👁️</button>
        </div>
        <div class="field-error" id="loginPasswordError"></div>
      </div>
      <button type="submit" class="btn-primary" id="loginBtn" style="width:100%;padding:13px;font-size:0.95rem;border:none;cursor:pointer;margin-top:4px">
        Đăng nhập
      </button>
    </form>
    <div class="modal-divider">hoặc thử với tài khoản demo</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:4px">
      <button class="btn-outline" onclick="Auth.fillDemo('admin')" style="font-size:0.78rem;padding:9px 12px;cursor:pointer">⚙️ Admin demo</button>
      <button class="btn-outline" onclick="Auth.fillDemo('advertiser')" style="font-size:0.78rem;padding:9px 12px;cursor:pointer">📣 Nhà QC demo</button>
    </div>
    <div class="switch-modal">Chưa có tài khoản? <a onclick="Modal.close('loginModal');Modal.open('registerModal')">Đăng ký miễn phí</a></div>
  </div>
</div>

<!-- REGISTER MODAL -->
<div class="modal-overlay" id="registerModal" onclick="if(event.target===this)Modal.close('registerModal')">
  <div class="modal-box">
    <button class="modal-close" onclick="Modal.close('registerModal')">✕</button>
    <div style="text-align:center; margin-bottom:24px;">
      <div style="width:52px;height:52px;background:var(--gradient-blue);border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:1.5rem;margin:0 auto 16px;box-shadow:0 8px 20px rgba(37,99,235,0.35)">✨</div>
      <div class="modal-title">Tạo tài khoản</div>
      <div class="modal-sub">Bắt đầu hành trình quảng cáo của bạn</div>
    </div>

    <div class="role-tabs">
      <button type="button" class="role-tab active" id="roleTab_user" onclick="Auth.setRegisterRole('user')">👤 Người dùng</button>
      <button type="button" class="role-tab" id="roleTab_advertiser" onclick="Auth.setRegisterRole('advertiser')">🏢 Nhà quảng cáo</button>
    </div>

    <form id="registerForm" onsubmit="Auth.handleRegister(event)">
      <input type="hidden" id="registerRole" value="user">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
        <div class="form-field" style="margin-bottom:0">
          <label>Họ và tên *</label>
          <input type="text" id="regFullName" placeholder="Nguyễn Văn An" required>
        </div>
        <div class="form-field" style="margin-bottom:0">
          <label>Số điện thoại</label>
          <input type="tel" id="regPhone" placeholder="0912 345 678">
        </div>
      </div>
      <div class="form-field" style="margin-top:14px">
        <label>Email *</label>
        <input type="email" id="regEmail" placeholder="email@congty.com" required>
        <div class="field-error" id="regEmailError"></div>
      </div>
      <div class="form-field">
        <label>Mật khẩu *</label>
        <div class="password-wrap">
          <input type="password" id="regPassword" placeholder="Tối thiểu 6 ký tự" required minlength="6">
          <button type="button" class="pass-toggle" onclick="Auth.togglePassword('regPassword', this)">👁️</button>
        </div>
      </div>

      <!-- Company fields (advertiser only) -->
      <div id="companyFields" style="display:none">
        <div style="font-size:0.8rem;font-weight:700;color:var(--blue-600);margin-bottom:12px;padding:8px 12px;background:var(--blue-50);border-radius:8px">🏢 Thông tin doanh nghiệp</div>
        <div class="form-field">
          <label>Tên công ty *</label>
          <input type="text" id="regCompanyName" placeholder="Công ty TNHH ABC">
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
          <div class="form-field" style="margin-bottom:0">
            <label>Mã số thuế</label>
            <input type="text" id="regTaxCode" placeholder="0100109106">
          </div>
          <div class="form-field" style="margin-bottom:0">
            <label>Website</label>
            <input type="text" id="regWebsite" placeholder="https://company.vn">
          </div>
        </div>
      </div>

      <button type="submit" class="btn-primary" id="registerBtn" style="width:100%;padding:13px;font-size:0.95rem;border:none;cursor:pointer;margin-top:16px">
        Tạo tài khoản miễn phí
      </button>
    </form>
    <div class="switch-modal">Đã có tài khoản? <a onclick="Modal.close('registerModal');Modal.open('loginModal')">Đăng nhập</a></div>
  </div>
</div>
`;

// ─── Auth Actions ─────────────────────────────────────────────
Object.assign(Auth, {
  // Inject modals when DOM ready
  injectModals() {
    const container = document.createElement('div');
    container.innerHTML = authModalHTML;
    document.body.appendChild(container);
  },

  // Update nav links that open modals
  wireNavButtons() {
    document.querySelectorAll('[href="#contact"].btn-outline').forEach(el => {
      if (el.textContent.includes('Đăng nhập')) {
        el.removeAttribute('href');
        el.addEventListener('click', () => Modal.open('loginModal'));
      }
    });
    document.querySelectorAll('[href="#contact"].btn-primary').forEach(el => {
      if (el.textContent.includes('Đăng ký')) {
        el.removeAttribute('href');
        el.addEventListener('click', () => Modal.open('registerModal'));
      }
    });
    document.querySelectorAll('.btn-ghost').forEach(el => {
      if (el.textContent.includes('Đăng ký quảng cáo')) {
        el.removeAttribute('href');
        el.addEventListener('click', () => Modal.open('registerModal'));
      }
    });
  },

  togglePassword(inputId, btn) {
    const input = document.getElementById(inputId);
    if (!input) return;
    const isText = input.type === 'text';
    input.type = isText ? 'password' : 'text';
    btn.textContent = isText ? '👁️' : '🙈';
  },

  setRegisterRole(role) {
    document.getElementById('registerRole').value = role;
    document.querySelectorAll('.role-tab').forEach(t => t.classList.remove('active'));
    document.getElementById(`roleTab_${role}`)?.classList.add('active');
    const companyFields = document.getElementById('companyFields');
    if (companyFields) companyFields.style.display = role === 'advertiser' ? 'block' : 'none';
  },

  fillDemo(type) {
    const demos = {
      admin: { email: 'admin@spiritads.vn', password: 'admin123456' },
      advertiser: { email: 'minh@dalat.vn', password: 'password123' },
    };
    const d = demos[type];
    if (!d) return;
    const emailEl = document.getElementById('loginEmail');
    const passEl = document.getElementById('loginPassword');
    if (emailEl) emailEl.value = d.email;
    if (passEl) passEl.value = d.password;
    Toast.info('Đã điền tài khoản demo. Nhấn Đăng nhập để tiếp tục.');
  },

  async handleLogin(e) {
    e.preventDefault();
    const btn = document.getElementById('loginBtn');
    const email = document.getElementById('loginEmail')?.value?.trim();
    const password = document.getElementById('loginPassword')?.value;

    Loader.show(btn, 'Đang đăng nhập...');

    const result = await api.post('/auth/login', { email, password });

    Loader.hide(btn);

    if (result.success) {
      Auth.setSession(result.token, result.user);
      UI.updateNavForAuth();
      Modal.close('loginModal');
      Toast.success(result.message);
      setTimeout(() => App.showDashboard(), 600);
    } else {
      Toast.error(result.message || 'Đăng nhập thất bại');
    }
  },

  async handleRegister(e) {
    e.preventDefault();
    const btn = document.getElementById('registerBtn');
    const role = document.getElementById('registerRole')?.value;

    const payload = {
      fullName: document.getElementById('regFullName')?.value?.trim(),
      email: document.getElementById('regEmail')?.value?.trim(),
      password: document.getElementById('regPassword')?.value,
      phone: document.getElementById('regPhone')?.value?.trim(),
      role,
    };

    if (role === 'advertiser') {
      payload.company = {
        name: document.getElementById('regCompanyName')?.value?.trim(),
        taxCode: document.getElementById('regTaxCode')?.value?.trim(),
        website: document.getElementById('regWebsite')?.value?.trim(),
      };
    }

    Loader.show(btn, 'Đang tạo tài khoản...');
    const result = await api.post('/auth/register', payload);
    Loader.hide(btn);

    if (result.success) {
      Auth.setSession(result.token, result.user);
      UI.updateNavForAuth();
      Modal.close('registerModal');
      Toast.success(result.message);
      setTimeout(() => App.showDashboard(), 600);
    } else {
      Toast.error(result.message || 'Đăng ký thất bại');
    }
  },
});

// Wire contact form
function wireContactForm() {
  const form = document.querySelector('#contact .contact-form-card');
  if (!form) return;
  const btn = form.querySelector('.btn-primary');
  if (!btn) return;

  btn.addEventListener('click', async (e) => {
    e.preventDefault();
    const payload = {
      fullName: form.querySelector('input[placeholder*="Nguyễn"]')?.value?.trim(),
      phone: form.querySelector('input[type="tel"]')?.value?.trim(),
      email: form.querySelector('input[type="email"]')?.value?.trim(),
      company: form.querySelector('input[placeholder*="Công ty"]')?.value?.trim(),
      service: form.querySelector('select')?.value,
      message: form.querySelector('textarea')?.value?.trim(),
    };

    if (!payload.fullName || !payload.phone || !payload.email) {
      Toast.warning('Vui lòng điền đầy đủ thông tin bắt buộc');
      return;
    }

    Loader.show(btn, 'Đang gửi...');
    const result = await api.post('/contact', payload);
    Loader.hide(btn);

    if (result.success) {
      Toast.success(result.message);
      form.querySelectorAll('input, textarea, select').forEach(el => {
        if (el.tagName !== 'BUTTON') el.value = '';
      });
    } else {
      Toast.error(result.message);
    }
  });
}
