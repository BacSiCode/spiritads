/* ═══════════════════════════════════════════════════════════════
   SpiritAds – app.js
   Main bootstrap: wires all JS together + existing page interactions
═══════════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {
  // ─── 1. Inject auth modals ─────────────────────────────────
  Auth.injectModals();
  CampaignForm.init();

  // ─── 2. Restore auth session ───────────────────────────────
  UI.updateNavForAuth();

  // ─── 3. Wire nav buttons ────────────────────────────────────
  Auth.wireNavButtons();

  // ─── 4. Wire contact form ───────────────────────────────────
  wireContactForm();

  // ─── 5. Load dynamic brand cards from API ───────────────────
  loadBrandCards();

  // ─── 6. Existing page interactions ─────────────────────────
  initPageInteractions();

  // ─── 7. Navbar scroll effect ────────────────────────────────
  const nav = document.getElementById('mainNav');
  window.addEventListener('scroll', () => {
    nav?.classList.toggle('scrolled', window.scrollY > 20);
  });

  // ─── 8. Scroll-triggered fade-up animations ─────────────────
  initScrollAnimations();

  // ─── 9. Active nav links ────────────────────────────────────
  initActiveNavLinks();

  // ─── 10. Filter tabs ────────────────────────────────────────
  initFilterTabs();

  // ─── 11. Dashboard nav items ────────────────────────────────
  document.querySelectorAll('.dash-nav-item').forEach(item => {
    item.addEventListener('click', function () {
      document.querySelectorAll('.dash-nav-item').forEach(i => i.classList.remove('active'));
      this.classList.add('active');
    });
  });

  // ─── 12. Animate metric bars ────────────────────────────────
  initMetricBarAnimations();
});

// ─── Load brand cards from API ───────────────────────────────
async function loadBrandCards() {
  const grid = document.querySelector('.products-grid');
  if (!grid) return;

  const res = await api.get('/brands?limit=4');
  if (!res.success || !res.data?.length) return; // keep static if API not ready

  grid.innerHTML = res.data.map(b => `
    <div class="product-card" style="animation: fadeUp 0.5s ease both">
      <div class="product-image" style="background: ${getCategoryGradient(b.category)};">
        ${b.badge ? `<span class="product-badge">${b.badge}</span>` : ''}
        ${getCategoryEmoji(b.category)}
      </div>
      <div class="product-info">
        <div class="product-brand">${b.name}</div>
        <div class="product-name" style="font-size:1rem">${b.category} • ${b.origin || 'Việt Nam'}</div>
        <div class="product-desc">${(b.description || '').slice(0, 90)}...</div>
        <div class="product-footer">
          <div class="product-rating">
            <span class="stars">${'★'.repeat(Math.round(b.rating || 4))}${'☆'.repeat(5 - Math.round(b.rating || 4))}</span>
            (${b.rating || 4.5})
          </div>
          <button class="btn-detail" onclick="showBrandDetail(${JSON.stringify(b).replace(/"/g, '&quot;')})">Xem chi tiết →</button>
        </div>
      </div>
    </div>
  `).join('');
}

function getCategoryEmoji(cat) {
  const m = { Vang:'🍷', Bia:'🍺', Whisky:'🥃', Vodka:'🍸', Brandy:'🥃', Sake:'🍶' };
  return `<span style="font-size:4rem">${m[cat] || '🍶'}</span>`;
}
function getCategoryGradient(cat) {
  const m = { Vang:'linear-gradient(135deg,#fce7f3,#fdf2f8)', Bia:'linear-gradient(135deg,#d1fae5,#ecfdf5)', Whisky:'linear-gradient(135deg,#fef3c7,#fffbeb)', Vodka:'linear-gradient(135deg,#e0e7ff,#eef2ff)', Brandy:'linear-gradient(135deg,#fde8d8,#fff7f0)' };
  return m[cat] || 'linear-gradient(135deg,#eff6ff,#f0f9ff)';
}

function showBrandDetail(brand) {
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:10001;background:rgba(10,22,40,0.6);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;padding:20px';
  overlay.innerHTML = `
    <div style="background:white;border-radius:24px;padding:36px;max-width:480px;width:100%;box-shadow:0 24px 80px rgba(10,22,40,0.3);position:relative">
      <button onclick="this.closest('div[style*=fixed]').remove()" style="position:absolute;top:16px;right:16px;width:34px;height:34px;border-radius:50%;border:none;background:var(--gray-100);cursor:pointer;font-size:1rem">✕</button>
      <div style="text-align:center;font-size:4rem;margin-bottom:16px">${getCategoryEmoji(brand.category)}</div>
      <div style="font-family:'Playfair Display',serif;font-size:1.5rem;font-weight:700;color:var(--blue-900);margin-bottom:8px">${brand.name}</div>
      <div style="margin-bottom:16px">${brand.badge ? `<span style="background:var(--gradient-blue);color:white;font-size:0.75rem;font-weight:700;padding:4px 12px;border-radius:99px">${brand.badge}</span>` : ''}</div>
      <div style="font-size:0.9rem;color:var(--gray-600);line-height:1.7;margin-bottom:20px">${brand.description}</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:24px">
        ${[['🌏 Xuất xứ', brand.origin || 'Việt Nam'], ['🍾 Loại', brand.category], ['🔢 Độ cồn', (brand.alcoholContent || '?') + '%'], ['💰 Giá', brand.price ? UI.formatCurrency(brand.price) : '—']].map(([k,v]) => `<div style="background:var(--gray-50);padding:12px;border-radius:var(--radius-md)"><div style="font-size:0.72rem;color:var(--gray-400)">${k}</div><div style="font-weight:700;font-size:0.9rem;color:var(--blue-900);margin-top:3px">${v}</div></div>`).join('')}
      </div>
      <button class="btn-primary" onclick="Modal.open('registerModal');this.closest('div[style*=fixed]').remove()" style="width:100%;padding:12px;border:none;cursor:pointer;font-size:0.95rem">📣 Quảng cáo thương hiệu này</button>
    </div>
  `;
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
  document.body.appendChild(overlay);
}

// ─── Filter tabs ──────────────────────────────────────────────
function initFilterTabs() {
  const tabs = document.querySelectorAll('.filter-tab');
  tabs.forEach(tab => {
    tab.addEventListener('click', async function () {
      tabs.forEach(t => t.classList.remove('active'));
      this.classList.add('active');
      const category = this.textContent.trim();
      const grid = document.querySelector('.products-grid');
      if (!grid) return;

      grid.style.opacity = '0.5';
      const param = category === 'Tất cả' ? '' : `&category=${encodeURIComponent(category)}`;
      const res = await api.get(`/brands?limit=4${param}`);
      grid.style.opacity = '1';

      if (res.success && res.data?.length) {
        grid.innerHTML = res.data.map(b => `
          <div class="product-card">
            <div class="product-image" style="background:${getCategoryGradient(b.category)}">
              ${b.badge ? `<span class="product-badge">${b.badge}</span>` : ''}
              ${getCategoryEmoji(b.category)}
            </div>
            <div class="product-info">
              <div class="product-brand">${b.name}</div>
              <div class="product-name" style="font-size:1rem">${b.category} • ${b.origin || 'Việt Nam'}</div>
              <div class="product-desc">${(b.description || '').slice(0, 90)}...</div>
              <div class="product-footer">
                <div class="product-rating"><span class="stars">${'★'.repeat(Math.round(b.rating || 4))}</span> (${b.rating})</div>
                <button class="btn-detail" onclick="showBrandDetail(${JSON.stringify(b).replace(/"/g, '&quot;')})">Xem chi tiết →</button>
              </div>
            </div>
          </div>
        `).join('');
      }
    });
  });
}

// ─── Scroll animations ────────────────────────────────────────
function initScrollAnimations() {
  const elements = document.querySelectorAll('.fade-up');
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) entry.target.classList.add('visible');
    });
  }, { threshold: 0.1 });
  elements.forEach(el => observer.observe(el));
}

// ─── Active nav links ─────────────────────────────────────────
function initActiveNavLinks() {
  const sections = document.querySelectorAll('section[id]');
  const navLinks = document.querySelectorAll('.nav-links a');
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        navLinks.forEach(link => {
          link.classList.toggle('active', link.getAttribute('href') === `#${entry.target.id}`);
        });
      }
    });
  }, { threshold: 0.3 });
  sections.forEach(s => observer.observe(s));
}

// ─── Metric bar animations ────────────────────────────────────
function initMetricBarAnimations() {
  const barObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.querySelectorAll('.metric-bar-fill').forEach(bar => {
          const w = bar.style.width;
          bar.style.width = '0';
          setTimeout(() => { bar.style.width = w; }, 100);
        });
      }
    });
  }, { threshold: 0.3 });
  document.querySelectorAll('.analytics-card').forEach(el => barObserver.observe(el));
}

// ─── Page interactions ────────────────────────────────────────
function initPageInteractions() {
  // CTA buttons that need auth gate
  document.querySelectorAll('.btn-ghost').forEach(btn => {
    if (btn.textContent.includes('Đăng ký quảng cáo')) {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        if (Auth.isLoggedIn() && Auth.isAdvertiser()) {
          DashboardPanel.openCreateCampaign();
        } else {
          Modal.open('registerModal');
        }
      });
    }
  });

  // Dashboard section button
  document.querySelectorAll('.dash-btn-primary').forEach(btn => {
    if (btn.textContent.includes('Tạo chiến dịch')) {
      btn.addEventListener('click', () => {
        if (!Auth.isLoggedIn()) { Modal.open('loginModal'); return; }
        DashboardPanel.openCreateCampaign();
      });
    }
  });
}

// ─── Global mobile menu ───────────────────────────────────────
function toggleMenu() {
  const menu = document.getElementById('mobileMenu');
  menu?.classList.toggle('open');
}

document.addEventListener('click', (e) => {
  const menu = document.getElementById('mobileMenu');
  if (menu?.classList.contains('open') && !menu.contains(e.target) && !e.target.closest('.hamburger')) {
    menu.classList.remove('open');
  }
});
