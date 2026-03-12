/* ═══════════════════════════════════════════════════════════════
   SpiritAds – dashboard.js
   User dashboard, campaign management, admin panel
═══════════════════════════════════════════════════════════════ */

// ─── App-level page controller ────────────────────────────────
const App = {
  // Show user dashboard overlay
  showDashboard() {
    if (!Auth.isLoggedIn()) { Modal.open('loginModal'); return; }
    DashboardPanel.open();
  },
  showAdmin() {
    if (!Auth.isAdmin()) { Toast.error('Bạn không có quyền truy cập Admin Panel'); return; }
    AdminPanel.open();
  },
  showProfile() {
    ProfilePanel.open();
  },
  logout() {
    Auth.clearSession();
    UI.updateNavForAuth();
    Toast.info('Đã đăng xuất. Hẹn gặp lại!');
    // Close any open panels
    document.getElementById('dashboardPanel')?.remove();
    document.getElementById('adminPanel')?.remove();
    document.getElementById('profilePanel')?.remove();
  },
};

// ─── Reusable Panel builder ───────────────────────────────────
function buildPanel(id, content) {
  document.getElementById(id)?.remove();
  const panel = document.createElement('div');
  panel.id = id;
  panel.style.cssText = `
    position:fixed; inset:0; z-index:9000;
    background:rgba(10,22,40,0.55); backdrop-filter:blur(4px);
    display:flex; align-items:flex-end; justify-content:flex-end;
    padding:16px;
  `;
  panel.innerHTML = content;
  document.body.appendChild(panel);
  document.body.style.overflow = 'hidden';

  // Close on backdrop
  panel.addEventListener('click', (e) => {
    if (e.target === panel) {
      panel.remove();
      document.body.style.overflow = '';
    }
  });

  requestAnimationFrame(() => {
    const inner = panel.querySelector('.panel-inner');
    if (inner) { inner.style.transform = 'translateX(0)'; inner.style.opacity = '1'; }
  });

  return panel;
}

// ─── Dashboard Panel ──────────────────────────────────────────
const DashboardPanel = {
  async open() {
    const user = Auth.getUser();

    buildPanel('dashboardPanel', `
      <style>
        .panel-inner { transform:translateX(60px); opacity:0; transition:all 0.35s cubic-bezier(0.34,1.56,0.64,1); }
        .dash-panel-tab { padding:10px 18px; border-radius:var(--radius-md); cursor:pointer; font-size:0.88rem; font-weight:600; border:none; background:transparent; color:var(--gray-500); transition:all 0.2s; font-family:'DM Sans',sans-serif; }
        .dash-panel-tab.active { background:var(--blue-50); color:var(--blue-500); }
        .dash-panel-tab:hover:not(.active) { background:var(--gray-100); }
        table { width:100%; border-collapse:collapse; }
        th { font-size:0.75rem; font-weight:700; color:var(--gray-500); padding:10px 14px; text-align:left; background:var(--gray-50); border-bottom:1px solid var(--gray-200); }
        td { font-size:0.85rem; color:var(--gray-700); padding:12px 14px; border-bottom:1px solid var(--gray-100); }
        tr:hover td { background:var(--blue-50); }
        .empty-state { text-align:center; padding:40px 20px; color:var(--gray-400); }
        .empty-state .empty-icon { font-size:3rem; margin-bottom:12px; }
      </style>
      <div class="panel-inner" style="
        background:white; border-radius:24px; width:100%; max-width:900px;
        height:calc(100vh - 32px); display:flex; flex-direction:column;
        box-shadow:0 24px 80px rgba(10,22,40,0.3); overflow:hidden;
      ">
        <!-- Header -->
        <div style="padding:24px 28px; border-bottom:1px solid var(--gray-100); display:flex; justify-content:space-between; align-items:center; flex-shrink:0;">
          <div>
            <div style="font-family:'Playfair Display',serif;font-size:1.4rem;font-weight:700;color:var(--blue-900)">Dashboard</div>
            <div style="font-size:0.82rem;color:var(--gray-500);margin-top:2px">Xin chào, ${user?.fullName} 👋</div>
          </div>
          <div style="display:flex;gap:10px;align-items:center">
            ${Auth.isAdvertiser() ? `<button class="btn-primary" onclick="DashboardPanel.openCreateCampaign()" style="font-size:0.84rem;padding:9px 18px;border:none;cursor:pointer">+ Tạo chiến dịch</button>` : ''}
            <button onclick="document.getElementById('dashboardPanel').remove();document.body.style.overflow=''" style="width:36px;height:36px;border-radius:50%;border:1.5px solid var(--gray-200);background:white;cursor:pointer;font-size:1rem;display:flex;align-items:center;justify-content:center;">✕</button>
          </div>
        </div>
        <!-- Tabs -->
        <div style="padding:0 28px;border-bottom:1px solid var(--gray-100);display:flex;gap:4px;flex-shrink:0;padding-top:8px">
          <button class="dash-panel-tab active" onclick="DashboardPanel.switchTab('overview', this)">📊 Tổng quan</button>
          <button class="dash-panel-tab" onclick="DashboardPanel.switchTab('campaigns', this)">📣 Chiến dịch</button>
          ${Auth.isAdmin() ? '<button class="dash-panel-tab" onclick="DashboardPanel.switchTab(\'users\', this)">👥 Người dùng</button>' : ''}
        </div>
        <!-- Content -->
        <div id="dashPanelContent" style="flex:1;overflow-y:auto;padding:28px;">
          <div style="text-align:center;padding:40px"><div style="display:inline-block;width:28px;height:28px;border:3px solid var(--blue-100);border-top-color:var(--blue-500);border-radius:50%;animation:spin .7s linear infinite"></div></div>
        </div>
      </div>
    `);

    await this.loadTab('overview');
  },

  async switchTab(tab, btn) {
    document.querySelectorAll('.dash-panel-tab').forEach(t => t.classList.remove('active'));
    btn?.classList.add('active');
    await this.loadTab(tab);
  },

  async loadTab(tab) {
    const content = document.getElementById('dashPanelContent');
    if (!content) return;
    content.innerHTML = `<div style="text-align:center;padding:40px"><div style="display:inline-block;width:28px;height:28px;border:3px solid var(--blue-100);border-top-color:var(--blue-500);border-radius:50%;animation:spin .7s linear infinite"></div></div>`;

    if (tab === 'overview') {
      const res = await api.get('/campaigns/my-stats', true);
      if (res.success) content.innerHTML = this.renderOverview(res.stats);
      else content.innerHTML = `<div class="empty-state"><div class="empty-icon">⚠️</div>Lỗi tải dữ liệu: ${res.message}</div>`;

    } else if (tab === 'campaigns') {
      const res = await api.get('/campaigns?limit=50', true);
      if (res.success) content.innerHTML = this.renderCampaigns(res.data, res.pagination);
      else content.innerHTML = `<div class="empty-state"><div class="empty-icon">⚠️</div>${res.message}</div>`;

    } else if (tab === 'users') {
      const res = await api.get('/admin/users?limit=30', true);
      if (res.success) content.innerHTML = this.renderUsers(res.data, res.pagination);
      else content.innerHTML = `<div class="empty-state"><div class="empty-icon">⚠️</div>${res.message}</div>`;
    }
  },

  renderOverview(stats) {
    return `
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:16px;margin-bottom:28px">
        ${[
          { icon:'📣', label:'Tổng chiến dịch', value: stats.total, color:'var(--blue-500)' },
          { icon:'🟢', label:'Đang chạy', value: stats.active, color:'#10b981' },
          { icon:'⏳', label:'Chờ duyệt', value: stats.pending, color:'#f59e0b' },
          { icon:'👁️', label:'Lượt hiển thị', value: UI.formatNumber(stats.totalImpressions), color:'var(--blue-400)' },
          { icon:'👆', label:'Lượt nhấp', value: UI.formatNumber(stats.totalClicks), color:'#8b5cf6' },
          { icon:'💰', label:'Đã chi', value: UI.formatCurrency(stats.totalSpent), color:'#ef4444' },
        ].map(k => `
          <div style="background:var(--gray-50);border:1px solid var(--gray-100);border-radius:var(--radius-lg);padding:20px;transition:all 0.2s" onmouseenter="this.style.boxShadow='var(--shadow-md)'" onmouseleave="this.style.boxShadow=''">
            <div style="font-size:1.5rem;margin-bottom:8px">${k.icon}</div>
            <div style="font-size:1.4rem;font-weight:800;color:${k.color};line-height:1">${k.value}</div>
            <div style="font-size:0.75rem;color:var(--gray-500);margin-top:4px">${k.label}</div>
          </div>
        `).join('')}
      </div>
      <div style="background:var(--blue-50);border:1px solid var(--blue-100);border-radius:var(--radius-lg);padding:24px">
        <div style="font-weight:700;color:var(--blue-900);margin-bottom:16px;font-size:1rem">📈 ROI trung bình: <span style="color:var(--blue-500)">${stats.avgROI}%</span></div>
        <div style="display:flex;align-items:flex-end;gap:6px;height:80px">
          ${Array.from({length: 7}, (_, i) => {
            const h = 20 + Math.random() * 80;
            return `<div style="flex:1;border-radius:4px 4px 0 0;background:var(--gradient-blue);height:${h}%;opacity:${0.5 + i*0.07};transition:opacity 0.2s" onmouseenter="this.style.opacity=1" onmouseleave="this.style.opacity=${0.5+i*0.07}"></div>`;
          }).join('')}
        </div>
        <div style="display:flex;justify-content:space-between;font-size:0.7rem;color:var(--gray-400);margin-top:6px">
          ${['T9','T10','T11','T12','T1','T2','T3'].map(m => `<span>${m}</span>`).join('')}
        </div>
      </div>
    `;
  },

  renderCampaigns(campaigns, pagination) {
    if (!campaigns?.length) {
      return `<div class="empty-state"><div class="empty-icon">📣</div><div style="font-size:1rem;font-weight:600;color:var(--gray-600);margin-bottom:8px">Chưa có chiến dịch nào</div><div style="font-size:0.85rem">Hãy tạo chiến dịch đầu tiên của bạn</div>${Auth.isAdvertiser() ? `<button class="btn-primary" style="margin-top:16px;border:none;cursor:pointer;padding:10px 24px" onclick="DashboardPanel.openCreateCampaign()">+ Tạo chiến dịch</button>` : ''}</div>`;
    }
    return `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
        <div style="font-size:0.88rem;color:var(--gray-500)">Tổng cộng <strong>${pagination?.total || campaigns.length}</strong> chiến dịch</div>
      </div>
      <div style="overflow-x:auto;border-radius:var(--radius-lg);border:1px solid var(--gray-200)">
        <table>
          <thead><tr>
            <th>Tên chiến dịch</th>
            <th>Thương hiệu</th>
            <th>Trạng thái</th>
            <th>Ngân sách</th>
            <th>Hiển thị</th>
            <th>Click</th>
            <th>Thao tác</th>
          </tr></thead>
          <tbody>
            ${campaigns.map(c => `
              <tr>
                <td><div style="font-weight:600;color:var(--blue-900);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${c.name}</div><div style="font-size:0.72rem;color:var(--gray-400)">${UI.formatDate(c.startDate)} – ${UI.formatDate(c.endDate)}</div></td>
                <td style="font-size:0.85rem">${c.brand}</td>
                <td>${UI.statusBadge(c.status)}</td>
                <td style="font-size:0.82rem">${UI.formatCurrency(c.budget?.total)}</td>
                <td style="font-size:0.82rem">${UI.formatNumber(c.stats?.impressions)}</td>
                <td style="font-size:0.82rem">${UI.formatNumber(c.stats?.clicks)}</td>
                <td>
                  <div style="display:flex;gap:6px">
                    <button onclick="DashboardPanel.viewCampaign('${c._id}')" style="padding:5px 10px;border-radius:6px;border:1.5px solid var(--blue-200);background:var(--blue-50);color:var(--blue-600);font-size:0.75rem;cursor:pointer;font-family:'DM Sans',sans-serif">Xem</button>
                    ${(c.status === 'draft' || c.status === 'paused') ? `<button onclick="DashboardPanel.deleteCampaign('${c._id}','${c.name}')" style="padding:5px 10px;border-radius:6px;border:1.5px solid #fca5a5;background:#fef2f2;color:#dc2626;font-size:0.75rem;cursor:pointer;font-family:'DM Sans',sans-serif">Xóa</button>` : ''}
                    ${Auth.isAdmin() && c.status === 'pending' ? `<button onclick="DashboardPanel.approveCampaign('${c._id}')" style="padding:5px 10px;border-radius:6px;border:1.5px solid #6ee7b7;background:#ecfdf5;color:#065f46;font-size:0.75rem;cursor:pointer;font-family:'DM Sans',sans-serif">✓ Duyệt</button>` : ''}
                  </div>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  },

  renderUsers(users) {
    if (!users?.length) return '<div class="empty-state"><div class="empty-icon">👥</div>Không có người dùng</div>';
    return `
      <div style="overflow-x:auto;border-radius:var(--radius-lg);border:1px solid var(--gray-200)">
        <table>
          <thead><tr><th>Người dùng</th><th>Role</th><th>Trạng thái</th><th>Ngày tạo</th><th>Thao tác</th></tr></thead>
          <tbody>
            ${users.map(u => `
              <tr>
                <td>
                  <div style="display:flex;align-items:center;gap:10px">
                    <div style="width:32px;height:32px;border-radius:50%;background:var(--gradient-blue);display:flex;align-items:center;justify-content:center;color:white;font-weight:700;font-size:0.75rem;flex-shrink:0">${u.fullName?.split(' ').map(w=>w[0]).slice(-2).join('').toUpperCase()}</div>
                    <div><div style="font-weight:600;font-size:0.88rem">${u.fullName}</div><div style="font-size:0.75rem;color:var(--gray-400)">${u.email}</div></div>
                  </div>
                </td>
                <td>${UI.roleBadge(u.role)}</td>
                <td><span style="font-size:0.75rem;font-weight:600;color:${u.isActive ? '#065f46' : '#7f1d1d'};background:${u.isActive ? '#d1fae5' : '#fee2e2'};padding:3px 9px;border-radius:99px">${u.isActive ? '● Hoạt động' : '● Vô hiệu'}</span></td>
                <td style="font-size:0.82rem;color:var(--gray-500)">${UI.formatDate(u.createdAt)}</td>
                <td>
                  <button onclick="DashboardPanel.toggleUserStatus('${u._id}', ${!u.isActive})" style="padding:5px 10px;border-radius:6px;border:1.5px solid var(--gray-200);background:var(--gray-50);color:var(--gray-600);font-size:0.75rem;cursor:pointer;font-family:'DM Sans',sans-serif">
                    ${u.isActive ? 'Vô hiệu hóa' : 'Kích hoạt'}
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  },

  openCreateCampaign() {
    Modal.open('createCampaignModal');
    CampaignForm.init();
  },

  async viewCampaign(id) {
    const res = await api.get(`/campaigns/${id}`, true);
    if (!res.success) return Toast.error(res.message);
    const c = res.data;
    const info = [
      ['Thương hiệu', c.brand],
      ['Loại', c.productType],
      ['Ngân sách', UI.formatCurrency(c.budget?.total)],
      ['Đã chi', UI.formatCurrency(c.budget?.spent)],
      ['Bắt đầu', UI.formatDate(c.startDate)],
      ['Kết thúc', UI.formatDate(c.endDate)],
      ['Hiển thị', UI.formatNumber(c.stats?.impressions)],
      ['Click', UI.formatNumber(c.stats?.clicks)],
      ['CTR', (c.stats?.ctr || 0) + '%'],
      ['ROI', (c.stats?.roi || 0) + '%'],
    ];
    const content = `
      <div style="max-width:520px;width:100%;background:white;border-radius:24px;padding:32px;position:relative;max-height:85vh;overflow-y:auto">
        <button onclick="this.closest('[id]').remove();document.body.style.overflow=''" style="position:absolute;top:16px;right:16px;width:34px;height:34px;border-radius:50%;border:none;background:var(--gray-100);cursor:pointer;font-size:1rem">✕</button>
        <div style="font-family:'Playfair Display',serif;font-size:1.3rem;font-weight:700;color:var(--blue-900);margin-bottom:6px">${c.name}</div>
        <div style="margin-bottom:16px">${UI.statusBadge(c.status)}</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px">
          ${info.map(([label, val]) => `<div style="background:var(--gray-50);padding:12px;border-radius:var(--radius-md)"><div style="font-size:0.72rem;color:var(--gray-400);margin-bottom:3px">${label}</div><div style="font-weight:700;font-size:0.9rem;color:var(--blue-900)">${val || '—'}</div></div>`).join('')}
        </div>
        ${c.description ? `<div style="background:var(--blue-50);border:1px solid var(--blue-100);border-radius:var(--radius-md);padding:14px;font-size:0.85rem;color:var(--gray-700)">${c.description}</div>` : ''}
        ${Auth.isAdmin() && c.status === 'pending' ? `
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:20px">
            <button onclick="DashboardPanel.approveCampaign('${c._id}')" style="padding:11px;border-radius:var(--radius-md);border:none;background:#10b981;color:white;font-weight:700;cursor:pointer;font-family:'DM Sans',sans-serif">✓ Phê duyệt</button>
            <button onclick="DashboardPanel.rejectCampaign('${c._id}')" style="padding:11px;border-radius:var(--radius-md);border:none;background:#ef4444;color:white;font-weight:700;cursor:pointer;font-family:'DM Sans',sans-serif">✗ Từ chối</button>
          </div>` : ''}
      </div>
    `;
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;inset:0;z-index:10001;background:rgba(10,22,40,0.6);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;padding:20px';
    overlay.innerHTML = content;
    overlay.id = `campaignDetail_${id}`;
    overlay.onclick = (e) => { if (e.target === overlay) { overlay.remove(); document.body.style.overflow = ''; } };
    document.body.appendChild(overlay);
  },

  async approveCampaign(id) {
    const res = await api.patch(`/campaigns/${id}/status`, { status: 'active' }, true);
    if (res.success) {
      Toast.success('Chiến dịch đã được phê duyệt');
      document.getElementById(`campaignDetail_${id}`)?.remove();
      this.loadTab('campaigns');
    } else Toast.error(res.message);
  },

  async rejectCampaign(id) {
    const reason = prompt('Lý do từ chối (không bắt buộc):') ?? '';
    const res = await api.patch(`/campaigns/${id}/status`, { status: 'rejected', rejectionReason: reason }, true);
    if (res.success) {
      Toast.info('Đã từ chối chiến dịch');
      document.getElementById(`campaignDetail_${id}`)?.remove();
      this.loadTab('campaigns');
    } else Toast.error(res.message);
  },

  async deleteCampaign(id, name) {
    if (!confirm(`Xác nhận xóa chiến dịch "${name}"?`)) return;
    const res = await api.delete(`/campaigns/${id}`, true);
    if (res.success) { Toast.success('Đã xóa chiến dịch'); this.loadTab('campaigns'); }
    else Toast.error(res.message);
  },

  async toggleUserStatus(id, isActive) {
    const res = await api.patch(`/admin/users/${id}`, { isActive }, true);
    if (res.success) { Toast.success('Cập nhật thành công'); this.loadTab('users'); }
    else Toast.error(res.message);
  },
};

// ─── Campaign Create Form ─────────────────────────────────────
const CampaignForm = {
  init() {
    const existing = document.getElementById('createCampaignModal');
    if (existing) return;

    const today = new Date().toISOString().split('T')[0];
    const monthLater = new Date(Date.now() + 30 * 86400000).toISOString().split('T')[0];

    const html = `
      <div class="modal-overlay" id="createCampaignModal" onclick="if(event.target===this)Modal.close('createCampaignModal')" style="display:none">
        <div class="modal-box" style="max-width:600px">
          <button class="modal-close" onclick="Modal.close('createCampaignModal')">✕</button>
          <div style="font-family:'Playfair Display',serif;font-size:1.5rem;font-weight:700;color:var(--blue-900);margin-bottom:6px">Tạo chiến dịch mới</div>
          <div style="font-size:0.85rem;color:var(--gray-500);margin-bottom:24px">Điền thông tin để tạo chiến dịch quảng cáo</div>
          <form id="createCampaignForm" onsubmit="CampaignForm.submit(event)">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
              <div class="form-field" style="grid-column:1/-1">
                <label>Tên chiến dịch *</label>
                <input type="text" id="cf_name" placeholder="VD: Chiến dịch Tết 2026 – Vang Đà Lạt" required>
              </div>
              <div class="form-field">
                <label>Thương hiệu *</label>
                <input type="text" id="cf_brand" placeholder="VD: Dalat Winery" required>
              </div>
              <div class="form-field">
                <label>Loại sản phẩm</label>
                <select id="cf_productType">
                  <option value="Vang">Vang</option><option value="Bia">Bia</option>
                  <option value="Whisky">Whisky</option><option value="Vodka">Vodka</option>
                  <option value="Brandy">Brandy</option><option value="Khác">Khác</option>
                </select>
              </div>
              <div class="form-field">
                <label>Loại chiến dịch</label>
                <select id="cf_type">
                  <option value="digital">Quảng cáo số</option>
                  <option value="product">Quảng cáo sản phẩm</option>
                  <option value="brand">Xây dựng thương hiệu</option>
                  <option value="marketing">Marketing tổng thể</option>
                </select>
              </div>
              <div class="form-field">
                <label>Ngân sách tổng (VNĐ) *</label>
                <input type="number" id="cf_budget" placeholder="10000000" min="100000" required>
              </div>
              <div class="form-field">
                <label>Ngày bắt đầu *</label>
                <input type="date" id="cf_startDate" value="${today}" required>
              </div>
              <div class="form-field" style="grid-column:1/-1">
                <label>Ngày kết thúc *</label>
                <input type="date" id="cf_endDate" value="${monthLater}" required>
              </div>
              <div class="form-field" style="grid-column:1/-1">
                <label>Kênh quảng cáo</label>
                <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:6px" id="channelCheckboxes">
                  ${['facebook','instagram','google','tiktok','youtube','display'].map(ch => `
                    <label style="display:flex;align-items:center;gap:6px;padding:7px 14px;border:1.5px solid var(--gray-200);border-radius:99px;cursor:pointer;font-size:0.82rem;font-weight:500;transition:all 0.2s" class="channel-chip">
                      <input type="checkbox" name="channels" value="${ch}" style="display:none">
                      <span>${{facebook:'📘',instagram:'📸',google:'🔍',tiktok:'🎵',youtube:'▶️',display:'🖥️'}[ch]} ${ch.charAt(0).toUpperCase()+ch.slice(1)}</span>
                    </label>
                  `).join('')}
                </div>
              </div>
              <div class="form-field" style="grid-column:1/-1">
                <label>Mô tả chiến dịch</label>
                <textarea id="cf_description" placeholder="Mục tiêu và mô tả ngắn về chiến dịch..." style="width:100%;padding:12px 16px;border:1.5px solid var(--gray-200);border-radius:var(--radius-md);font-size:0.9rem;font-family:'DM Sans',sans-serif;resize:vertical;min-height:80px;outline:none;transition:border-color 0.2s" onfocus="this.style.borderColor='var(--blue-400)'" onblur="this.style.borderColor='var(--gray-200)'"></textarea>
              </div>
            </div>
            <button type="submit" class="btn-primary" id="createCampaignBtn" style="width:100%;padding:13px;font-size:0.95rem;border:none;cursor:pointer;margin-top:8px">🚀 Tạo chiến dịch</button>
          </form>
        </div>
      </div>
    `;

    const el = document.createElement('div');
    el.innerHTML = html;
    document.body.appendChild(el);

    // Channel chip toggle
    document.querySelectorAll('.channel-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        const cb = chip.querySelector('input[type=checkbox]');
        cb.checked = !cb.checked;
        chip.style.borderColor = cb.checked ? 'var(--blue-400)' : 'var(--gray-200)';
        chip.style.background = cb.checked ? 'var(--blue-50)' : '';
        chip.style.color = cb.checked ? 'var(--blue-600)' : '';
      });
    });
  },

  async submit(e) {
    e.preventDefault();
    const btn = document.getElementById('createCampaignBtn');
    const channels = [...document.querySelectorAll('input[name=channels]:checked')].map(i => i.value);

    const payload = {
      name: document.getElementById('cf_name').value.trim(),
      brand: document.getElementById('cf_brand').value.trim(),
      productType: document.getElementById('cf_productType').value,
      type: document.getElementById('cf_type').value,
      budget: { total: parseInt(document.getElementById('cf_budget').value) },
      startDate: document.getElementById('cf_startDate').value,
      endDate: document.getElementById('cf_endDate').value,
      description: document.getElementById('cf_description').value.trim(),
      channels,
    };

    Loader.show(btn, 'Đang tạo...');
    const res = await api.post('/campaigns', payload, true);
    Loader.hide(btn);

    if (res.success) {
      Toast.success(res.message);
      Modal.close('createCampaignModal');
      document.getElementById('dashboardPanel')?.remove();
      setTimeout(() => DashboardPanel.open(), 300);
    } else {
      Toast.error(res.message);
    }
  },
};

// ─── Profile Panel ────────────────────────────────────────────
const ProfilePanel = {
  async open() {
    const res = await api.get('/auth/me', true);
    if (!res.success) { Toast.error(res.message); return; }
    const u = res.user;

    buildPanel('profilePanel', `
      <style>.profile-panel-inner{transform:translateX(60px);opacity:0;transition:all 0.35s cubic-bezier(0.34,1.56,0.64,1)}</style>
      <div class="panel-inner profile-panel-inner" style="background:white;border-radius:24px;width:100%;max-width:500px;height:calc(100vh - 32px);display:flex;flex-direction:column;box-shadow:0 24px 80px rgba(10,22,40,0.3);overflow:hidden">
        <div style="padding:24px 28px;border-bottom:1px solid var(--gray-100);display:flex;justify-content:space-between;align-items:center">
          <div style="font-family:'Playfair Display',serif;font-size:1.4rem;font-weight:700;color:var(--blue-900)">Hồ sơ cá nhân</div>
          <button onclick="document.getElementById('profilePanel').remove();document.body.style.overflow=''" style="width:36px;height:36px;border-radius:50%;border:1.5px solid var(--gray-200);background:white;cursor:pointer;font-size:1rem">✕</button>
        </div>
        <div style="flex:1;overflow-y:auto;padding:28px">
          <!-- Avatar -->
          <div style="text-align:center;margin-bottom:28px">
            <div style="width:72px;height:72px;border-radius:50%;background:var(--gradient-blue);display:flex;align-items:center;justify-content:center;color:white;font-weight:700;font-size:1.5rem;margin:0 auto 12px;box-shadow:0 8px 24px rgba(37,99,235,0.35)">${u.fullName?.split(' ').map(w=>w[0]).slice(-2).join('').toUpperCase()}</div>
            <div style="font-weight:700;font-size:1.1rem;color:var(--blue-900)">${u.fullName}</div>
            <div style="font-size:0.82rem;color:var(--gray-500);margin-top:4px">${u.email}</div>
            <div style="margin-top:8px">${UI.roleBadge(u.role)}</div>
          </div>

          <!-- Edit form -->
          <form onsubmit="ProfilePanel.save(event)">
            <div class="form-field"><label>Họ và tên</label><input type="text" id="prof_name" value="${u.fullName}" required></div>
            <div class="form-field"><label>Số điện thoại</label><input type="tel" id="prof_phone" value="${u.phone || ''}"></div>
            ${u.role === 'advertiser' ? `
              <div style="font-size:0.8rem;font-weight:700;color:var(--blue-600);margin-bottom:12px;padding:8px 12px;background:var(--blue-50);border-radius:8px">🏢 Thông tin doanh nghiệp</div>
              <div class="form-field"><label>Tên công ty</label><input type="text" id="prof_company" value="${u.company?.name || ''}"></div>
              <div class="form-field"><label>Mã số thuế</label><input type="text" id="prof_tax" value="${u.company?.taxCode || ''}"></div>
              <div class="form-field"><label>Địa chỉ</label><input type="text" id="prof_addr" value="${u.company?.address || ''}"></div>
            ` : ''}
            <button type="submit" class="btn-primary" id="saveProfileBtn" style="width:100%;padding:12px;border:none;cursor:pointer">Lưu thay đổi</button>
          </form>

          <!-- Change password -->
          <div style="margin-top:24px;padding-top:24px;border-top:1px solid var(--gray-100)">
            <div style="font-weight:700;font-size:0.95rem;color:var(--blue-900);margin-bottom:16px">🔒 Đổi mật khẩu</div>
            <form onsubmit="ProfilePanel.changePassword(event)">
              <div class="form-field"><label>Mật khẩu hiện tại</label><div class="password-wrap"><input type="password" id="prof_curPass" placeholder="••••••••"><button type="button" class="pass-toggle" onclick="Auth.togglePassword('prof_curPass',this)">👁️</button></div></div>
              <div class="form-field"><label>Mật khẩu mới</label><div class="password-wrap"><input type="password" id="prof_newPass" placeholder="Tối thiểu 6 ký tự" minlength="6"><button type="button" class="pass-toggle" onclick="Auth.togglePassword('prof_newPass',this)">👁️</button></div></div>
              <button type="submit" class="btn-outline" id="changePassBtn" style="width:100%;padding:11px;cursor:pointer;font-family:'DM Sans',sans-serif">Đổi mật khẩu</button>
            </form>
          </div>
        </div>
      </div>
    `);
  },

  async save(e) {
    e.preventDefault();
    const btn = document.getElementById('saveProfileBtn');
    const payload = {
      fullName: document.getElementById('prof_name')?.value.trim(),
      phone: document.getElementById('prof_phone')?.value.trim(),
    };
    const companyName = document.getElementById('prof_company');
    if (companyName) {
      payload.company = {
        name: companyName.value.trim(),
        taxCode: document.getElementById('prof_tax')?.value.trim(),
        address: document.getElementById('prof_addr')?.value.trim(),
      };
    }
    Loader.show(btn, 'Đang lưu...');
    const res = await api.put('/auth/profile', payload, true);
    Loader.hide(btn);
    if (res.success) {
      Auth.setSession(Auth.getToken(), res.user);
      UI.updateNavForAuth();
      Toast.success(res.message);
    } else Toast.error(res.message);
  },

  async changePassword(e) {
    e.preventDefault();
    const btn = document.getElementById('changePassBtn');
    const payload = {
      currentPassword: document.getElementById('prof_curPass')?.value,
      newPassword: document.getElementById('prof_newPass')?.value,
    };
    Loader.show(btn, 'Đang xử lý...');
    const res = await api.put('/auth/change-password', payload, true);
    Loader.hide(btn);
    if (res.success) {
      Toast.success(res.message);
      document.getElementById('prof_curPass').value = '';
      document.getElementById('prof_newPass').value = '';
    } else Toast.error(res.message);
  },
};

// ─── Admin Panel (quick overview) ─────────────────────────────
const AdminPanel = {
  async open() {
    if (!Auth.isAdmin()) return Toast.error('Không có quyền truy cập');

    buildPanel('adminPanel', `
      <style>.adm-panel-inner{transform:translateX(60px);opacity:0;transition:all 0.35s cubic-bezier(0.34,1.56,0.64,1)}</style>
      <div class="panel-inner adm-panel-inner" style="background:white;border-radius:24px;width:100%;max-width:1000px;height:calc(100vh - 32px);display:flex;flex-direction:column;box-shadow:0 24px 80px rgba(10,22,40,0.3);overflow:hidden">
        <div style="padding:24px 28px;border-bottom:1px solid var(--gray-100);display:flex;justify-content:space-between;align-items:center">
          <div>
            <div style="font-family:'Playfair Display',serif;font-size:1.4rem;font-weight:700;color:var(--blue-900)">⚙️ Admin Panel</div>
            <div style="font-size:0.82rem;color:var(--gray-500);margin-top:2px">Quản lý hệ thống SpiritAds</div>
          </div>
          <button onclick="document.getElementById('adminPanel').remove();document.body.style.overflow=''" style="width:36px;height:36px;border-radius:50%;border:1.5px solid var(--gray-200);background:white;cursor:pointer;font-size:1rem">✕</button>
        </div>
        <div id="adminContent" style="flex:1;overflow-y:auto;padding:28px">
          <div style="text-align:center;padding:40px"><div style="display:inline-block;width:28px;height:28px;border:3px solid var(--blue-100);border-top-color:var(--blue-500);border-radius:50%;animation:spin .7s linear infinite"></div></div>
        </div>
      </div>
    `);

    const res = await api.get('/admin/overview', true);
    const content = document.getElementById('adminContent');
    if (!content) return;

    if (!res.success) { content.innerHTML = `<div style="text-align:center;padding:40px;color:#ef4444">Lỗi: ${res.message}</div>`; return; }

    const d = res.data;
    content.innerHTML = `
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:32px">
        ${[
          { icon:'👥', label:'Tổng người dùng', value: d.users.total, sub: `+${d.users.newToday} hôm nay`, color:'var(--blue-500)' },
          { icon:'📣', label:'Tổng chiến dịch', value: d.campaigns.total, sub: `${d.campaigns.active} đang chạy`, color:'#10b981' },
          { icon:'⏳', label:'Chờ phê duyệt', value: d.campaigns.pending, sub: 'Cần xử lý', color:'#f59e0b' },
          { icon:'📝', label:'Yêu cầu liên hệ', value: d.contacts.total, sub: `+${d.contacts.newToday} hôm nay`, color:'#8b5cf6' },
          { icon:'🏷️', label:'Thương hiệu', value: d.brands.total, sub: 'Đang hiển thị', color:'#ec4899' },
          { icon:'💰', label:'Tổng doanh thu', value: UI.formatCurrency(d.revenue.total), sub: 'Từ chiến dịch', color:'#ef4444' },
        ].map(k => `
          <div style="background:var(--gray-50);border:1px solid var(--gray-100);border-radius:var(--radius-lg);padding:20px">
            <div style="font-size:1.5rem;margin-bottom:8px">${k.icon}</div>
            <div style="font-size:1.4rem;font-weight:800;color:${k.color};line-height:1">${k.value}</div>
            <div style="font-size:0.72rem;color:var(--gray-400);margin-top:6px">${k.sub}</div>
            <div style="font-size:0.75rem;color:var(--gray-500);margin-top:2px;font-weight:600">${k.label}</div>
          </div>
        `).join('')}
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
        <div style="background:white;border:1px solid var(--gray-100);border-radius:var(--radius-lg);padding:24px">
          <div style="font-weight:700;color:var(--blue-900);margin-bottom:16px">📊 Phân bổ chiến dịch</div>
          ${d.campaigns.byStatus.map(s => `
            <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--gray-100)">
              <span style="font-size:0.85rem">${UI.statusBadge(s._id)}</span>
              <span style="font-weight:700;color:var(--blue-700)">${s.count}</span>
            </div>
          `).join('')}
        </div>
        <div style="background:white;border:1px solid var(--gray-100);border-radius:var(--radius-lg);padding:24px">
          <div style="font-weight:700;color:var(--blue-900);margin-bottom:16px">👥 Người dùng theo role</div>
          ${d.users.byRole.map(r => `
            <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--gray-100)">
              <span style="font-size:0.85rem">${UI.roleBadge(r._id)}</span>
              <span style="font-weight:700;color:var(--blue-700)">${r.count}</span>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  },
};
