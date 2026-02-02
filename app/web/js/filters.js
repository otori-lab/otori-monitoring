/**
 * OTORI Dashboard - Filter System
 * Session filtering and quick filters
 */

// Filter state
let allSessions = [];
let filteredSessions = [];
let availableCountries = [];
let activeFilters = {
  ip: '',
  username: '',
  countries: [],
  dangerLevels: ['critical', 'high', 'medium', 'low', 'minimal'],
  attackerTypes: ['bot', 'human', 'hybrid', 'unknown'],
  scoreMin: 0,
  scoreMax: 100,
  cmdMin: null,
  cmdMax: null,
  honeypotType: 'all',
  hasPersistence: false,
  hasCredentialAccess: false
};

function initFilters() {
  const saved = localStorage.getItem('otori-session-filters');
  if (saved) {
    try {
      const parsed = JSON.parse(saved);
      activeFilters = { ...activeFilters, ...parsed };
      restoreFilterUI();
    } catch (e) {}
  }
  updateBadgeStates();
}

function restoreFilterUI() {
  document.getElementById('filter-ip').value = activeFilters.ip || '';
  document.getElementById('filter-username').value = activeFilters.username || '';
  document.getElementById('filter-score-min').value = activeFilters.scoreMin ?? 0;
  document.getElementById('filter-score-max').value = activeFilters.scoreMax ?? 100;
  document.getElementById('filter-cmd-min').value = activeFilters.cmdMin ?? '';
  document.getElementById('filter-cmd-max').value = activeFilters.cmdMax ?? '';

  document.querySelectorAll('#danger-level-group input').forEach(cb => {
    cb.checked = activeFilters.dangerLevels.includes(cb.value);
  });

  document.querySelectorAll('#attacker-type-group input').forEach(cb => {
    cb.checked = activeFilters.attackerTypes.includes(cb.value);
  });

  document.querySelectorAll('#honeypot-segment .segment-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.value === activeFilters.honeypotType);
  });

  document.getElementById('filter-persistence').checked = activeFilters.hasPersistence;
  document.getElementById('filter-credential').checked = activeFilters.hasCredentialAccess;

  updateBadgeStates();
}

function updateBadgeStates() {
  document.querySelectorAll('#danger-level-group .filter-badge').forEach(badge => {
    const cb = badge.querySelector('input');
    badge.classList.toggle('unchecked', !cb.checked);
  });

  document.querySelectorAll('#attacker-type-group .filter-badge').forEach(badge => {
    const cb = badge.querySelector('input');
    badge.classList.toggle('unchecked', !cb.checked);
  });
}

function saveFilters() {
  localStorage.setItem('otori-session-filters', JSON.stringify(activeFilters));
}

function toggleFilters() {
  const panel = document.getElementById('filter-panel');
  panel.classList.toggle('collapsed');
}

function onFilterChange() {
  activeFilters.ip = document.getElementById('filter-ip').value.trim();
  activeFilters.username = document.getElementById('filter-username').value.trim();

  activeFilters.dangerLevels = [];
  document.querySelectorAll('#danger-level-group input:checked').forEach(cb => {
    activeFilters.dangerLevels.push(cb.value);
  });

  activeFilters.attackerTypes = [];
  document.querySelectorAll('#attacker-type-group input:checked').forEach(cb => {
    activeFilters.attackerTypes.push(cb.value);
  });

  activeFilters.scoreMin = parseInt(document.getElementById('filter-score-min').value) || 0;
  activeFilters.scoreMax = parseInt(document.getElementById('filter-score-max').value) || 100;

  const cmdMin = document.getElementById('filter-cmd-min').value;
  const cmdMax = document.getElementById('filter-cmd-max').value;
  activeFilters.cmdMin = cmdMin !== '' ? parseInt(cmdMin) : null;
  activeFilters.cmdMax = cmdMax !== '' ? parseInt(cmdMax) : null;

  activeFilters.hasPersistence = document.getElementById('filter-persistence').checked;
  activeFilters.hasCredentialAccess = document.getElementById('filter-credential').checked;

  updateBadgeStates();
  saveFilters();
  applyFilters();
  renderFilteredSessions();
  updateFilterSummary();
}

function setHoneypotFilter(type) {
  activeFilters.honeypotType = type;
  document.querySelectorAll('#honeypot-segment .segment-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.value === type);
  });
  saveFilters();
  applyFilters();
  renderFilteredSessions();
  updateFilterSummary();
}

function toggleCountryDropdown(event) {
  event.stopPropagation();
  const menu = document.getElementById('country-dropdown-menu');
  const trigger = event.currentTarget;
  menu.classList.toggle('open');
  trigger.classList.toggle('open');
}

function updateCountryDropdown() {
  const countries = new Set();
  allSessions.forEach(s => {
    if (s.country_code && s.country_code !== 'PRIVATE') {
      countries.add(s.country_code);
    }
  });
  availableCountries = Array.from(countries).sort();

  const menu = document.getElementById('country-dropdown-menu');
  menu.innerHTML = availableCountries.map(code => `
    <label class="dropdown-item">
      <input type="checkbox" value="${code}" ${activeFilters.countries.length === 0 || activeFilters.countries.includes(code) ? 'checked' : ''} onchange="onCountryChange()">
      <span class="flag">${countryCodeToFlag(code)}</span>
      <span>${code}</span>
    </label>
  `).join('');

  updateCountryDropdownText();
}

function onCountryChange() {
  const checkedCountries = [];
  document.querySelectorAll('#country-dropdown-menu input:checked').forEach(cb => {
    checkedCountries.push(cb.value);
  });

  if (checkedCountries.length === availableCountries.length) {
    activeFilters.countries = [];
  } else {
    activeFilters.countries = checkedCountries;
  }

  updateCountryDropdownText();
  saveFilters();
  applyFilters();
  renderFilteredSessions();
  updateFilterSummary();
}

function updateCountryDropdownText() {
  const text = document.getElementById('country-dropdown-text');
  if (activeFilters.countries.length === 0 || activeFilters.countries.length === availableCountries.length) {
    text.textContent = t('filter.allCountries');
  } else if (activeFilters.countries.length === 1) {
    text.textContent = activeFilters.countries[0];
  } else {
    text.textContent = `${activeFilters.countries.length} ${currentLang === 'fr' ? 'pays' : 'countries'}`;
  }
}

function applyFilters() {
  filteredSessions = allSessions.filter(session => {
    if (activeFilters.ip && !session.src_ip?.toLowerCase().includes(activeFilters.ip.toLowerCase())) {
      return false;
    }

    if (activeFilters.username && !session.username?.toLowerCase().includes(activeFilters.username.toLowerCase())) {
      return false;
    }

    if (activeFilters.countries.length > 0 && !activeFilters.countries.includes(session.country_code)) {
      return false;
    }

    const dangerLevel = session.danger_level || 'unknown';
    if (!activeFilters.dangerLevels.includes(dangerLevel)) {
      return false;
    }

    const attackerType = session.attacker_type || 'unknown';
    if (!activeFilters.attackerTypes.includes(attackerType)) {
      return false;
    }

    const score = session.danger_score ?? 0;
    if (score < activeFilters.scoreMin || score > activeFilters.scoreMax) {
      return false;
    }

    const cmdCount = session.command_count ?? 0;
    if (activeFilters.cmdMin !== null && cmdCount < activeFilters.cmdMin) {
      return false;
    }
    if (activeFilters.cmdMax !== null && cmdCount > activeFilters.cmdMax) {
      return false;
    }

    if (activeFilters.honeypotType !== 'all') {
      const isIA = session.honeypot_type === 'ia' || session.is_ia_honeypot;
      if (activeFilters.honeypotType === 'ia' && !isIA) return false;
      if (activeFilters.honeypotType === 'classic' && isIA) return false;
    }

    if (activeFilters.hasPersistence && !session.has_persistence) {
      return false;
    }

    if (activeFilters.hasCredentialAccess && !session.has_credential_access) {
      return false;
    }

    return true;
  });
}

function renderFilteredSessions() {
  document.getElementById('session-count').textContent = `${filteredSessions.length} sessions`;
  document.getElementById('filter-result-count').textContent =
    t('filter.results').replace('{count}', filteredSessions.length);

  const tbody = document.getElementById('sessions-tbody');
  if (filteredSessions.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-state">${t('empty.noSession')}</td></tr>`;
    return;
  }

  tbody.innerHTML = filteredSessions.map(s => {
    const dangerClass = s.danger_level || 'unknown';
    const attackerClass = s.attacker_type || 'unknown';
    const scoreClass = s.danger_score >= 80 ? 'critical' : s.danger_score >= 50 ? 'high' : s.danger_score >= 25 ? 'medium' : 'low';
    const flag = countryCodeToFlag(s.country_code);

    return `
      <tr>
        <td class="ip-cell quick-filter" onclick="openIpModal('${esc(s.src_ip)}')">${esc(s.src_ip) || '-'}</td>
        <td class="quick-filter" onclick="quickFilterCountry('${esc(s.country_code)}')"><span class="flag">${flag}</span><span class="code">${esc(s.country_code) || '-'}</span></td>
        <td>${esc(s.username) || '-'}</td>
        <td>${s.command_count || 0}</td>
        <td><span class="score-wrapper" data-tooltip="${t('tooltip.dangerScore')}"><span class="score-bar"><span class="score-bar-fill ${scoreClass}" style="width: ${s.danger_score || 0}%"></span></span><span class="score-value">${s.danger_score || 0}</span></span></td>
        <td><span class="danger-badge ${dangerClass} quick-filter" onclick="quickFilterDangerLevel('${dangerClass}')">${dangerClass}</span></td>
        <td><span class="attacker-badge ${attackerClass} quick-filter" onclick="quickFilterAttackerType('${attackerClass}')">${attackerClass}</span></td>
        <td>${fmtDuration(s.duration_sec)}</td>
      </tr>
    `;
  }).join('');
}

function updateFilterSummary() {
  const count = countActiveFilters();
  const summary = document.getElementById('filter-summary');
  if (count === 0) {
    summary.textContent = '';
  } else {
    summary.textContent = t('filter.activeFilters').replace('{count}', count);
  }
}

function countActiveFilters() {
  let count = 0;
  if (activeFilters.ip) count++;
  if (activeFilters.username) count++;
  if (activeFilters.countries.length > 0) count++;
  if (activeFilters.dangerLevels.length < 5) count++;
  if (activeFilters.attackerTypes.length < 4) count++;
  if (activeFilters.scoreMin > 0 || activeFilters.scoreMax < 100) count++;
  if (activeFilters.cmdMin !== null || activeFilters.cmdMax !== null) count++;
  if (activeFilters.honeypotType !== 'all') count++;
  if (activeFilters.hasPersistence) count++;
  if (activeFilters.hasCredentialAccess) count++;
  return count;
}

function resetFilters() {
  activeFilters = {
    ip: '',
    username: '',
    countries: [],
    dangerLevels: ['critical', 'high', 'medium', 'low', 'minimal'],
    attackerTypes: ['bot', 'human', 'hybrid', 'unknown'],
    scoreMin: 0,
    scoreMax: 100,
    cmdMin: null,
    cmdMax: null,
    honeypotType: 'all',
    hasPersistence: false,
    hasCredentialAccess: false
  };

  restoreFilterUI();
  updateCountryDropdown();
  saveFilters();
  applyFilters();
  renderFilteredSessions();
  updateFilterSummary();
}

// Quick filter functions
function quickFilterIP(ip) {
  if (!ip || ip === '-') return;
  openIpModal(ip);
}

function quickFilterCountry(code) {
  if (!code || code === '-' || code === 'PRIVATE') return;
  activeFilters.countries = [code];

  document.querySelectorAll('#country-dropdown-menu input').forEach(cb => {
    cb.checked = cb.value === code;
  });

  updateCountryDropdownText();
  saveFilters();
  applyFilters();
  renderFilteredSessions();
  updateFilterSummary();
}

function quickFilterDangerLevel(level) {
  if (!level || level === 'unknown') return;
  activeFilters.dangerLevels = [level];

  document.querySelectorAll('#danger-level-group input').forEach(cb => {
    cb.checked = cb.value === level;
  });

  updateBadgeStates();
  saveFilters();
  applyFilters();
  renderFilteredSessions();
  updateFilterSummary();
}

function quickFilterAttackerType(type) {
  if (!type || type === 'unknown') return;
  activeFilters.attackerTypes = [type];

  document.querySelectorAll('#attacker-type-group input').forEach(cb => {
    cb.checked = cb.value === type;
  });

  updateBadgeStates();
  saveFilters();
  applyFilters();
  renderFilteredSessions();
  updateFilterSummary();
}

// Close dropdown when clicking outside
document.addEventListener('click', (e) => {
  const dropdown = document.getElementById('country-dropdown');
  if (dropdown && !dropdown.contains(e.target)) {
    document.getElementById('country-dropdown-menu').classList.remove('open');
    document.querySelector('.dropdown-trigger')?.classList.remove('open');
  }
});
