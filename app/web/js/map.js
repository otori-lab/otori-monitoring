/**
 * OTORI Dashboard - Attack Map
 * Leaflet.js map for visualizing attack origins
 */

// Map instance
let attackMap = null;
let markersLayer = null;
let countryLayer = null;

// Cached geo data
let cachedGeoData = {
  coordinates: [],
  countries: [],
  asn: []
};

// Marker colors based on attack intensity
const MARKER_COLORS = {
  critical: '#f87171',  // red
  high: '#fb923c',      // orange
  medium: '#fbbf24',    // yellow
  low: '#34d399',       // green
  default: '#4cc9ff'    // blue
};

/**
 * Initialize the Leaflet map
 */
function initAttackMap() {
  // Check if map container exists
  const mapContainer = document.getElementById('attack-map');
  if (!mapContainer) return;

  // Destroy existing map if any
  if (attackMap) {
    attackMap.remove();
    attackMap = null;
  }

  // Create map centered on world view
  attackMap = L.map('attack-map', {
    center: [30, 0],
    zoom: 2,
    minZoom: 2,
    maxZoom: 12,
    worldCopyJump: true,
    maxBounds: [[-90, -180], [90, 180]],
    maxBoundsViscosity: 1.0
  });

  // Dark theme tile layer (CartoDB Dark Matter)
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/attributions">CARTO</a>',
    subdomains: 'abcd',
    maxZoom: 19
  }).addTo(attackMap);

  // Create markers layer group
  markersLayer = L.layerGroup().addTo(attackMap);

  // Handle map resize when tab becomes visible
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.dataset.page === 'geography') {
        setTimeout(() => {
          if (attackMap) attackMap.invalidateSize();
        }, 100);
      }
    });
  });
}

/**
 * Update map with attack coordinates
 */
function updateAttackMap(coordinates, countries) {
  if (!attackMap || !markersLayer) {
    initAttackMap();
    if (!attackMap) return;
  }

  // Clear existing markers
  markersLayer.clearLayers();

  // Group attacks by coordinates for clustering
  const locationGroups = {};

  coordinates.forEach(point => {
    if (!point.lat || !point.lon) return;

    // Round coordinates for grouping nearby attacks
    const key = `${point.lat.toFixed(2)},${point.lon.toFixed(2)}`;
    if (!locationGroups[key]) {
      locationGroups[key] = {
        lat: point.lat,
        lon: point.lon,
        country: point.country,
        city: point.city,
        ips: [],
        count: 0
      };
    }
    locationGroups[key].ips.push(point.ip);
    locationGroups[key].count++;
  });

  // Create country session counts for sizing
  const countrySessionCounts = {};
  countries.forEach(c => {
    countrySessionCounts[c.code] = c.sessions;
  });

  // Add markers for each location group
  Object.values(locationGroups).forEach(group => {
    const sessions = countrySessionCounts[group.country] || group.count;
    const intensity = getIntensityLevel(sessions);
    const color = MARKER_COLORS[intensity];
    const radius = getMarkerRadius(group.count);

    // Create circle marker
    const marker = L.circleMarker([group.lat, group.lon], {
      radius: radius,
      fillColor: color,
      color: color,
      weight: 2,
      opacity: 0.9,
      fillOpacity: 0.6
    });

    // Create popup content
    const popupContent = createPopupContent(group);
    marker.bindPopup(popupContent, {
      className: 'dark-popup'
    });

    // Add tooltip
    const tooltipText = `${group.city || group.country || 'Unknown'}: ${group.count} attack${group.count > 1 ? 's' : ''}`;
    marker.bindTooltip(tooltipText, {
      className: 'dark-tooltip',
      direction: 'top'
    });

    // Click handler to show country details
    marker.on('click', () => {
      if (group.country && group.country !== 'PRIVATE') {
        // Could trigger showCountryDetails here if desired
      }
    });

    markersLayer.addLayer(marker);
  });

  // Fit bounds if we have markers
  if (Object.keys(locationGroups).length > 0) {
    const bounds = markersLayer.getBounds();
    if (bounds.isValid()) {
      attackMap.fitBounds(bounds, { padding: [50, 50], maxZoom: 6 });
    }
  }
}

/**
 * Determine intensity level based on session count
 */
function getIntensityLevel(count) {
  if (count >= 50) return 'critical';
  if (count >= 20) return 'high';
  if (count >= 10) return 'medium';
  if (count >= 5) return 'low';
  return 'default';
}

/**
 * Calculate marker radius based on attack count
 */
function getMarkerRadius(count) {
  const base = 6;
  const scale = Math.log10(count + 1) * 4;
  return Math.min(base + scale, 25); // Cap at 25px
}

/**
 * Create popup HTML content
 */
function createPopupContent(group) {
  const uniqueIps = [...new Set(group.ips)];
  const displayIps = uniqueIps.slice(0, 5);
  const moreCount = uniqueIps.length - 5;

  let html = `
    <div class="map-popup">
      <div class="popup-header">
        <span class="popup-flag">${countryCodeToFlag(group.country)}</span>
        <span class="popup-location">${group.city || ''} ${group.country || 'Unknown'}</span>
      </div>
      <div class="popup-stats">
        <div class="popup-stat">
          <span class="popup-stat-value">${group.count}</span>
          <span class="popup-stat-label">${t('geo.attacks')}</span>
        </div>
        <div class="popup-stat">
          <span class="popup-stat-value">${uniqueIps.length}</span>
          <span class="popup-stat-label">${t('geo.uniqueIps')}</span>
        </div>
      </div>
      <div class="popup-ips">
        <div class="popup-ips-title">${t('geo.recentIps')}:</div>
  `;

  displayIps.forEach(ip => {
    html += `<div class="popup-ip" onclick="openIpModal('${ip}')">${ip}</div>`;
  });

  if (moreCount > 0) {
    html += `<div class="popup-more">+${moreCount} ${t('geo.more')}</div>`;
  }

  html += `
      </div>
    </div>
  `;

  return html;
}

/**
 * Update geography page with geo data
 */
function updateGeographyPage(kpi) {
  // Store cached data
  cachedGeoData = {
    coordinates: kpi.attack_coordinates || [],
    countries: kpi.top_countries || [],
    asn: kpi.top_asn || []
  };

  // Update KPI cards
  document.getElementById('kpi-countries').textContent = kpi.unique_countries || 0;

  if (kpi.top_countries && kpi.top_countries.length > 0) {
    const top = kpi.top_countries[0];
    document.getElementById('kpi-top-country').textContent =
      `${countryCodeToFlag(top.code)} ${top.code}`;
    document.getElementById('kpi-top-country-sessions').textContent =
      `${top.sessions} sessions`;
  }

  document.getElementById('kpi-attack-points').textContent =
    (kpi.attack_coordinates || []).length;

  if (kpi.top_asn && kpi.top_asn.length > 0) {
    const topAsn = kpi.top_asn[0];
    const asnName = topAsn.org ?
      (topAsn.org.length > 15 ? topAsn.org.substring(0, 15) + '...' : topAsn.org) :
      '-';
    document.getElementById('kpi-top-asn').textContent = asnName;
    document.getElementById('kpi-top-asn-sessions').textContent =
      `${topAsn.sessions} sessions`;
  }

  // Update map
  updateAttackMap(kpi.attack_coordinates || [], kpi.top_countries || []);

  // Update top countries list
  renderTopCountries(kpi.top_countries || []);

  // Update top ASN list
  renderTopAsn(kpi.top_asn || []);
}

/**
 * Render top countries list
 */
function renderTopCountries(countries) {
  const container = document.getElementById('top-countries-list');
  if (!container) return;

  if (!countries || countries.length === 0) {
    container.innerHTML = `<div class="empty-state">${t('empty.noData')}</div>`;
    return;
  }

  const maxSessions = Math.max(...countries.map(c => c.sessions));

  container.innerHTML = countries.slice(0, 10).map((country, i) => {
    const percentage = (country.sessions / maxSessions) * 100;
    return `
      <div class="top-item clickable" onclick="showCountryDetails('${country.code}')">
        <span class="rank ${i < 3 ? 'top3' : ''}">${i + 1}</span>
        <div class="content">
          <div class="name">
            <span class="flag">${countryCodeToFlag(country.code)}</span>
            ${country.name || country.code}
          </div>
          <div class="progress-bar">
            <div class="progress-fill" style="width: ${percentage}%; background: var(--accent);"></div>
          </div>
        </div>
        <span class="count">${country.sessions}</span>
      </div>
    `;
  }).join('');
}

/**
 * Render top ASN list
 */
function renderTopAsn(asnList) {
  const container = document.getElementById('top-asn-list');
  if (!container) return;

  if (!asnList || asnList.length === 0) {
    container.innerHTML = `<div class="empty-state">${t('empty.noData')}</div>`;
    return;
  }

  const maxSessions = Math.max(...asnList.map(a => a.sessions));

  container.innerHTML = asnList.slice(0, 10).map((asn, i) => {
    const percentage = (asn.sessions / maxSessions) * 100;
    const orgName = asn.org || 'Unknown';
    const displayName = orgName.length > 35 ? orgName.substring(0, 35) + '...' : orgName;

    return `
      <div class="top-item">
        <span class="rank ${i < 3 ? 'top3' : ''}">${i + 1}</span>
        <div class="content">
          <div class="name" title="${orgName}">${displayName}</div>
          <div class="progress-bar">
            <div class="progress-fill" style="width: ${percentage}%; background: var(--purple);"></div>
          </div>
        </div>
        <span class="count">${asn.sessions}</span>
      </div>
    `;
  }).join('');
}

/**
 * Show country details in modal
 */
function showCountryDetailsFromMap(countryCode) {
  if (typeof showCountryDetails === 'function') {
    showCountryDetails(countryCode);
  }
}
