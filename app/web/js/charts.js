/**
 * OTORI Dashboard - Charts
 * Chart.js initialization and configuration
 */

// Chart instances
let activityChart, loginChart, categoryChart, severityChart;

// Chart.js defaults
Chart.defaults.color = '#8b95a5';
Chart.defaults.borderColor = '#1e2733';
Chart.defaults.font.family = 'Inter, sans-serif';

function initActivityChart() {
  const ctx = document.getElementById('activityChart').getContext('2d');
  activityChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Sessions',
          data: [],
          borderColor: COLORS.accent,
          backgroundColor: 'rgba(255, 79, 216, 0.1)',
          fill: true,
          tension: 0.4,
          pointRadius: 4,
          pointHoverRadius: 8,
          borderWidth: 2,
        },
        {
          label: 'Commandes',
          data: [],
          borderColor: COLORS.blue,
          backgroundColor: 'rgba(76, 201, 255, 0.1)',
          fill: true,
          tension: 0.4,
          pointRadius: 4,
          pointHoverRadius: 8,
          borderWidth: 2,
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { intersect: false, mode: 'index' },
      plugins: {
        legend: { display: true, position: 'top', align: 'end', labels: { boxWidth: 12, padding: 20 } }
      },
      scales: {
        x: { grid: { display: false } },
        y: { beginAtZero: true, grid: { color: '#1e2733' } }
      },
      onClick: (event, elements) => {
        if (elements.length > 0) {
          const index = elements[0].index;
          const label = activityChart.data.labels[index];
          const sessions = activityChart.data.datasets[0].data[index];
          const commands = activityChart.data.datasets[1].data[index];
          showTimelineDetails(label, sessions, commands);
        }
      }
    }
  });
  document.getElementById('activityChart').style.cursor = 'pointer';
}

function initLoginChart() {
  const ctx = document.getElementById('loginChart').getContext('2d');
  loginChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Succès', 'Échecs'],
      datasets: [{
        data: [0, 0],
        backgroundColor: [COLORS.green, COLORS.red],
        borderWidth: 0,
        spacing: 3,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '70%',
      plugins: { legend: { display: false } },
      onClick: (event, elements) => {
        if (elements.length > 0) {
          const index = elements[0].index;
          showAuthDetails(index === 0 ? 'success' : 'failed');
        }
      }
    }
  });
  document.getElementById('loginChart').style.cursor = 'pointer';
}

function initCategoryChart() {
  const ctx = document.getElementById('categoryChart').getContext('2d');
  categoryChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        data: [],
        backgroundColor: [],
        borderRadius: 6,
        borderSkipped: false,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: 'y',
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: '#1e2733' }, beginAtZero: true },
        y: { grid: { display: false } }
      },
      onClick: (event, elements) => {
        if (elements.length > 0) {
          const index = elements[0].index;
          const category = categoryChart.data.labels[index];
          showCategoryDetails(category);
        }
      }
    }
  });
  document.getElementById('categoryChart').style.cursor = 'pointer';
}

function initSeverityChart() {
  const ctx = document.getElementById('severityChart').getContext('2d');
  severityChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: [],
      datasets: [{
        data: [],
        backgroundColor: [],
        borderWidth: 0,
        spacing: 3,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '55%',
      plugins: {
        legend: { display: true, position: 'right', labels: { boxWidth: 12, padding: 12, font: { size: 11 } } }
      },
      onClick: (event, elements) => {
        if (elements.length > 0) {
          const index = elements[0].index;
          const severity = severityChart.data.labels[index];
          showSeverityDetails(severity);
        }
      }
    }
  });
  document.getElementById('severityChart').style.cursor = 'pointer';
}

function initAllCharts() {
  initActivityChart();
  initLoginChart();
  initCategoryChart();
  initSeverityChart();
}
