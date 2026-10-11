/**
 * ThreatLens — Vulnerability Assessment System
 * Main JavaScript — Phase 1
 */

'use strict';

/* ============================================================
   Flash Message Auto-Dismiss
   ============================================================ */
document.querySelectorAll('.flash-msg').forEach(msg => {
  setTimeout(() => {
    msg.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
    msg.style.opacity = '0';
    msg.style.transform = 'translateX(100%)';
    setTimeout(() => msg.remove(), 500);
  }, 4000);
});

/* ============================================================
   Animate stat card numbers (count-up effect)
   ============================================================ */
function animateCountUp(el) {
  const target = parseInt(el.getAttribute('data-target') || el.textContent, 10);
  if (isNaN(target) || target === 0) return;

  const duration = 1200;
  const step     = target / (duration / 16);
  let current    = 0;

  const timer = setInterval(() => {
    current += step;
    if (current >= target) {
      el.textContent = target;
      clearInterval(timer);
    } else {
      el.textContent = Math.floor(current);
    }
  }, 16);
}

document.querySelectorAll('.stat-value[data-target]').forEach(animateCountUp);

/* ============================================================
   Risk bar widths — driven by data-score attribute
   ============================================================ */
document.querySelectorAll('.risk-bar-fill[data-score]').forEach(bar => {
  const score = parseFloat(bar.getAttribute('data-score'));
  const pct   = (score / 10) * 100;
  bar.style.width = pct + '%';
});

/* ============================================================
   Severity Doughnut Chart (Dashboard)
   ============================================================ */
function initSeverityChart(chartData) {
  const canvas = document.getElementById('severityChart');
  if (!canvas || typeof Chart === 'undefined') return;

  const ctx = canvas.getContext('2d');

  const total = chartData.values.reduce((a, b) => a + b, 0);
  if (total === 0) {
    canvas.parentElement.innerHTML = '<div class="empty-state"><div class="empty-icon">📊</div><p>No vulnerability data yet.</p></div>';
    return;
  }

  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: chartData.labels,
      datasets: [{
        data:            chartData.values,
        backgroundColor: chartData.colors,
        borderColor:     'transparent',
        borderWidth:     0,
        hoverOffset:     8,
      }],
    },
    options: {
      responsive: true,
      cutout: '70%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color:    '#94a3b8',
            padding:  16,
            font:     { size: 12, family: 'Inter' },
            usePointStyle: true,
            pointStyleWidth: 10,
          },
        },
        tooltip: {
          backgroundColor: '#131929',
          titleColor:      '#e2e8f0',
          bodyColor:       '#94a3b8',
          borderColor:     'rgba(255,255,255,0.07)',
          borderWidth:     1,
          padding:         12,
          callbacks: {
            label: ctx => ` ${ctx.label}: ${ctx.parsed} (${Math.round(ctx.parsed / total * 100)}%)`,
          },
        },
      },
    },
  });
}

/* ============================================================
   Assessment Status Bar Chart (Dashboard)
   ============================================================ */
function initStatusChart(statusData) {
  const canvas = document.getElementById('statusChart');
  if (!canvas || typeof Chart === 'undefined') return;

  const ctx = canvas.getContext('2d');

  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Completed', 'Running', 'Pending', 'Failed'],
      datasets: [{
        data:            [statusData.completed, statusData.running, statusData.pending, statusData.failed],
        backgroundColor: ['#22c55e', '#3b82f6', '#94a3b8', '#ef4444'],
        borderRadius:    6,
        borderSkipped:   false,
      }],
    },
    options: {
      responsive: true,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#131929',
          titleColor:      '#e2e8f0',
          bodyColor:       '#94a3b8',
          borderColor:     'rgba(255,255,255,0.07)',
          borderWidth:     1,
          padding:         12,
        },
      },
      scales: {
        x: {
          grid:  { color: 'rgba(255,255,255,0.04)' },
          ticks: { color: '#64748b', font: { size: 11 } },
        },
        y: {
          grid:       { color: 'rgba(255,255,255,0.04)' },
          ticks:      { color: '#64748b', font: { size: 11 }, stepSize: 1 },
          beginAtZero: true,
        },
      },
    },
  });
}

/* ============================================================
   Expose chart initializers globally so templates can call them
   ============================================================ */
window.ThreatLens = {
  initSeverityChart,
  initStatusChart,
};
