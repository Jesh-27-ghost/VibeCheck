/**
 * VibeCheck Frontend Logic
 * Implements real-time API client, 1-click demos, animated scan stepper,
 * findings filtering, prompt copy, and Phase 5 rescan comparison.
 */

// Global state
let currentScan = null;
let currentComparison = null;
let activeFilter = 'all';

// DOM elements
const backendStatusText = document.getElementById('backend-status-text');
const backendStatusPill = document.getElementById('backend-status');
const btnQuickVuln = document.getElementById('btn-quick-vuln');
const btnQuickRescan = document.getElementById('btn-quick-rescan');
const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('file-input');
const btnSelectFile = document.getElementById('btn-select-file');
const progressPanel = document.getElementById('progress-panel');
const progressTitle = document.getElementById('progress-title');
const resultsContainer = document.getElementById('results-container');
const btnCopyPrompt = document.getElementById('btn-copy-prompt');
const repairPromptText = document.getElementById('repair-prompt-text');
const toast = document.getElementById('toast');
const filterBtns = document.querySelectorAll('.filter-btn');
const findingsList = document.getElementById('findings-list');

// 1. Health check probe
async function checkHealth() {
  const start = performance.now();
  try {
    const res = await fetch('/health');
    const data = await res.json();
    const duration = Math.round(performance.now() - start);
    if (res.ok && data.ready) {
      backendStatusText.textContent = `Online • ${duration}ms`;
      backendStatusPill.style.background = 'rgba(16, 185, 129, 0.12)';
      backendStatusPill.style.color = '#10b981';
      backendStatusPill.style.borderColor = 'rgba(16, 185, 129, 0.3)';
    } else {
      throw new Error('Not ready');
    }
  } catch (err) {
    backendStatusText.textContent = 'Backend Offline';
    backendStatusPill.style.background = 'rgba(244, 63, 94, 0.12)';
    backendStatusPill.style.color = '#f43f5e';
    backendStatusPill.style.borderColor = 'rgba(244, 63, 94, 0.3)';
  }
}

// 2. Animated stepper helper
function startScanningAnimation() {
  progressPanel.style.display = 'block';
  resultsContainer.style.display = 'none';

  const steps = [
    document.getElementById('step-1'),
    document.getElementById('step-2'),
    document.getElementById('step-3'),
    document.getElementById('step-4'),
  ];

  steps.forEach(s => s.className = 'step-card');
  steps[0].classList.add('active');

  setTimeout(() => {
    steps[0].classList.replace('active', 'done');
    steps[1].classList.add('active');
  }, 350);

  setTimeout(() => {
    steps[1].classList.replace('active', 'done');
    steps[2].classList.add('active');
  }, 750);

  setTimeout(() => {
    steps[2].classList.replace('active', 'done');
    steps[3].classList.add('active');
  }, 1150);
}

function finishScanningAnimation() {
  const steps = [
    document.getElementById('step-1'),
    document.getElementById('step-2'),
    document.getElementById('step-3'),
    document.getElementById('step-4'),
  ];
  steps.forEach(s => s.className = 'step-card done');

  setTimeout(() => {
    progressPanel.style.display = 'none';
    resultsContainer.style.display = 'flex';
  }, 300);
}

// 3. Render Scan Results
function renderScanResults(scan) {
  currentScan = scan;
  btnQuickRescan.disabled = false;

  // Metrics
  const findings = scan.findings || [];
  const critCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;

  const metricRisk = document.getElementById('metric-risk');
  if (critCount > 0) {
    metricRisk.textContent = 'CRITICAL RISK';
    metricRisk.style.color = 'var(--sev-critical)';
  } else if (highCount > 0) {
    metricRisk.textContent = 'HIGH RISK';
    metricRisk.style.color = 'var(--sev-high)';
  } else if (findings.length > 0) {
    metricRisk.textContent = 'MEDIUM RISK';
    metricRisk.style.color = 'var(--sev-medium)';
  } else {
    metricRisk.textContent = 'SECURE (CLEAN)';
    metricRisk.style.color = 'var(--status-success)';
  }

  document.getElementById('metric-scan-id').textContent = `Scan ID: ${scan.scan_id}`;
  document.getElementById('metric-findings-count').textContent = findings.length;
  document.getElementById('metric-critical-count').textContent = `${critCount} critical, ${highCount} high`;

  const cov = scan.coverage || {};
  document.getElementById('metric-files-lines').textContent = `${cov.files_scanned || 0} / ${cov.total_lines || 0}`;

  // Coverage Pills
  const covPills = document.getElementById('coverage-pills');
  covPills.innerHTML = '';

  const completed = cov.completed || [];
  completed.forEach(c => {
    const pill = document.createElement('span');
    pill.className = 'pill pill-green';
    pill.innerHTML = `✓ ${c}`;
    covPills.appendChild(pill);
  });

  const skipped = (cov.skipped || []).concat(cov.unsupported || []);
  skipped.forEach(s => {
    const pill = document.createElement('span');
    pill.className = 'pill pill-gray';
    pill.innerHTML = `• ${s} (skipped/unsupported)`;
    covPills.appendChild(pill);
  });

  document.getElementById('coverage-rules-count').textContent = `${completed.length} rules evaluated`;

  // Repair Prompt
  repairPromptText.value = scan.repair_prompt || 'No findings detected requiring repair.';

  // Findings list
  document.getElementById('filter-all-count').textContent = findings.length;
  renderFilteredFindings();
}

// 4. Render Filtered Findings
function renderFilteredFindings() {
  if (!currentScan) return;
  const findings = currentScan.findings || [];

  const filtered = findings.filter(f => {
    if (activeFilter === 'all') return true;
    if (activeFilter === 'critical') return f.severity === 'critical';
    if (activeFilter === 'high') return f.severity === 'high';
    if (activeFilter === 'medium') return f.severity === 'medium';
    if (activeFilter === 'exposed_secret') return f.category === 'exposed_secret';
    if (activeFilter === 'injection') return f.category === 'injection';
    if (activeFilter === 'code_execution') return f.category === 'code_execution';
    return true;
  });

  findingsList.innerHTML = '';
  if (filtered.length === 0) {
    findingsList.innerHTML = `
      <div class="glass-panel" style="padding: 2.5rem; text-align: center; color: var(--text-muted);">
        ✨ No findings matching the current filter.
      </div>
    `;
    return;
  }

  filtered.forEach(f => {
    const card = document.createElement('div');
    card.className = `glass-panel finding-card severity-${f.severity || 'medium'}`;

    const loc = f.location || {};
    const lineInfo = loc.line_start ? `Line ${loc.line_start}` : 'General';
    const filePath = loc.file_path || 'unknown';

    // Mask highlighting in snippet
    let snippet = loc.snippet || (typeof f.evidence === 'string' ? f.evidence : (f.evidence?.snippet || ''));
    if (!snippet && typeof f.evidence === 'object') {
      snippet = JSON.stringify(f.evidence, null, 2);
    }
    const safeSnippet = escapeHtml(snippet).replace(
      /\[MASKED\]/g,
      '<span class="masked-tag">🛡️ [MASKED SECRET]</span>'
    );

    const steps = (f.verification_steps || [])
      .map(s => `<li>${escapeHtml(s)}</li>`)
      .join('');

    card.innerHTML = `
      <div class="finding-top">
        <div class="finding-title-group">
          <span class="finding-id-badge">${escapeHtml(f.id)} • Rule: ${escapeHtml(f.rule_id)}</span>
          <h4 class="finding-title">${escapeHtml(f.title)}</h4>
          <span class="finding-loc">📄 ${escapeHtml(filePath)} : ${lineInfo}</span>
        </div>
        <div class="finding-badges">
          <span class="badge-sev ${f.severity}">${f.severity}</span>
          <span class="badge-conf">Confidence: ${f.confidence}</span>
        </div>
      </div>

      <div class="code-snippet">
        <code>${safeSnippet}</code>
      </div>

      <div class="finding-details">
        <div class="detail-box">
          <div class="detail-label">⚠️ Impact & Exploitation Precondition</div>
          <p style="color: #e2e8f0;">${escapeHtml(f.impact || 'Security risk detected in code pattern.')}</p>
        </div>

        <div class="detail-box">
          <div class="detail-label">💡 Recommended Remediation</div>
          <p style="color: #e2e8f0; margin-bottom: 0.5rem;">${escapeHtml(f.recommendation || 'Remediate this finding by following best practices.')}</p>
          ${steps ? `<ul style="padding-left: 1.2rem; color: #94a3b8; font-size: 0.78rem;">${steps}</ul>` : ''}
        </div>
      </div>
    `;

    findingsList.appendChild(card);
  });
}

// 5. Render Comparison Section (Phase 5)
function renderComparison(comp) {
  currentComparison = comp;
  const section = document.getElementById('comparison-section');
  section.style.display = 'block';

  const sum = comp.summary || {};
  document.getElementById('count-resolved').textContent = sum.resolved_count || 0;
  document.getElementById('count-still-present').textContent = sum.still_present_count || 0;
  document.getElementById('count-new').textContent = sum.new_count || 0;
  document.getElementById('count-not-verified').textContent = sum.not_verified_count || 0;

  const totalBase = sum.total_baseline || 1;
  const pct = Math.round(((sum.resolved_count || 0) / totalBase) * 100);
  document.getElementById('comparison-stats-badge').textContent = `${sum.resolved_count || 0} / ${totalBase} Resolved (${pct}%)`;

  // Render items in each column
  renderCompItems('list-resolved', comp.resolved_by_checks || [], 'Resolved');
  renderCompItems('list-still-present', comp.still_present || [], 'Still Present');
  renderCompItems('list-new', comp.new || [], 'New');
  renderCompItems('list-not-verified', comp.not_verified || [], 'Unverified');

  section.scrollIntoView({ behavior: 'smooth' });
}

function renderCompItems(elementId, items, label) {
  const container = document.getElementById(elementId);
  container.innerHTML = '';
  if (items.length === 0) {
    container.innerHTML = `<span style="font-size: 0.75rem; color: var(--text-dim);">No items in this category.</span>`;
    return;
  }
  items.forEach(it => {
    const div = document.createElement('div');
    div.className = 'comp-item';
    const loc = it.location || {};
    div.innerHTML = `
      <div style="font-weight: 700; color: #ffffff;">${escapeHtml(it.title || it.id)}</div>
      <div style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono);">${escapeHtml(loc.file_path || 'file')}</div>
      ${it.verification_note ? `<div style="font-size: 0.7rem; color: #f59e0b; margin-top: 0.25rem;">⚠️ ${escapeHtml(it.verification_note)}</div>` : ''}
    `;
    container.appendChild(div);
  });
}

// 6. API Actions
async function scanZipFile(file) {
  const formData = new FormData();
  formData.append('file', file);

  startScanningAnimation();
  try {
    const res = await fetch('/api/v1/scans', {
      method: 'POST',
      body: formData,
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || 'Scan failed');
    }
    finishScanningAnimation();
    renderScanResults(data);
    showToast('Scan completed successfully!');
  } catch (err) {
    progressPanel.style.display = 'none';
    alert(`Scan error: ${err.message}`);
  }
}

async function triggerDemoScan(sampleType = 'vulnerable') {
  startScanningAnimation();
  try {
    const res = await fetch(`/api/v1/demo/scan-sample?sample_type=${sampleType}`, {
      method: 'POST',
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || 'Demo scan failed');
    }
    finishScanningAnimation();
    renderScanResults(data);
    showToast(`Loaded ${sampleType} sample scan!`);
  } catch (err) {
    progressPanel.style.display = 'none';
    alert(`Demo scan failed: ${err.message}`);
  }
}

async function triggerDemoRescan() {
  if (!currentScan || !currentScan.scan_id) {
    alert('Please run a baseline scan first!');
    return;
  }
  startScanningAnimation();
  progressTitle.textContent = 'Running Rescan & Verification Comparison...';
  try {
    const res = await fetch(`/api/v1/demo/rescan-sample/${currentScan.scan_id}`, {
      method: 'POST',
    });
    const compData = await res.json();
    if (!res.ok) {
      throw new Error(compData.detail || 'Rescan failed');
    }
    finishScanningAnimation();
    renderComparison(compData);
    showToast('Rescan comparison complete!');
  } catch (err) {
    progressPanel.style.display = 'none';
    alert(`Rescan failed: ${err.message}`);
  }
}

// 7. Utility functions
function showToast(msg) {
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2800);
}

function escapeHtml(text) {
  if (!text) return '';
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return String(text).replace(/[&<>"']/g, m => map[m]);
}

// Event Listeners
btnQuickVuln.addEventListener('click', () => triggerDemoScan('vulnerable'));
btnQuickRescan.addEventListener('click', triggerDemoRescan);

btnSelectFile.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', (e) => {
  if (e.target.files.length > 0) {
    scanZipFile(e.target.files[0]);
  }
});

dropzone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropzone.classList.add('drag-active');
});

dropzone.addEventListener('dragleave', () => {
  dropzone.classList.remove('drag-active');
});

dropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropzone.classList.remove('drag-active');
  if (e.dataTransfer.files.length > 0) {
    scanZipFile(e.dataTransfer.files[0]);
  }
});

btnCopyPrompt.addEventListener('click', () => {
  navigator.clipboard.writeText(repairPromptText.value).then(() => {
    showToast('Copied repair prompt to clipboard!');
  }).catch(() => {
    repairPromptText.select();
    document.execCommand('copy');
    showToast('Copied repair prompt!');
  });
});

filterBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    filterBtns.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeFilter = btn.dataset.filter;
    renderFilteredFindings();
  });
});

// Initial load
checkHealth();
setInterval(checkHealth, 8000);
