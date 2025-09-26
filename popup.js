document.addEventListener('DOMContentLoaded', () => {
  const elements = {
    threatsBlocked: document.getElementById('threats-blocked'),
    linksScanned: document.getElementById('links-scanned'),
    sessionsProtected: document.getElementById('sessions-protected'),
    mlPatterns: document.getElementById('ml-patterns'),
    redirectsBlocked: document.getElementById('redirects-blocked'),
    contentThreats: document.getElementById('content-threats'),
    status: document.getElementById('status'),
    refreshBtn: document.getElementById('refresh-btn'),
    dashboardBtn: document.getElementById('dashboard-btn'),
    settingsBtn: document.getElementById('settings-btn')
  };

  function loadStats() {
    chrome.runtime.sendMessage({ action: 'getStats' }, (stats) => {
      if (stats) {
        elements.threatsBlocked.textContent = stats.threatsBlocked || 0;
        elements.linksScanned.textContent = stats.linksScanned || 0;
        elements.sessionsProtected.textContent = stats.sessionsProtected || 0;
        elements.mlPatterns.textContent = (stats.mlStats && stats.mlStats.learnedPatterns) || 0;
        elements.redirectsBlocked.textContent = stats.redirectsBlocked || 0;
        elements.contentThreats.textContent = (stats.contentStats && stats.contentStats.threatsDetected) || 0;
        
        const mlStats = stats.mlStats || {};
        if (stats.threatsBlocked > 5) {
          elements.status.innerHTML = '🔥 High threat activity - AI learning active';
          elements.status.className = 'status threat-high';
        } else if (stats.threatsBlocked > 0) {
          elements.status.innerHTML = `⚠️ ${stats.threatsBlocked} threats blocked - ${mlStats.learnedPatterns || 0} patterns learned`;
          elements.status.className = 'status threat-medium';
        } else {
          const redirectCount = stats.redirectsBlocked || 0;
          const contentScore = (stats.contentStats && stats.contentStats.contentScore) || 0;
          elements.status.innerHTML = `🤖 Full Protection Active - Content: ${(contentScore * 100).toFixed(0)}%, ${mlStats.totalAnalyzed || 0} analyzed`;
          elements.status.className = 'status active';
        }
      }
    });
  }

  function animateCounter(element, target) {
    const current = parseInt(element.textContent) || 0;
    const increment = Math.ceil((target - current) / 10);
    
    if (current < target) {
      element.textContent = current + increment;
      setTimeout(() => animateCounter(element, target), 50);
    } else {
      element.textContent = target;
    }
  }


  elements.refreshBtn.addEventListener('click', () => {
    elements.refreshBtn.textContent = 'Refreshing...';
    setTimeout(() => {
      loadStats();
      elements.refreshBtn.textContent = 'Refresh Stats';
    }, 500);
  });

  elements.dashboardBtn.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('scan-dashboard.html') });
  });
  
  elements.settingsBtn.addEventListener('click', () => {
    chrome.tabs.create({ url: 'chrome://extensions/?id=' + chrome.runtime.id });
  });

  loadStats();
  setInterval(loadStats, 3000);
});