class RedirectMonitor {
  constructor(bogaGuard) {
    this.bogaGuard = bogaGuard;
    this.redirectChain = [];
    this.blockedRedirects = new Set();
    this.monitoringActive = false;
    
    this.init();
  }

  init() {
    this.interceptNavigations();
    this.monitorURLChanges();
    this.interceptFetch();
    this.interceptXHR();
  }

  interceptNavigations() {
    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;
    const originalReload = location.reload;
    const originalAssign = location.assign;
    const originalReplace = location.replace;
    
    history.pushState = (...args) => {
      if (this.requestNavigationApproval(args[2] || window.location.href, 'pushState')) {
        return originalPushState.apply(history, args);
      }
    };
    
    history.replaceState = (...args) => {
      if (this.requestNavigationApproval(args[2] || window.location.href, 'replaceState')) {
        return originalReplaceState.apply(history, args);
      }
    };
    
    location.reload = (...args) => {
      if (this.requestNavigationApproval(window.location.href, 'reload')) {
        return originalReload.apply(location, args);
      }
    };
    
    location.assign = (url) => {
      if (this.requestNavigationApproval(url, 'assign')) {
        return originalAssign.call(location, url);
      }
    };
    
    location.replace = (url) => {
      if (this.requestNavigationApproval(url, 'replace')) {
        return originalReplace.call(location, url);
      }
    };
    
    let currentHref = window.location.href;
    Object.defineProperty(window.location, 'href', {
      get: () => currentHref,
      set: (url) => {
        if (this.requestNavigationApproval(url, 'href')) {
          currentHref = url;
          originalAssign.call(location, url);
        }
      }
    });
    
    window.addEventListener('popstate', () => {
      this.checkURLChange(window.location.href);
    });
    
    window.addEventListener('beforeunload', (e) => {
      if (!this.requestNavigationApproval(window.location.href, 'beforeunload')) {
        e.preventDefault();
        e.returnValue = '';
      }
    });
  }

  monitorURLChanges() {
    let currentURL = window.location.href;
    
    setInterval(() => {
      if (window.location.href !== currentURL) {
        this.checkURLChange(window.location.href);
        currentURL = window.location.href;
      }
    }, 500);
    
    window.addEventListener('hashchange', () => {
      this.checkURLChange(window.location.href);
    });
  }

  interceptFetch() {
    const originalFetch = window.fetch;
    
    window.fetch = async (...args) => {
      const url = args[0];
      if (typeof url === 'string') {
        await this.checkRedirectURL(url, 'fetch');
      }
      return originalFetch.apply(window, args);
    };
  }

  interceptXHR() {
    const originalOpen = XMLHttpRequest.prototype.open;
    
    XMLHttpRequest.prototype.open = function(method, url, ...args) {
      if (typeof url === 'string') {
        this._redirectMonitor_url = url;
      }
      return originalOpen.apply(this, [method, url, ...args]);
    };
    
    const originalSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(...args) {
      if (this._redirectMonitor_url) {
        this.redirectMonitor?.checkRedirectURL(this._redirectMonitor_url, 'xhr');
      }
      return originalSend.apply(this, args);
    };
  }

  requestNavigationApproval(newURL, source) {
    const riskData = this.bogaGuard.calculateRisk(newURL);
    return this.showNavigationDialog(newURL, riskData, source);
  }
  
  showNavigationDialog(url, riskData, source) {
    const isHighRisk = riskData.level > 0.6;
    const isMediumRisk = riskData.level > 0.3;
    
    let riskColor = 'green';
    let riskText = 'Low Risk';
    let defaultAction = 'allow';
    
    if (isHighRisk) {
      riskColor = 'red';
      riskText = 'HIGH RISK';
      defaultAction = 'block';
    } else if (isMediumRisk) {
      riskColor = 'orange';
      riskText = 'Medium Risk';
      defaultAction = 'warn';
    }
    
    const dialog = document.createElement('div');
    dialog.className = 'lg-navigation-dialog';
    dialog.innerHTML = `
      <div class="lg-nav-dialog-content">
        <h3>🛡️ BogaGuard Navigation Control</h3>
        <div class="lg-nav-info">
          <p><strong>Navigation Type:</strong> ${source}</p>
          <p><strong>Destination:</strong></p>
          <div class="lg-nav-url">${url}</div>
          <p><strong>Risk Level:</strong> <span style="color: ${riskColor}; font-weight: bold;">${riskText} (${(riskData.level * 100).toFixed(0)}%)</span></p>
          ${riskData.reasons.length > 0 ? `
            <div class="lg-nav-reasons">
              <strong>Detected Issues:</strong>
              <ul>
                ${riskData.reasons.map(reason => `<li>${reason}</li>`).join('')}
              </ul>
            </div>
          ` : ''}
        </div>
        <div class="lg-nav-buttons">
          <button class="lg-btn-danger" onclick="this.resolveNavigation(false)">🚫 Block</button>
          <button class="lg-btn-warning" onclick="this.resolveNavigation(true)">⚠️ Allow Once</button>
          <button class="lg-btn-safe" onclick="this.resolveNavigation(true, true)">✅ Always Allow This Site</button>
        </div>
        <div class="lg-nav-footer">
          <small>BogaGuard protects you by asking permission for all navigation attempts</small>
        </div>
      </div>
    `;
    
    document.body.appendChild(dialog);
    this.addNavigationDialogStyles();
    
    return new Promise((resolve) => {
      dialog.resolveNavigation = (allow, whitelist = false) => {
        if (whitelist) {
          this.addToWhitelist(new URL(url).hostname);
        }
        dialog.remove();
        resolve(allow);
      };
      
      if (isHighRisk) {
        setTimeout(() => {
          if (dialog.parentElement) {
            dialog.resolveNavigation(false);
          }
        }, 10000);
      }
    });
  }
  
  async checkURLChange(newURL) {
    this.redirectChain.push({
      url: newURL,
      timestamp: Date.now(),
      source: 'navigation'
    });
    
    if (this.redirectChain.length > 10) {
      this.redirectChain = this.redirectChain.slice(-10);
    }
    
    return true;
  }

  async checkRedirectURL(url, source) {
    if (this.blockedRedirects.has(url)) {
      return false;
    }
    
    const riskData = this.bogaGuard.calculateRisk(url);
    
    if (riskData.level > 0.5) {
      this.blockedRedirects.add(url);
      this.showRedirectWarning(url, riskData, source);
      return false;
    }
    
    return true;
  }

  detectSuspiciousRedirectPattern() {
    if (this.redirectChain.length < 3) return false;
    
    const recent = this.redirectChain.slice(-3);
    const timeSpan = recent[2].timestamp - recent[0].timestamp;
    
    if (timeSpan < 2000) {
      return true;
    }
    
    const domains = recent.map(r => {
      try {
        return new URL(r.url).hostname;
      } catch {
        return null;
      }
    }).filter(Boolean);
    
    const uniqueDomains = new Set(domains);
    if (uniqueDomains.size === domains.length) {
      return true;
    }
    
    return false;
  }

  blockRedirect(url, riskData) {
    window.stop();
    
    document.body.innerHTML = `
      <div class="lg-redirect-block">
        <div class="lg-redirect-content">
          <h1>🛡️ BogaGuard - Redirect Blocked</h1>
          <div class="lg-redirect-icon">🚫</div>
          <h2>Malicious redirect detected and blocked</h2>
          <p><strong>Attempted redirect to:</strong></p>
          <div class="lg-url-display">${url}</div>
          <p><strong>Threat Level:</strong> <span class="risk-high">${(riskData.level * 100).toFixed(0)}%</span></p>
          <div class="lg-threat-reasons">
            <strong>Detected threats:</strong>
            <ul>
              ${riskData.reasons.map(reason => `<li>${reason}</li>`).join('')}
            </ul>
          </div>
          <div class="lg-redirect-buttons">
            <button onclick="goBack()" class="lg-btn-safe">Go Back</button>
            <button onclick="closeTab()" class="lg-btn-danger">Close Tab</button>
            <button onclick="proceedAnyway('${url}')" class="lg-btn-warning">Proceed Anyway</button>
          </div>
          <p class="lg-redirect-footer">Protected by BogaGuard Anti-Redirect System</p>
        </div>
      </div>
    `;
    
    this.addRedirectBlockStyles();
    this.bogaGuard.threatCount++;
    this.bogaGuard.updateStats();
  }

  blockRedirectChain() {
    window.stop();
    
    document.body.innerHTML = `
      <div class="lg-redirect-block">
        <div class="lg-redirect-content">
          <h1>🛡️ BogaGuard - Redirect Chain Blocked</h1>
          <div class="lg-redirect-icon">🔄</div>
          <h2>Suspicious redirect pattern detected</h2>
          <p>Multiple rapid redirects detected - possible redirect attack</p>
          <div class="lg-redirect-chain">
            <strong>Redirect chain:</strong>
            ${this.redirectChain.slice(-5).map((r, i) => 
              `<div class="redirect-step">${i + 1}. ${r.url}</div>`
            ).join('')}
          </div>
          <div class="lg-redirect-buttons">
            <button onclick="goBack()" class="lg-btn-safe">Go Back</button>
            <button onclick="closeTab()" class="lg-btn-danger">Close Tab</button>
          </div>
          <p class="lg-redirect-footer">Protected by BogaGuard Anti-Redirect System</p>
        </div>
      </div>
    `;
    
    this.addRedirectBlockStyles();
    this.bogaGuard.threatCount++;
    this.bogaGuard.updateStats();
  }

  showRedirectWarning(url, riskData, source) {
    const warning = document.createElement('div');
    warning.className = 'lg-redirect-warning';
    warning.innerHTML = `
      <div class="lg-warning-content">
        <span class="lg-warning-icon">⚠️</span>
        <div class="lg-warning-text">
          <strong>Redirect blocked:</strong> ${riskData.category} detected
          <div class="lg-warning-url">${url}</div>
        </div>
        <button class="lg-warning-close" onclick="this.parentElement.parentElement.remove()">×</button>
      </div>
    `;
    
    document.body.appendChild(warning);
    
    setTimeout(() => {
      if (warning.parentElement) {
        warning.remove();
      }
    }, 5000);
  }

  addToWhitelist(hostname) {
    const whitelist = JSON.parse(localStorage.getItem('lg_whitelist') || '[]');
    if (!whitelist.includes(hostname)) {
      whitelist.push(hostname);
      localStorage.setItem('lg_whitelist', JSON.stringify(whitelist));
    }
  }
  
  isWhitelisted(hostname) {
    const whitelist = JSON.parse(localStorage.getItem('lg_whitelist') || '[]');
    return whitelist.includes(hostname);
  }
  
  addNavigationDialogStyles() {
    const style = document.createElement('style');
    style.textContent = `
      .lg-navigation-dialog {
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100% !important;
        height: 100% !important;
        background: rgba(0, 0, 0, 0.8) !important;
        z-index: 999999 !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
      }
      
      .lg-nav-dialog-content {
        background: white !important;
        padding: 30px !important;
        border-radius: 15px !important;
        max-width: 600px !important;
        max-height: 80vh !important;
        overflow-y: auto !important;
        box-shadow: 0 20px 40px rgba(0,0,0,0.3) !important;
      }
      
      .lg-nav-url {
        background: #f5f5f5 !important;
        padding: 10px !important;
        border-radius: 5px !important;
        font-family: monospace !important;
        word-break: break-all !important;
        margin: 10px 0 !important;
      }
      
      .lg-nav-reasons {
        background: #fff3cd !important;
        padding: 15px !important;
        border-radius: 5px !important;
        margin: 15px 0 !important;
        border-left: 4px solid #ffc107 !important;
      }
      
      .lg-nav-buttons {
        display: flex !important;
        gap: 10px !important;
        justify-content: center !important;
        margin: 20px 0 !important;
        flex-wrap: wrap !important;
      }
      
      .lg-nav-buttons button {
        padding: 12px 20px !important;
        border: none !important;
        border-radius: 8px !important;
        cursor: pointer !important;
        font-weight: bold !important;
        font-size: 14px !important;
      }
    `;
    document.head.appendChild(style);
  }
  
  addRedirectBlockStyles() {
    const style = document.createElement('style');
    style.textContent = `
      .lg-redirect-block {
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100% !important;
        height: 100% !important;
        background: linear-gradient(135deg, #ff6b6b, #ee5a24) !important;
        z-index: 999999 !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
      }
      
      .lg-redirect-content {
        background: white !important;
        padding: 40px !important;
        border-radius: 15px !important;
        text-align: center !important;
        box-shadow: 0 20px 40px rgba(0,0,0,0.3) !important;
        max-width: 600px !important;
        max-height: 80vh !important;
        overflow-y: auto !important;
      }
      
      .lg-redirect-icon {
        font-size: 80px !important;
        margin: 20px 0 !important;
      }
      
      .lg-url-display {
        background: #f5f5f5 !important;
        padding: 10px !important;
        border-radius: 5px !important;
        font-family: monospace !important;
        word-break: break-all !important;
        margin: 10px 0 !important;
      }
      
      .lg-redirect-chain {
        text-align: left !important;
        margin: 20px 0 !important;
        background: #f9f9f9 !important;
        padding: 15px !important;
        border-radius: 5px !important;
      }
      
      .redirect-step {
        margin: 5px 0 !important;
        font-family: monospace !important;
        font-size: 12px !important;
      }
      
      .lg-threat-reasons {
        text-align: left !important;
        margin: 20px 0 !important;
      }
      
      .lg-redirect-warning {
        position: fixed !important;
        top: 20px !important;
        right: 20px !important;
        background: #ff9800 !important;
        color: white !important;
        padding: 15px !important;
        border-radius: 8px !important;
        z-index: 999998 !important;
        max-width: 400px !important;
        box-shadow: 0 4px 12px rgba(0,0,0,0.2) !important;
      }
      
      .lg-warning-content {
        display: flex !important;
        align-items: center !important;
        gap: 10px !important;
      }
      
      .lg-warning-close {
        background: none !important;
        border: none !important;
        color: white !important;
        font-size: 18px !important;
        cursor: pointer !important;
        margin-left: auto !important;
      }
    `;
    document.head.appendChild(style);
  }

  getRedirectStats() {
    return {
      redirectsMonitored: this.redirectChain.length,
      redirectsBlocked: this.blockedRedirects.size,
      recentRedirects: this.redirectChain.slice(-5)
    };
  }
}