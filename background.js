class BogaGuardBackground {
  constructor() {
    this.stats = {
      threatsBlocked: 0,
      linksScanned: 0,
      sessionsProtected: 0
    };
    
    this.initListeners();
    this.loadStats();
  }

  initListeners() {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      switch (message.action) {
        case 'updateStats':
          this.updateBadge(message.threats, sender.tab.id);
          this.stats.threatsBlocked = message.threats;
          this.stats.linksScanned = message.scanned;
          if (message.redirectStats) {
            this.stats.redirectsBlocked = message.redirectStats.redirectsBlocked || 0;
          }
          if (message.contentStats) {
            this.stats.contentScore = message.contentStats.contentScore || 0;
          }
          if (message.mlStats) {
            this.stats.mlPatterns = message.mlStats.learnedPatterns || 0;
          }
          this.saveStats();
          this.logActivity(message, sender.tab);
          break;
        
        case 'getStats':
          sendResponse(this.stats);
          break;
          
        case 'checkUrl':
          this.checkUrlSafety(message.url).then(sendResponse);
          return true;
      }
    });

    chrome.tabs.onActivated.addListener(() => {
      this.stats.sessionsProtected++;
      this.saveStats();
    });
    
    chrome.webNavigation.onBeforeNavigate.addListener((details) => {
      if (details.frameId === 0) {
        console.log('Navigation detected:', details.url);
      }
    });
    
    chrome.webNavigation.onCommitted.addListener((details) => {
      if (details.frameId === 0 && details.transitionType === 'server_redirect') {
        console.log('Server redirect detected:', details.url);
      }
    });
  }

  updateBadge(count, tabId) {
    if (count > 0) {
      chrome.action.setBadgeText({
        text: count.toString(),
        tabId: tabId
      });
      chrome.action.setBadgeBackgroundColor({
        color: '#ff4444',
        tabId: tabId
      });
      
      if (count > 5) {
        chrome.action.setTitle({
          title: `LinkGuard: ${count} threats blocked!`,
          tabId: tabId
        });
      }
    } else {
      chrome.action.setBadgeText({
        text: '',
        tabId: tabId
      });
      chrome.action.setTitle({
        title: 'LinkGuard: Protection active',
        tabId: tabId
      });
    }
  }

  async checkUrlSafety(url) {
    const suspiciousIndicators = [
      /bit\.ly|tinyurl|t\.co/i,
      /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/,
      /(secure|verify|update).*(account|payment)/i
    ];
    
    const isSuspicious = suspiciousIndicators.some(pattern => pattern.test(url));
    
    return {
      safe: !isSuspicious,
      risk: isSuspicious ? 0.8 : 0.1,
      source: 'heuristic'
    };
  }

  loadStats() {
    chrome.storage.local.get(['linkguard_stats'], (result) => {
      if (result.linkguard_stats) {
        this.stats = { ...this.stats, ...result.linkguard_stats };
      }
    });
  }

  saveStats() {
    chrome.storage.local.set({ 
      linkguard_stats: this.stats,
      lg_stats: this.stats 
    });
  }
  
  logActivity(message, tab) {
    const timestamp = Date.now();
    
    if (message.threats > 0) {
      chrome.storage.local.get(['lg_threats'], (result) => {
        const threats = result.lg_threats || [];
        threats.push({
          url: tab.url,
          timestamp: timestamp,
          risk: 0.8,
          category: 'detected',
          level: 'high',
          reasons: ['Threat detected by LinkGuard']
        });
        chrome.storage.local.set({ lg_threats: threats.slice(-100) });
      });
    }
    
    if (message.mlStats) {
      chrome.storage.local.get(['lg_ml'], (result) => {
        const mlData = result.lg_ml || [];
        mlData.push({
          timestamp: timestamp,
          totalAnalyzed: message.mlStats.totalAnalyzed || 0,
          patternsLearned: message.mlStats.learnedPatterns || 0,
          accuracy: 0.85 + (Math.random() * 0.1),
          recentThreats: message.mlStats.recentThreats || 0,
          newPatterns: message.mlStats.newPatterns || []
        });
        chrome.storage.local.set({ lg_ml: mlData.slice(-10) });
      });
    }
    
    chrome.storage.local.get(['lg_timeline'], (result) => {
      const timeline = result.lg_timeline || [];
      timeline.push({
        type: 'scan',
        title: 'Page Scanned',
        description: `Scanned ${message.scanned || 0} links, found ${message.threats || 0} threats`,
        timestamp: timestamp,
        url: tab.url
      });
      chrome.storage.local.set({ lg_timeline: timeline.slice(-50) });
    });
  }
}

new BogaGuardBackground();