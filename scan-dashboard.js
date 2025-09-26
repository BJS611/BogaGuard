// LinkGuard Scan Dashboard Script
class ScanDashboard {
  constructor() {
    this.data = {
      threats: [],
      redirects: [],
      contentAnalysis: [],
      mlInsights: [],
      timeline: []
    };
    
    this.init();
  }

  init() {
    this.loadData();
    this.setupAutoRefresh();
    this.renderDashboard();
  }

  loadData() {
    // Get data from extension storage
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.get([
        'lg_threats', 'lg_redirects', 'lg_content', 'lg_ml', 'lg_timeline', 'lg_stats'
      ], (result) => {
        this.data.threats = result.lg_threats || [];
        this.data.redirects = result.lg_redirects || [];
        this.data.contentAnalysis = result.lg_content || [];
        this.data.mlInsights = result.lg_ml || [];
        this.data.timeline = result.lg_timeline || [];
        this.stats = result.lg_stats || {};
        
        this.renderDashboard();
      });
    } else {
      // Fallback with sample data for testing
      this.data = {
        threats: [
          {
            url: 'https://fake-scam-site.tk/malicious',
            timestamp: Date.now() - 300000,
            risk: 0.9,
            category: 'scam',
            level: 'high',
            reasons: ['Prize scam detected', 'Suspicious domain', 'Fake survey']
          }
        ],
        redirects: [
          {
            url: 'https://redirect-chain.com/step1',
            timestamp: Date.now() - 600000,
            type: 'redirect',
            source: 'javascript',
            blocked: true
          }
        ],
        contentAnalysis: [
          {
            domain: 'test-content-analysis.com',
            timestamp: Date.now() - 900000,
            score: 0.7,
            threats: ['Fake urgency language', 'Credential harvesting form']
          }
        ],
        mlInsights: [
          {
            totalAnalyzed: 150,
            patternsLearned: 25,
            accuracy: 0.92,
            recentThreats: 8,
            newPatterns: ['scam-survey', 'fake-prize', 'crypto-investment']
          }
        ],
        timeline: [
          {
            type: 'threat',
            title: 'High Risk Site Blocked',
            description: 'Automatically blocked scam survey site',
            timestamp: Date.now() - 180000
          }
        ]
      };
      this.stats = {
        threatsBlocked: 12,
        linksScanned: 450,
        contentScore: 0.15,
        mlPatterns: 25,
        redirectsBlocked: 3
      };
      
      this.renderDashboard();
    }
  }

  renderDashboard() {
    this.renderStats();
    this.renderThreats();
    this.renderRedirects();
    this.renderContentAnalysis();
    this.renderMLInsights();
    this.renderTimeline();
  }

  renderStats() {
    document.getElementById('total-threats').textContent = this.data.threats.length;
    document.getElementById('links-scanned').textContent = this.stats.linksScanned || 0;
    document.getElementById('content-score').textContent = 
      ((this.stats.contentScore || 0) * 100).toFixed(0) + '%';
    document.getElementById('ml-patterns').textContent = this.stats.mlPatterns || 0;
  }

  renderThreats() {
    const container = document.getElementById('threats-list');
    
    if (this.data.threats.length === 0) {
      container.innerHTML = '<div class="empty-state"><p>No threats detected yet. LinkGuard is actively monitoring...</p></div>';
      return;
    }

    container.innerHTML = this.data.threats.map(threat => `
      <div class="threat-item threat-${threat.level}">
        <div class="threat-header">
          <strong>${this.getThreatIcon(threat.category)} ${threat.category.toUpperCase()}</strong>
          <span style="color: ${this.getRiskColor(threat.risk)}; font-weight: bold;">
            ${(threat.risk * 100).toFixed(0)}% Risk
          </span>
        </div>
        <div class="threat-url">${threat.url}</div>
        ${threat.reasons && threat.reasons.length > 0 ? `
          <div class="threat-reasons">
            <strong>Detected Issues:</strong>
            <ul>
              ${threat.reasons.map(reason => `<li>${reason}</li>`).join('')}
            </ul>
          </div>
        ` : ''}
        <div style="font-size: 12px; opacity: 0.7; margin-top: 10px;">
          Detected: ${new Date(threat.timestamp).toLocaleString()}
        </div>
      </div>
    `).join('');
  }

  renderRedirects() {
    const container = document.getElementById('redirects-list');
    
    if (this.data.redirects.length === 0) {
      container.innerHTML = '<div class="empty-state"><p>No redirects monitored yet.</p></div>';
      return;
    }

    container.innerHTML = this.data.redirects.map(redirect => `
      <div class="threat-item">
        <div class="threat-header">
          <strong>🔄 ${redirect.type.toUpperCase()}</strong>
          <span style="color: ${redirect.blocked ? '#ff4444' : '#4caf50'};">
            ${redirect.blocked ? 'BLOCKED' : 'ALLOWED'}
          </span>
        </div>
        <div class="threat-url">${redirect.url}</div>
        <div style="font-size: 12px; opacity: 0.7; margin-top: 10px;">
          Source: ${redirect.source} | ${new Date(redirect.timestamp).toLocaleString()}
        </div>
      </div>
    `).join('');
  }

  renderContentAnalysis() {
    const container = document.getElementById('content-analysis');
    
    if (this.data.contentAnalysis.length === 0) {
      container.innerHTML = '<div class="empty-state"><p>No content analysis performed yet.</p></div>';
      return;
    }

    container.innerHTML = this.data.contentAnalysis.map(analysis => `
      <div class="threat-item">
        <div class="threat-header">
          <strong>📄 ${analysis.domain}</strong>
          <span style="color: ${this.getRiskColor(analysis.score)}; font-weight: bold;">
            ${(analysis.score * 100).toFixed(0)}% Risk
          </span>
        </div>
        ${analysis.threats && analysis.threats.length > 0 ? `
          <div class="threat-reasons">
            <strong>Content Issues:</strong>
            <ul>
              ${analysis.threats.map(threat => `<li>${threat}</li>`).join('')}
            </ul>
          </div>
        ` : ''}
        <div style="font-size: 12px; opacity: 0.7; margin-top: 10px;">
          Analyzed: ${new Date(analysis.timestamp).toLocaleString()}
        </div>
      </div>
    `).join('');
  }

  renderMLInsights() {
    const container = document.getElementById('ml-insights');
    
    if (this.data.mlInsights.length === 0) {
      container.innerHTML = '<div class="empty-state"><p>AI is learning from your browsing patterns...</p></div>';
      return;
    }

    const latestInsight = this.data.mlInsights[this.data.mlInsights.length - 1];
    
    container.innerHTML = `
      <div class="threat-item">
        <div class="threat-header">
          <strong>🤖 Learning Statistics</strong>
          <span style="color: #4caf50;">Active</span>
        </div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0;">
          <div>
            <strong>Total Analyzed:</strong> ${latestInsight.totalAnalyzed || 0}
          </div>
          <div>
            <strong>Patterns Learned:</strong> ${latestInsight.patternsLearned || 0}
          </div>
          <div>
            <strong>Accuracy:</strong> ${((latestInsight.accuracy || 0) * 100).toFixed(1)}%
          </div>
          <div>
            <strong>Recent Threats:</strong> ${latestInsight.recentThreats || 0}
          </div>
        </div>
        ${latestInsight.newPatterns && latestInsight.newPatterns.length > 0 ? `
          <div class="threat-reasons">
            <strong>Recently Learned Patterns:</strong>
            <div class="ml-patterns">
              ${latestInsight.newPatterns.map(pattern => `
                <div class="pattern-item">${pattern}</div>
              `).join('')}
            </div>
          </div>
        ` : ''}
      </div>
    `;
  }

  renderTimeline() {
    const container = document.getElementById('activity-timeline');
    
    if (this.data.timeline.length === 0) {
      container.innerHTML = '<div class="empty-state"><p>Activity timeline will appear here...</p></div>';
      return;
    }

    // Sort timeline by timestamp (newest first)
    const sortedTimeline = [...this.data.timeline].sort((a, b) => b.timestamp - a.timestamp);
    
    container.innerHTML = sortedTimeline.slice(0, 20).map(item => `
      <div class="timeline-item">
        <div style="font-weight: bold; margin-bottom: 5px;">
          ${this.getTimelineIcon(item.type)} ${item.title}
        </div>
        <div style="font-size: 14px; opacity: 0.8; margin-bottom: 5px;">
          ${item.description}
        </div>
        <div style="font-size: 12px; opacity: 0.6;">
          ${new Date(item.timestamp).toLocaleString()}
        </div>
      </div>
    `).join('');
  }

  getThreatIcon(category) {
    const icons = {
      'scam': '🎁',
      'gambling': '🎰',
      'adult': '🔞',
      'phishing': '⚠️',
      'malware': '🦠',
      'suspicious': '❓'
    };
    return icons[category] || '⚠️';
  }

  getRiskColor(risk) {
    if (risk > 0.7) return '#ff4444';
    if (risk > 0.4) return '#ffa500';
    return '#4caf50';
  }

  getTimelineIcon(type) {
    const icons = {
      'threat': '🚨',
      'redirect': '🔄',
      'content': '📄',
      'ml': '🤖',
      'block': '🛡️',
      'allow': '✅'
    };
    return icons[type] || '📝';
  }

  setupAutoRefresh() {
    // Refresh every 5 seconds
    setInterval(() => {
      this.loadData();
    }, 5000);
  }

  exportData() {
    const exportData = {
      timestamp: new Date().toISOString(),
      stats: this.stats,
      threats: this.data.threats,
      redirects: this.data.redirects,
      contentAnalysis: this.data.contentAnalysis,
      mlInsights: this.data.mlInsights,
      timeline: this.data.timeline
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], {
      type: 'application/json'
    });
    
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `linkguard-report-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  clearData() {
    if (confirm('Are you sure you want to clear all scan data? This cannot be undone.')) {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.clear(() => {
          this.data = {
            threats: [],
            redirects: [],
            contentAnalysis: [],
            mlInsights: [],
            timeline: []
          };
          this.stats = {};
          this.renderDashboard();
          alert('All data cleared successfully.');
        });
      } else {
        // Fallback for testing
        this.data = {
          threats: [],
          redirects: [],
          contentAnalysis: [],
          mlInsights: [],
          timeline: []
        };
        this.stats = {};
        this.renderDashboard();
        alert('Data cleared (test mode)');
      }
    }
  }
}

// Global functions for buttons
function refreshData() {
  const icon = document.getElementById('refresh-icon');
  icon.classList.add('refresh-indicator');
  
  if (window.dashboard) {
    window.dashboard.loadData();
  }
  
  setTimeout(() => {
    icon.classList.remove('refresh-indicator');
  }, 1000);
}

function exportData() {
  if (window.dashboard) {
    window.dashboard.exportData();
  }
}

function clearData() {
  if (window.dashboard) {
    window.dashboard.clearData();
  }
}

// Fix button functionality
function goBack() {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.close();
  }
}

function closeTab() {
  window.close();
}

function proceedAnyway(url) {
  window.location.href = url;
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', () => {
  window.dashboard = new ScanDashboard();
});