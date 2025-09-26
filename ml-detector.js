class MLDetector {
  constructor() {
    this.negativeKeywords = new Set();
    this.positiveKeywords = new Set();
    this.suspiciousPatterns = new Map();
    this.learningData = [];
    
    this.initializeBaseLearning();
  }

  initializeBaseLearning() {
    const negativeSeeds = [
      'scam', 'fraud', 'fake', 'phishing', 'malware', 'virus',
      'gambling', 'casino', 'bet', 'porn', 'adult', 'nude',
      'free', 'win', 'prize', 'survey', 'claim', 'urgent',
      'limited', 'expires', 'congratulations', 'winner'
    ];
    
    const positiveSeeds = [
      'official', 'secure', 'verified', 'government', 'bank',
      'education', 'news', 'help', 'support', 'contact'
    ];
    
    negativeSeeds.forEach(word => this.negativeKeywords.add(word.toLowerCase()));
    positiveSeeds.forEach(word => this.positiveKeywords.add(word.toLowerCase()));
    
    this.loadLearningData();
  }

  analyzeURL(url) {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname.toLowerCase();
      const path = urlObj.pathname.toLowerCase();
      const params = urlObj.search.toLowerCase();
      const fullUrl = url.toLowerCase();
      
      let suspicionScore = 0;
      let indicators = [];
      
      const domainScore = this.analyzeDomain(domain);
      suspicionScore += domainScore.score;
      indicators.push(...domainScore.indicators);
      
      const pathScore = this.analyzePath(path);
      suspicionScore += pathScore.score;
      indicators.push(...pathScore.indicators);
      
      const paramScore = this.analyzeParameters(params);
      suspicionScore += paramScore.score;
      indicators.push(...paramScore.indicators);
      
      const contentScore = this.analyzeContent(fullUrl);
      suspicionScore += contentScore.score;
      indicators.push(...contentScore.indicators);
      
      this.updateLearning(fullUrl, suspicionScore, indicators);
      
      return {
        score: Math.min(suspicionScore, 1.0),
        indicators: indicators,
        category: this.categorizeContent(indicators)
      };
      
    } catch (e) {
      return { score: 0.3, indicators: ['Invalid URL'], category: 'unknown' };
    }
  }

  analyzeDomain(domain) {
    let score = 0;
    let indicators = [];
    
    if (domain.length > 25) {
      score += 0.2;
      indicators.push('Long domain name');
    }
    
    const subdomains = domain.split('.').length - 2;
    if (subdomains > 2) {
      score += 0.15;
      indicators.push('Multiple subdomains');
    }
    
    if (/\.(tk|ml|ga|cf|pw|top|click|download|zip)$/.test(domain)) {
      score += 0.3;
      indicators.push('Suspicious TLD');
    }
    
    if (/\d{3,}/.test(domain)) {
      score += 0.1;
      indicators.push('Many numbers in domain');
    }
    
    if ((domain.match(/-/g) || []).length > 2) {
      score += 0.15;
      indicators.push('Excessive hyphens');
    }
    
    if (/[^\x00-\x7F]/.test(domain)) {
      score += 0.25;
      indicators.push('Non-ASCII characters');
    }
    
    return { score, indicators };
  }

  analyzePath(path) {
    let score = 0;
    let indicators = [];
    
    const suspiciousPaths = [
      /\/(login|secure|verify|update|confirm)/,
      /\/(claim|prize|winner|survey|free)/,
      /\/(download|install|setup|exe)/,
      /\/[a-z0-9]{20,}/  // Random strings
    ];
    
    suspiciousPaths.forEach(pattern => {
      if (pattern.test(path)) {
        score += 0.2;
        indicators.push('Suspicious path pattern');
      }
    });
    
    return { score, indicators };
  }

  analyzeParameters(params) {
    let score = 0;
    let indicators = [];
    
    if (!params) return { score, indicators };
    
    if (/[?&](utm_|ref|affiliate|track|click)/.test(params)) {
      score += 0.1;
      indicators.push('Tracking parameters');
    }
    
    if (/[?&](s|ssk|var|ymid|z)=\d+/.test(params)) {
      score += 0.3;
      indicators.push('Scam-like parameters');
    }
    
    if (/expires?=\d+/.test(params)) {
      score += 0.2;
      indicators.push('Expiration parameter');
    }
    
    return { score, indicators };
  }

  analyzeContent(fullUrl) {
    let score = 0;
    let indicators = [];
    
    const words = fullUrl.match(/[a-z]+/gi) || [];
    const wordCount = words.length;
    let negativeCount = 0;
    let positiveCount = 0;
    
    words.forEach(word => {
      const lowerWord = word.toLowerCase();
      if (this.negativeKeywords.has(lowerWord)) {
        negativeCount++;
      }
      if (this.positiveKeywords.has(lowerWord)) {
        positiveCount++;
      }
    });
    
    if (wordCount > 0) {
      const negativeRatio = negativeCount / wordCount;
      const positiveRatio = positiveCount / wordCount;
      
      if (negativeRatio > 0.1) {
        score += negativeRatio * 2;
        indicators.push('High negative keyword density');
      }
      
      if (positiveRatio > 0.1) {
        score -= positiveRatio;
        indicators.push('Positive keywords detected');
      }
    }
    
    const learnedScore = this.matchLearnedPatterns(fullUrl);
    score += learnedScore.score;
    indicators.push(...learnedScore.indicators);
    
    return { score, indicators };
  }

  matchLearnedPatterns(url) {
    let score = 0;
    let indicators = [];
    
    for (let [pattern, data] of this.suspiciousPatterns) {
      if (url.includes(pattern)) {
        score += data.weight;
        indicators.push(`Learned pattern: ${pattern}`);
      }
    }
    
    return { score, indicators };
  }

  categorizeContent(indicators) {
    const indicatorText = indicators.join(' ').toLowerCase();
    
    if (/gambling|casino|bet|judi|slot|poker/.test(indicatorText)) {
      return 'gambling';
    }
    if (/adult|porn|sex|nude/.test(indicatorText)) {
      return 'adult';
    }
    if (/scam|survey|prize|winner|claim/.test(indicatorText)) {
      return 'scam';
    }
    if (/phishing|fake|fraud|malware/.test(indicatorText)) {
      return 'phishing';
    }
    
    return 'suspicious';
  }

  updateLearning(url, score, indicators) {
    // Store learning data
    this.learningData.push({
      url: url,
      score: score,
      indicators: indicators,
      timestamp: Date.now()
    });
    
    // Extract patterns for future detection
    if (score > 0.6) {
      const words = url.match(/[a-z]{3,}/gi) || [];
      words.forEach(word => {
        const lowerWord = word.toLowerCase();
        if (lowerWord.length > 3) {
          this.negativeKeywords.add(lowerWord);
          
          // Update pattern weights
          if (this.suspiciousPatterns.has(lowerWord)) {
            const existing = this.suspiciousPatterns.get(lowerWord);
            existing.weight += 0.05;
            existing.count += 1;
          } else {
            this.suspiciousPatterns.set(lowerWord, { weight: 0.1, count: 1 });
          }
        }
      });
    }
    
    // Learn from indicators
    if (indicators && indicators.length > 0) {
      indicators.forEach(indicator => {
        const words = indicator.match(/[a-z]{3,}/gi) || [];
        words.forEach(word => {
          const lowerWord = word.toLowerCase();
          if (lowerWord.length > 3) {
            this.negativeKeywords.add(lowerWord);
          }
        });
      });
    }
    
    // Limit learning data size
    if (this.learningData.length > 1000) {
      this.learningData = this.learningData.slice(-500);
    }
    
    // Save learning progress
    this.saveLearningData();
  }

  analyzePageContent(content) {
    if (!content) return { score: 0, indicators: [] };
    
    const text = content.toLowerCase();
    let score = 0;
    let indicators = [];
    
    const urgencyWords = ['urgent', 'limited time', 'expires', 'hurry', 'act now'];
    urgencyWords.forEach(word => {
      if (text.includes(word)) {
        score += 0.15;
        indicators.push('Urgency language detected');
      }
    });
    
    const moneyWords = ['free money', 'win cash', 'guaranteed profit', 'easy money'];
    moneyWords.forEach(word => {
      if (text.includes(word)) {
        score += 0.2;
        indicators.push('Money/prize language');
      }
    });
    
    if (/enter.*(password|credit card|ssn|bank|account)/.test(text)) {
      score += 0.4;
      indicators.push('Requests sensitive information');
    }
    
    return { score, indicators };
  }

  saveLearningData() {
    try {
      const learningState = {
        negativeKeywords: Array.from(this.negativeKeywords),
        suspiciousPatterns: Array.from(this.suspiciousPatterns.entries()),
        learningData: this.learningData.slice(-100) // Keep last 100
      };
      
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.set({ lg_ml_learning: learningState });
      }
    } catch (e) {
      console.log('Could not save learning data:', e);
    }
  }
  
  loadLearningData() {
    try {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get(['lg_ml_learning'], (result) => {
          if (result.lg_ml_learning) {
            const state = result.lg_ml_learning;
            
            // Restore keywords
            if (state.negativeKeywords) {
              state.negativeKeywords.forEach(keyword => {
                this.negativeKeywords.add(keyword);
              });
            }
            
            // Restore patterns
            if (state.suspiciousPatterns) {
              state.suspiciousPatterns.forEach(([pattern, data]) => {
                this.suspiciousPatterns.set(pattern, data);
              });
            }
            
            // Restore learning data
            if (state.learningData) {
              this.learningData = state.learningData;
            }
          }
        });
      }
    } catch (e) {
      console.log('Could not load learning data:', e);
    }
  }
  
  getLearningStats() {
    return {
      totalAnalyzed: this.learningData.length,
      negativeKeywords: this.negativeKeywords.size,
      learnedPatterns: this.suspiciousPatterns.size,
      recentThreats: this.learningData.filter(d => d.score > 0.6).length,
      newPatterns: Array.from(this.suspiciousPatterns.keys()).slice(-10)
    };
  }
}