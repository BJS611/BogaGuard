class BogaGuard {
  constructor() {
    this.mlDetector = new MLDetector();
    this.redirectMonitor = null;
    this.contentAnalyzer = null;
    this.suspiciousPatterns = [
      /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly/i,
      /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/,
      /[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.(tk|ml|ga|cf)/i,
      /(secure|verify|update|confirm).*(account|payment|login)/i,
      /[a-z]{20,}\.(com|net|org)/i
    ];
    
    // Gambling patterns (ASEAN-wide)
    this.gamblingPatterns = [
      // English/International
      /(slot|poker|casino|bet|betting|lottery|jackpot|bonus)/i,
      /(maxwin|gacor|withdraw|deposit|toto|naga|pragmatic)/i,
      // Indonesian
      /(judi|taruhan|togel|bola|sbobet|bandar|agen|daftar)/i,
      // Thai
      /(การพนัน|เดิมพัน|คาสิโน|สล็อต|หวย|บาคาร่า)/i,
      // Vietnamese  
      /(cờ bạc|đánh bạc|casino|xổ số|baccarat|poker)/i,
      // Malay/Malaysian
      /(judi|pertaruhan|kasino|loteri|bola|4d|toto)/i,
      // Filipino
      /(sugal|pustahan|casino|lotto|sabong|bingo)/i,
      // Burmese
      /(လောင်းကစား|ကစားခန်း)/i,
      // Numeric patterns
      /\b(88|777|999|168|303|888|4d|6d)\w*\.(com|net|org|id|th|vn|my|ph|sg)/i,
      /(nagatoto|nagaslot|totoslot|slottoto|bolatangkas)/i,
      /\b\d{2,4}(slot|toto|bet|win|4d)\b/i,
      /(rahasia|tips|cara).*(keberuntungan|hoki|rejeki|nasib)/i,
      /(logo|visual|simbol).*(membawa|mendatangkan).*(keberuntungan|hoki)/i,
      /(feng.?shui|numerologi|ramalan).*(angka|nomor|digit)/i,
      /(mistis|gaib|spiritual).*(kekuatan|energi|aura)/i,
      /(tersembunyi|rahasia).*(balik|dibalik).*(logo|visual)/i
    ];
    
    // Adult content patterns (ASEAN-wide)
    this.adultPatterns = [
      // English/International
      /(porn|xxx|sex|adult|nude|naked|erotic|mature|nsfw)/i,
      /(xnxx|pornhub|xvideos|redtube|onlyfans)/i,
      // Indonesian
      /(bokep|ngentot|memek|kontol|telanjang|bugil)/i,
      // Thai
      /(โป๊|เซ็กส์|ผู้ใหญ่|เปลือย)/i,
      // Vietnamese
      /(khiêu dâm|sex|người lớn|khỏa thân)/i,
      // Malay/Malaysian
      /(lucah|seks|dewasa|bogel)/i,
      // Filipino
      /(bastos|libog|hubad|matanda)/i,
      // Age restrictions
      /\b(18\+|21\+|mature|nsfw|adults?[_\s]?only)\b/i
    ];
    
    // Scam survey/prize patterns (ASEAN-wide)
    this.scamPatterns = [
      // English/International
      /(survey|sweeps|prize|winner|congratulations|claim|gift|reward|free)/i,
      /(iphone|samsung|xiaomi|oppo|vivo|huawei|realme)/i,
      /(aucey|prizelogic|rewardzone|giftcenter|surveymonkey)/i,
      // Indonesian
      /\b(hp|handphone).*(gratis|hadiah|menang)/i,
      /(selamat|klaim).*(menang|hadiah|prize)/i,
      // Thai
      /(แบบสำรวจ|รางวัล|ชนะ|ฟรี|ได้รับ|โทรศัพท์)/i,
      /(ยินดี|แจ้ง|รับรางวัล)/i,
      // Vietnamese
      /(khảo sát|giải thưởng|chiến thắng|miễn phí|điện thoại)/i,
      /(chúc mừng|nhận thưởng|quà tặng)/i,
      // Malay/Malaysian
      /(tinjauan|hadiah|menang|percuma|telefon)/i,
      /(tahniah|tuntut|terima)/i,
      // Filipino
      /(survey|premyo|panalo|libre|telepono)/i,
      /(congratulations|kunin|tanggap)/i,
      // URL patterns
      /expires?=\d+/i,
      /[?&](s|ssk|var|ymid|z|ref|utm)=\d+/i,
      /(news|berita|artikel).*(keberuntungan|hoki|rejeki)/i,
      /(jkumar|kumar|news).*(rahasia|tersembunyi)/i,
      /\.com\/news\/.*(keberuntungan|hoki|logo|visual)/i
    ];
    
    this.trustedDomains = [
      // Global trusted
      'google.com', 'github.com', 'stackoverflow.com', 'wikipedia.org',
      'facebook.com', 'youtube.com', 'twitter.com', 'linkedin.com',
      // ASEAN government/official
      'gov.sg', 'gov.my', 'go.th', 'gov.vn', 'gov.ph', 'gov.id',
      'moh.gov.sg', 'moh.gov.my', 'doh.gov.ph',
      // ASEAN banks
      'dbs.com', 'maybank.com', 'bca.co.id', 'bni.co.id',
      'kasikornbank.com', 'scb.co.th', 'vietcombank.com.vn',
      // ASEAN e-commerce
      'shopee.sg', 'shopee.my', 'shopee.co.th', 'shopee.vn', 'shopee.ph', 'shopee.co.id',
      'lazada.sg', 'lazada.com.my', 'lazada.co.th', 'lazada.vn', 'lazada.com.ph', 'lazada.co.id',
      'grab.com', 'gojek.com', 'foodpanda.com'
    ];
    this.checkedLinks = new Set();
    this.checkedUrls = new Set();
    this.threatCount = 0;
    this.scannedCount = 0;
    
    this.init();
  }

  init() {
    console.log('BogaGuard: Initializing...');
    this.checkCurrentPage();
    this.scanExistingLinks();
    this.observeNewLinks();
    this.initContentAnalyzer();
    this.initRedirectMonitor();
    this.updateStats();
  }
  
  initContentAnalyzer() {
    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        this.contentAnalyzer = new ContentAnalyzer(this);
        console.log('BogaGuard: Content analysis active');
      });
    } else {
      this.contentAnalyzer = new ContentAnalyzer(this);
      console.log('BogaGuard: Content analysis active');
    }
  }
  
  initRedirectMonitor() {
    this.redirectMonitor = new RedirectMonitor(this);
    console.log('BogaGuard: Redirect monitoring active');
  }

  checkCurrentPage() {
    const currentUrl = window.location.href;
    const currentDomain = window.location.hostname;
    
    // Check with ML detector first
    const mlResult = this.mlDetector.analyzeURL(currentUrl);
    
    if (mlResult.score > 0.8 || this.isBlockedSite(currentUrl, currentDomain)) {
      this.blockCurrentPage(currentUrl, mlResult);
      return;
    }
  }
  
  scanExistingLinks() {
    const links = document.querySelectorAll('a[href]');
    console.log(`LinkGuard: Found ${links.length} links to scan`);
    links.forEach(link => this.analyzeLink(link));
  }

  observeNewLinks() {
    const observer = new MutationObserver(mutations => {
      mutations.forEach(mutation => {
        mutation.addedNodes.forEach(node => {
          if (node.nodeType === 1) {
            const links = node.querySelectorAll ? node.querySelectorAll('a[href]') : [];
            links.forEach(link => this.analyzeLink(link));
          }
        });
      });
    });
    
    observer.observe(document.body, { childList: true, subtree: true });
  }

  analyzeLink(link) {
    const url = link.href;
    if (!url || this.checkedUrls.has(url)) return;
    
    this.checkedUrls.add(url);
    this.scannedCount++;
    
    const riskData = this.calculateRisk(url);
    
    // Auto-block high threat sites immediately
    if (riskData.level > 0.8) {
      this.blockHighThreatSite(url, riskData);
      return;
    }
    
    if (riskData.level > 0.6) {
      this.markAsThreat(link, riskData);
      this.threatCount++;
    } else if (riskData.level > 0.3) {
      this.markAsSuspicious(link);
    }
    
    // Feed data to ML for learning
    this.mlDetector.updateLearning(url, riskData.level, riskData.reasons);
    
    this.updateStats();
  }

  calculateRisk(url) {
    // Use ML detection first
    const mlResult = this.mlDetector.analyzeURL(url);
    
    let risk = mlResult.score;
    let category = mlResult.category;
    let reasons = [...mlResult.indicators];
    
    try {
      const domain = new URL(url).hostname.toLowerCase();
      const fullUrl = url.toLowerCase();
      
      // Check for scam surveys/prizes
      let scamCount = 0;
      this.scamPatterns.forEach(pattern => {
        if (pattern.test(fullUrl) || pattern.test(domain)) {
          scamCount++;
        }
      });
      
      if (scamCount >= 2) {
        risk += 0.9;
        category = 'scam';
        reasons.push('Scam survey/prize detected');
      }
      
      // Check for gambling content
      let gamblingCount = 0;
      this.gamblingPatterns.forEach(pattern => {
        if (pattern.test(fullUrl) || pattern.test(domain)) {
          gamblingCount++;
        }
      });
      
      if (gamblingCount >= 1) {
        risk += 0.8;
        category = 'gambling';
        reasons.push('Gambling/Judi content detected');
      }
      
      // Check for adult content
      this.adultPatterns.forEach(pattern => {
        if (pattern.test(fullUrl) || pattern.test(domain)) {
          risk += 0.9;
          category = 'adult';
          reasons.push('Adult/Pornographic content detected');
        }
      });
      
      // Check suspicious patterns
      this.suspiciousPatterns.forEach(pattern => {
        if (pattern.test(fullUrl)) {
          risk += 0.3;
          reasons.push('Suspicious URL pattern');
        }
      });
      
      // Trusted domains get negative risk
      if (this.trustedDomains.some(trusted => domain.includes(trusted))) {
        risk -= 0.5;
      }
      
      // ASEAN-specific suspicious TLDs
      if (/\.(tk|ml|ga|cf|pw|top|click|download)$/i.test(domain)) {
        risk += 0.3;
        reasons.push('Suspicious free domain');
      }
      
      // Suspicious domain characteristics
      if (domain.length > 30) {
        risk += 0.2;
        reasons.push('Unusually long domain');
      }
      if ((domain.match(/\./g) || []).length > 3) {
        risk += 0.2;
        reasons.push('Multiple subdomains');
      }
      if (/[0-9]/.test(domain) && !/github|google|shopee|lazada/.test(domain)) {
        risk += 0.1;
        reasons.push('Numbers in domain');
      }
      
      // Homograph attack detection (expanded for ASEAN)
      if (/[а-я]|[α-ω]|[ก-๙]|[ა-ჿ]/i.test(domain)) {
        risk += 0.4;
        reasons.push('Homograph attack detected');
      }
      
      // ASEAN crypto scam patterns
      if (/(bitcoin|crypto|binance|trading|forex|investment).*(profit|earn|money)/i.test(fullUrl)) {
        risk += 0.6;
        reasons.push('Crypto/Investment scam detected');
      }
      
    } catch (e) {
      risk += 0.3;
      reasons.push('Invalid URL structure');
    }
    
    // Combine ML results with pattern matching
    const finalRisk = Math.min(risk, 1);
    const finalCategory = this.determineFinalCategory(category, reasons);
    
    return {
      level: finalRisk,
      category: finalCategory,
      reasons: reasons,
      mlConfidence: mlResult.score
    };
  }
  
  determineFinalCategory(mlCategory, reasons) {
    const reasonText = reasons.join(' ').toLowerCase();
    
    // Override ML category if strong pattern matches found
    if (reasonText.includes('gambling') || reasonText.includes('judi')) {
      return 'gambling';
    }
    if (reasonText.includes('adult') || reasonText.includes('porn')) {
      return 'adult';
    }
    if (reasonText.includes('scam') || reasonText.includes('survey')) {
      return 'scam';
    }
    
    return mlCategory;
  }

  markAsThreat(link, riskData) {
    link.classList.add('lg-threat');
    link.setAttribute('data-lg-risk', riskData.level.toFixed(2));
    link.setAttribute('data-lg-category', riskData.category);
    
    const warning = document.createElement('span');
    warning.className = 'lg-warning';
    
    // Different icons for different threats
    if (riskData.category === 'scam') {
      warning.innerHTML = '🎁';
      warning.title = `Scam Survey/Prize Blocked: ${(riskData.level * 100).toFixed(0)}%`;
    } else if (riskData.category === 'gambling') {
      warning.innerHTML = '🎰';
      warning.title = `Gambling Site Blocked: ${(riskData.level * 100).toFixed(0)}%`;
    } else if (riskData.category === 'adult') {
      warning.innerHTML = '🔞';
      warning.title = `Adult Content Blocked: ${(riskData.level * 100).toFixed(0)}%`;
    } else {
      warning.innerHTML = '⚠️';
      warning.title = `Phishing Threat: ${(riskData.level * 100).toFixed(0)}%`;
    }
    
    link.parentNode.insertBefore(warning, link);
    
    link.addEventListener('click', (e) => {
      e.preventDefault();
      this.showThreatDialog(link.href, riskData);
    });
  }

  markAsSuspicious(link) {
    link.classList.add('lg-suspicious');
    link.title = 'LinkGuard: Potentially suspicious link';
  }

  isBlockedSite(url, domain) {
    const fullUrl = url.toLowerCase();
    const lowerDomain = domain.toLowerCase();
    
    // Check scam surveys
    let scamCount = 0;
    this.scamPatterns.forEach(pattern => {
      if (pattern.test(fullUrl) || pattern.test(lowerDomain)) {
        scamCount++;
      }
    });
    
    // Check gambling
    const isGambling = this.gamblingPatterns.some(pattern => 
      pattern.test(fullUrl) || pattern.test(lowerDomain)
    ) || (/jkumar\.com/i.test(lowerDomain) && /(keberuntungan|hoki)/i.test(fullUrl));
    
    // Check adult content
    const isAdult = this.adultPatterns.some(pattern => 
      pattern.test(fullUrl) || pattern.test(lowerDomain)
    );
    
    const isDisguisedGambling = /\/news\//i.test(fullUrl) && /(keberuntungan|hoki|rejeki|feng.?shui|numerologi|rahasia.*logo)/i.test(fullUrl);
    
    return scamCount >= 2 || isGambling || isAdult || isDisguisedGambling;
  }
  
  blockCurrentPage(url) {
    document.body.innerHTML = `
      <div class="lg-page-block">
        <div class="lg-block-content">
          <h1>🛡️ BogaGuard - Site Blocked</h1>
          <div class="lg-block-icon">🚫</div>
          <h2>This website has been blocked</h2>
          <p>LinkGuard has detected that this site contains:</p>
          <ul>
            <li>🎁 Scam Survey/Prize content</li>
            <li>🎰 Gambling content (Judi/การพนัน/Cờ bạc/Sugal)</li>
            <li>🔞 Adult content (18+/โป๊/Khiêu dâm/Lucah)</li>
            <li>💰 Crypto/Investment scam</li>
            <li>⚠️ Potentially harmful content</li>
          </ul>
          <div class="lg-block-buttons">
            <button onclick="history.back()" class="lg-btn-safe">Go Back</button>
            <button onclick="window.close()" class="lg-btn-danger">Close Tab</button>
          </div>
          <p class="lg-block-footer">Protected by BogaGuard Extension</p>
        </div>
      </div>
    `;
    
    // Add blocking styles
    const style = document.createElement('style');
    style.textContent = `
      .lg-page-block {
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100% !important;
        height: 100% !important;
        background: linear-gradient(135deg, #ff4444, #cc0000) !important;
        z-index: 999999 !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
      }
      .lg-block-content {
        background: white !important;
        padding: 40px !important;
        border-radius: 15px !important;
        text-align: center !important;
        box-shadow: 0 20px 40px rgba(0,0,0,0.3) !important;
        max-width: 500px !important;
      }
      .lg-block-icon {
        font-size: 80px !important;
        margin: 20px 0 !important;
      }
      .lg-block-buttons {
        margin: 30px 0 !important;
      }
      .lg-btn-safe, .lg-btn-danger {
        padding: 12px 24px !important;
        margin: 0 10px !important;
        border: none !important;
        border-radius: 8px !important;
        cursor: pointer !important;
        font-weight: bold !important;
      }
      .lg-btn-safe {
        background: #4CAF50 !important;
        color: white !important;
      }
      .lg-btn-danger {
        background: #f44336 !important;
        color: white !important;
      }
    `;
    document.head.appendChild(style);
    
    this.threatCount++;
    this.updateStats();
  }
  
  showThreatDialog(url, riskData) {
    const dialog = document.createElement('div');
    dialog.className = 'lg-dialog';
    
    let categoryText = 'Threat';
    let categoryIcon = '⚠️';
    
    if (riskData.category === 'scam') {
      categoryText = 'Scam Survey/Prize';
      categoryIcon = '🎁';
    } else if (riskData.category === 'gambling') {
      categoryText = 'Gambling Site';
      categoryIcon = '🎰';
    } else if (riskData.category === 'adult') {
      categoryText = 'Adult Content';
      categoryIcon = '🔞';
    }
    
    dialog.innerHTML = `
      <div class="lg-dialog-content">
        <h3>${categoryIcon} LinkGuard Alert</h3>
        <p><strong>${categoryText} detected!</strong></p>
        <p>Risk Level: <span class="risk-${riskData.level > 0.8 ? 'high' : 'medium'}">${(riskData.level * 100).toFixed(0)}%</span></p>
        <div class="lg-reasons">
          ${riskData.reasons.map(reason => `<div>• ${reason}</div>`).join('')}
        </div>
        <p class="url-preview">${url}</p>
        <div class="lg-buttons">
          <button class="lg-btn-danger" onclick="this.closest('.lg-dialog').remove()">Block</button>
          <button class="lg-btn-warning" onclick="window.open('${url}', '_blank'); this.closest('.lg-dialog').remove()">Proceed Anyway</button>
        </div>
      </div>
    `;
    
    document.body.appendChild(dialog);
    
    setTimeout(() => {
      if (dialog.parentNode) dialog.remove();
    }, 15000);
  }

  analyzePageContent() {
    // This is now handled by ContentAnalyzer
    // Keep for backward compatibility
    const pageText = document.body?.textContent || '';
    const contentAnalysis = this.mlDetector.analyzePageContent(pageText);
    
    if (contentAnalysis.score > 0.5) {
      console.log('LinkGuard: ML detected suspicious page content', contentAnalysis);
    }
  }
  
  blockHighThreatSite(url, riskData) {
    console.log('BogaGuard: Auto-blocking high threat site:', url);
    
    // Stop all page activity
    window.stop();
    
    document.body.innerHTML = `
      <div class="lg-auto-block">
        <div class="lg-auto-block-content">
          <h1>🛡️ BogaGuard - High Threat Blocked</h1>
          <div class="lg-block-icon">🚨</div>
          <h2>DANGEROUS SITE AUTOMATICALLY BLOCKED</h2>
          <p><strong>Threat Level:</strong> <span class="risk-critical">${(riskData.level * 100).toFixed(0)}%</span></p>
          <div class="lg-threat-details">
            <strong>Detected Threats:</strong>
            <ul>
              ${riskData.reasons.map(reason => `<li>${reason}</li>`).join('')}
            </ul>
          </div>
          <div class="lg-auto-buttons">
            <button onclick="history.back()" class="lg-btn-safe">Go Back Safely</button>
            <button onclick="window.close()" class="lg-btn-danger">Close Tab</button>
          </div>
          <p class="lg-auto-footer">Site blocked automatically due to high threat level</p>
        </div>
      </div>
    `;
    
    this.addAutoBlockStyles();
    this.threatCount++;
    this.updateStats();
  }
  
  addAutoBlockStyles() {
    const style = document.createElement('style');
    style.textContent = `
      .lg-auto-block {
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100% !important;
        height: 100% !important;
        background: linear-gradient(135deg, #dc3545, #bd2130) !important;
        z-index: 999999 !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
      }
      .lg-auto-block-content {
        background: white !important;
        padding: 40px !important;
        border-radius: 15px !important;
        text-align: center !important;
        box-shadow: 0 20px 40px rgba(0,0,0,0.5) !important;
        max-width: 500px !important;
        border: 4px solid #dc3545 !important;
      }
      .risk-critical {
        color: #dc3545 !important;
        font-weight: bold !important;
        font-size: 24px !important;
      }
    `;
    document.head.appendChild(style);
  }
  
  updateStats() {
    const mlStats = this.mlDetector.getLearningStats();
    const redirectStats = this.redirectMonitor ? this.redirectMonitor.getRedirectStats() : {};
    const contentStats = this.contentAnalyzer ? this.contentAnalyzer.getAnalysisStats() : {};
    
    chrome.runtime.sendMessage({
      action: 'updateStats',
      threats: this.threatCount,
      scanned: this.scannedCount,
      mlStats: mlStats,
      redirectStats: redirectStats,
      contentStats: contentStats
    });
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => new BogaGuard());
} else {
  new BogaGuard();
}