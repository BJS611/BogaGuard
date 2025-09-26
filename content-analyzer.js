// Content Analysis Engine - Deep Website Scanning
class ContentAnalyzer {
  constructor(linkGuard) {
    this.linkGuard = linkGuard;
    this.analysisResults = new Map();
    this.suspiciousElements = new Set();
    this.contentScore = 0;
    
    this.initPatterns();
    this.startAnalysis();
  }

  initPatterns() {
    // Scam/Phishing content patterns
    this.scamPatterns = {
      // Prize/Survey scams
      prize: [
        /(congratulations?|selamat|chúc mừng|tahniah|congratulation).{0,50}(winner|menang|thắng|pemenang)/i,
        /(you.{0,20}won|anda.{0,20}menang|bạn.{0,20}thắng).{0,50}(iphone|samsung|prize|hadiah)/i,
        /(claim.{0,20}now|klaim.{0,20}sekarang|nhận.{0,20}ngay)/i,
        /(limited.{0,20}time|waktu.{0,20}terbatas|thời.{0,20}gian.{0,20}có.{0,20}hạn)/i,
        /(survey.{0,30}complete|lengkapi.{0,20}survei|hoàn.{0,20}thành.{0,20}khảo.{0,20}sát)/i
      ],
      
      // Financial scams
      financial: [
        /(guaranteed.{0,20}profit|keuntungan.{0,20}pasti|lợi.{0,20}nhuận.{0,20}đảm.{0,20}bảo)/i,
        /(easy.{0,20}money|uang.{0,20}mudah|tiền.{0,20}dễ.{0,20}dàng)/i,
        /(invest.{0,20}now|investasi.{0,20}sekarang|đầu.{0,20}tư.{0,20}ngay)/i,
        /(double.{0,20}your.{0,20}money|gandakan.{0,20}uang|nhân.{0,20}đôi.{0,20}tiền)/i,
        /(\$\d+.{0,20}per.{0,20}day|rp\s?\d+.{0,20}per.{0,20}hari|\d+.{0,20}vnd.{0,20}mỗi.{0,20}ngày)/i
      ],
      
      // Urgency tactics
      urgency: [
        /(act.{0,20}now|bertindak.{0,20}sekarang|hành.{0,20}động.{0,20}ngay)/i,
        /(expires?.{0,20}(today|soon)|berakhir.{0,20}hari.{0,20}ini|hết.{0,20}hạn.{0,20}sớm)/i,
        /(hurry.{0,20}up|cepat|nhanh.{0,20}lên)/i,
        /(only.{0,20}\d+.{0,20}left|hanya.{0,20}\d+.{0,20}tersisa|chỉ.{0,20}còn.{0,20}\d+)/i,
        /(don.t.{0,20}miss|jangan.{0,20}lewatkan|đừng.{0,20}bỏ.{0,20}lỡ)/i
      ],
      
      // Credential harvesting
      phishing: [
        /(verify.{0,20}account|verifikasi.{0,20}akun|xác.{0,20}minh.{0,20}tài.{0,20}khoản)/i,
        /(update.{0,20}payment|perbarui.{0,20}pembayaran|cập.{0,20}nhật.{0,20}thanh.{0,20}toán)/i,
        /(suspended.{0,20}account|akun.{0,20}ditangguhkan|tài.{0,20}khoản.{0,20}bị.{0,20}đình.{0,20}chỉ)/i,
        /(enter.{0,20}password|masukkan.{0,20}kata.{0,20}sandi|nhập.{0,20}mật.{0,20}khẩu)/i,
        /(confirm.{0,20}identity|konfirmasi.{0,20}identitas|xác.{0,20}nhận.{0,20}danh.{0,20}tính)/i
      ],
      
      // Gambling content (including hidden/disguised)
      gambling: [
        /(slot.{0,20}gacor|slot.{0,20}maxwin)/i,
        /(jackpot.{0,20}hari.{0,20}ini|แจ็คพอต.{0,20}วันนี้)/i,
        /(menang.{0,20}terus|thắng.{0,20}liên.{0,20}tục|ชนะ.{0,20}ต่อเนื่อง)/i,
        /(deposit.{0,20}minimal|ฝาก.{0,20}ขั้น.{0,20}ต่ำ|nạp.{0,20}tối.{0,20}thiểu)/i,
        /(withdraw.{0,20}langsung|ถอน.{0,20}ทันที|rút.{0,20}ngay.{0,20}lập.{0,20}tức)/i,
        // Hidden gambling (disguised as articles)
        /(keberuntungan|hoki|rejeki|nasib|peruntungan).{0,30}(logo|visual|simbol)/i,
        /(rahasia|tips|cara).{0,30}(menang|untung|kaya|sukses).{0,30}(cepat|mudah|pasti)/i,
        /(feng.?shui|numerologi|ramalan).{0,30}(angka|nomor|digit)/i,
        /(mistis|gaib|spiritual).{0,30}(kekuatan|energi|aura)/i,
        /(logo|visual|simbol).{0,30}(membawa|mendatangkan).{0,30}(keberuntungan|hoki)/i,
        /(jkumar|kumar).{0,50}(keberuntungan|hoki|rejeki)/i,
        /\/news\/.{0,100}(keberuntungan|hoki|feng.?shui|numerologi)/i,
        /(tersembunyi|rahasia).{0,30}(balik|dibalik).{0,30}(logo|visual)/i,
        /(berita|artikel|news).{0,50}(keberuntungan|hoki|rejeki|nasib)/i
      ],
      
      // Adult content
      adult: [
        /(free.{0,20}porn|gratis.{0,20}bokep|โป๊.{0,20}ฟรี)/i,
        /(18\+.{0,20}content|konten.{0,20}dewasa|nội.{0,20}dung.{0,20}người.{0,20}lớn)/i,
        /(live.{0,20}cam|webcam.{0,20}langsung|cam.{0,20}trực.{0,20}tiếp)/i,
        /(hot.{0,20}girls|cewek.{0,20}seksi|gái.{0,20}xinh)/i
      ]
    };
    
    // Suspicious form patterns
    this.formPatterns = [
      /password/i, /credit.?card/i, /ssn|social.?security/i,
      /bank.?account/i, /pin.?code/i, /cvv|cvc/i,
      /kata.?sandi/i, /kartu.?kredit/i, /rekening/i,
      /mật.?khẩu/i, /thẻ.?tín.?dụng/i, /tài.?khoản.?ngân.?hàng/i
    ];
    
    // Fake UI elements
    this.fakeUIPatterns = [
      /loading.{0,20}please.{0,20}wait/i,
      /processing.{0,20}payment/i,
      /connecting.{0,20}to.{0,20}server/i,
      /downloading.{0,20}\d+%/i,
      /installing.{0,20}security.{0,20}update/i
    ];
  }

  startAnalysis() {
    // Initial analysis
    this.analyzePageContent();
    
    // Continuous monitoring
    this.observeContentChanges();
    
    // Form monitoring
    this.monitorForms();
    
    // Image analysis
    this.analyzeImages();
    
    // Script analysis
    this.analyzeScripts();
  }

  analyzePageContent() {
    const content = {
      title: document.title || '',
      text: document.body?.textContent || '',
      html: document.body?.innerHTML || '',
      meta: this.getMetaContent(),
      forms: this.analyzeForms(),
      links: this.analyzeLinks(),
      images: this.analyzeImages(),
      scripts: this.analyzeScripts()
    };
    
    let totalScore = 0;
    let detectedThreats = [];
    
    // Analyze text content
    const textAnalysis = this.analyzeText(content.text + ' ' + content.title);
    totalScore += textAnalysis.score;
    detectedThreats.push(...textAnalysis.threats);
    
    // Analyze HTML structure
    const htmlAnalysis = this.analyzeHTML(content.html);
    totalScore += htmlAnalysis.score;
    detectedThreats.push(...htmlAnalysis.threats);
    
    // Analyze hidden content
    const hiddenAnalysis = this.analyzeHiddenContent(content.html);
    totalScore += hiddenAnalysis.score;
    detectedThreats.push(...hiddenAnalysis.threats);
    
    // Analyze forms
    const formAnalysis = this.analyzeForms();
    totalScore += formAnalysis.score;
    detectedThreats.push(...formAnalysis.threats);
    
    // Analyze meta tags
    const metaAnalysis = this.analyzeMeta(content.meta);
    totalScore += metaAnalysis.score;
    detectedThreats.push(...metaAnalysis.threats);
    
    this.contentScore = Math.min(totalScore, 1.0);
    
    if (this.contentScore > 0.6) {
      this.blockMaliciousContent(detectedThreats);
    } else if (this.contentScore > 0.4) {
      this.showContentWarning(detectedThreats);
    }
    
    console.log('ContentAnalyzer: Page analysis complete', {
      score: this.contentScore,
      threats: detectedThreats
    });
  }

  analyzeText(text) {
    let score = 0;
    let threats = [];
    
    // Check each pattern category
    Object.entries(this.scamPatterns).forEach(([category, patterns]) => {
      let categoryMatches = 0;
      patterns.forEach(pattern => {
        const matches = text.match(pattern);
        if (matches) {
          categoryMatches++;
          threats.push(`${category}: ${matches[0].substring(0, 50)}...`);
        }
      });
      
      if (categoryMatches > 0) {
        score += Math.min(categoryMatches * 0.2, 0.6);
      }
    });
    
    if (/jkumar\.com/i.test(window.location.hostname) && /(keberuntungan|hoki|rejeki)/i.test(text)) {
      score += 0.8;
      threats.push('Disguised gambling content in news site');
    }
    
    // Check for fake UI elements
    this.fakeUIPatterns.forEach(pattern => {
      if (pattern.test(text)) {
        score += 0.3;
        threats.push('Fake UI element detected');
      }
    });
    
    // Check for excessive exclamation marks/caps
    const exclamationCount = (text.match(/!/g) || []).length;
    const capsRatio = (text.match(/[A-Z]/g) || []).length / text.length;
    
    if (exclamationCount > 10) {
      score += 0.2;
      threats.push('Excessive exclamation marks');
    }
    
    if (capsRatio > 0.3) {
      score += 0.2;
      threats.push('Excessive capital letters');
    }
    
    return { score, threats };
  }

  analyzeHTML(html) {
    let score = 0;
    let threats = [];
    
    // Check for hidden elements with suspicious content
    const hiddenElements = document.querySelectorAll('[style*="display:none"], [style*="visibility:hidden"], [hidden]');
    hiddenElements.forEach(el => {
      const text = el.textContent || '';
      if (text.length > 100) {
        score += 0.2;
        threats.push('Hidden content detected');
      }
    });
    
    // Check for suspicious iframes
    const iframes = document.querySelectorAll('iframe');
    iframes.forEach(iframe => {
      const src = iframe.src || '';
      if (src && !src.startsWith(window.location.origin)) {
        score += 0.3;
        threats.push(`Suspicious iframe: ${src}`);
      }
    });
    
    // Check for fake security badges
    const images = document.querySelectorAll('img');
    images.forEach(img => {
      const alt = (img.alt || '').toLowerCase();
      const src = (img.src || '').toLowerCase();
      if (alt.includes('secure') || alt.includes('verified') || src.includes('badge')) {
        score += 0.1;
        threats.push('Fake security badge detected');
      }
    });
    
    return { score, threats };
  }

  analyzeForms() {
    let score = 0;
    let threats = [];
    
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
      const inputs = form.querySelectorAll('input, textarea, select');
      let sensitiveFields = 0;
      
      inputs.forEach(input => {
        const name = (input.name || '').toLowerCase();
        const placeholder = (input.placeholder || '').toLowerCase();
        const label = this.getInputLabel(input);
        const fieldText = `${name} ${placeholder} ${label}`.toLowerCase();
        
        this.formPatterns.forEach(pattern => {
          if (pattern.test(fieldText)) {
            sensitiveFields++;
          }
        });
      });
      
      if (sensitiveFields > 2) {
        score += 0.4;
        threats.push(`Suspicious form requesting ${sensitiveFields} sensitive fields`);
      }
      
      // Check form action
      const action = form.action || '';
      if (action && !action.startsWith(window.location.origin)) {
        score += 0.3;
        threats.push(`Form submits to external domain: ${action}`);
      }
    });
    
    return { score, threats };
  }

  getInputLabel(input) {
    const id = input.id;
    if (id) {
      const label = document.querySelector(`label[for="${id}"]`);
      if (label) return label.textContent || '';
    }
    
    const parentLabel = input.closest('label');
    if (parentLabel) return parentLabel.textContent || '';
    
    return '';
  }

  analyzeMeta(metaContent) {
    let score = 0;
    let threats = [];
    
    // Check for suspicious meta redirects
    if (metaContent.refresh) {
      score += 0.3;
      threats.push('Meta refresh redirect detected');
    }
    
    // Check description for scam keywords
    if (metaContent.description) {
      const textAnalysis = this.analyzeText(metaContent.description);
      score += textAnalysis.score * 0.5;
      threats.push(...textAnalysis.threats.map(t => `Meta: ${t}`));
      
      if (/(keberuntungan|hoki|rejeki|feng.?shui|numerologi)/i.test(metaContent.description)) {
        score += 0.6;
        threats.push('Meta: Hidden gambling keywords detected');
      }
    }
    
    return { score, threats };
  }

  getMetaContent() {
    const meta = {};
    
    document.querySelectorAll('meta').forEach(tag => {
      const name = tag.getAttribute('name') || tag.getAttribute('property');
      const content = tag.getAttribute('content');
      
      if (name && content) {
        meta[name.toLowerCase()] = content;
      }
      
      if (tag.getAttribute('http-equiv') === 'refresh') {
        meta.refresh = content;
      }
    });
    
    return meta;
  }

  analyzeImages() {
    let score = 0;
    let threats = [];
    
    const images = document.querySelectorAll('img');
    images.forEach(img => {
      // Check for fake logos
      const src = (img.src || '').toLowerCase();
      const alt = (img.alt || '').toLowerCase();
      
      if (src.includes('logo') || alt.includes('logo')) {
        // Check if it's trying to impersonate known brands
        const brands = ['google', 'facebook', 'apple', 'microsoft', 'amazon', 'paypal'];
        brands.forEach(brand => {
          if ((src.includes(brand) || alt.includes(brand)) && !window.location.hostname.includes(brand)) {
            score += 0.3;
            threats.push(`Fake ${brand} logo detected`);
          }
        });
      }
    });
    
    return { score, threats };
  }

  analyzeHiddenContent(html) {
    let score = 0;
    let threats = [];
    
    // Check for hidden gambling content in comments
    const commentMatches = html.match(/<!--[\s\S]*?-->/g) || [];
    commentMatches.forEach(comment => {
      Object.entries(this.scamPatterns).forEach(([category, patterns]) => {
        patterns.forEach(pattern => {
          if (pattern.test(comment)) {
            score += 0.4;
            threats.push(`Hidden ${category} content in HTML comments`);
          }
        });
      });
    });
    
    // Check for base64 encoded content
    const base64Matches = html.match(/[A-Za-z0-9+/]{50,}={0,2}/g) || [];
    base64Matches.forEach(encoded => {
      try {
        const decoded = atob(encoded);
        Object.entries(this.scamPatterns).forEach(([category, patterns]) => {
          patterns.forEach(pattern => {
            if (pattern.test(decoded)) {
              score += 0.5;
              threats.push(`Hidden ${category} content in base64 encoding`);
            }
          });
        });
      } catch (e) {
        // Not valid base64
      }
    });
    
    // Check for obfuscated JavaScript
    const scriptMatches = html.match(/<script[^>]*>([\s\S]*?)<\/script>/gi) || [];
    scriptMatches.forEach(script => {
      // Check for heavily obfuscated code
      if (/[\x00-\x1F\x7F-\xFF]{10,}/.test(script)) {
        score += 0.3;
        threats.push('Obfuscated script content detected');
      }
      
      // Check for gambling keywords in scripts
      Object.entries(this.scamPatterns.gambling).forEach(pattern => {
        if (pattern.test(script)) {
          score += 0.6;
          threats.push('Hidden gambling content in JavaScript');
        }
      });
    });
    
    return { score, threats };
  }
  
  analyzeScripts() {
    let score = 0;
    let threats = [];
    
    const scripts = document.querySelectorAll('script');
    scripts.forEach(script => {
      const content = script.textContent || '';
      
      // Check for suspicious script patterns
      if (content.includes('eval(') || content.includes('document.write(')) {
        score += 0.2;
        threats.push('Suspicious script execution detected');
      }
      
      // Check for crypto mining
      if (/coinhive|cryptonight|monero/i.test(content)) {
        score += 0.5;
        threats.push('Crypto mining script detected');
      }
      
      // Check for gambling redirects in scripts
      if (/(location\.href|window\.open).*(slot|casino|bet|judi)/i.test(content)) {
        score += 0.7;
        threats.push('Gambling redirect script detected');
      }
    });
    
    return { score, threats };
  }

  observeContentChanges() {
    const observer = new MutationObserver(mutations => {
      let shouldReanalyze = false;
      
      mutations.forEach(mutation => {
        if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
          mutation.addedNodes.forEach(node => {
            if (node.nodeType === 1) { // Element node
              const text = node.textContent || '';
              if (text.length > 50) {
                shouldReanalyze = true;
              }
            }
          });
        }
      });
      
      if (shouldReanalyze) {
        setTimeout(() => this.analyzePageContent(), 1000);
      }
    });
    
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true
    });
  }

  monitorForms() {
    document.addEventListener('submit', (e) => {
      const form = e.target;
      if (form.tagName === 'FORM') {
        const analysis = this.analyzeForms();
        if (analysis.score > 0.5) {
          e.preventDefault();
          this.showFormWarning(form, analysis.threats);
        }
      }
    });
  }

  blockMaliciousContent(threats) {
    console.log('ContentAnalyzer: Blocking malicious content', threats);
    
    document.body.innerHTML = `
      <div class="lg-content-block">
        <div class="lg-content-block-inner">
          <h1>🛡️ LinkGuard - Malicious Content Blocked</h1>
          <div class="lg-block-icon">⚠️</div>
          <h2>Dangerous content detected and blocked</h2>
          <p><strong>Content Analysis Score:</strong> <span class="risk-high">${(this.contentScore * 100).toFixed(0)}%</span></p>
          <div class="lg-threat-list">
            <strong>Detected threats:</strong>
            <ul>
              ${threats.map(threat => `<li>${threat}</li>`).join('')}
            </ul>
          </div>
          <div class="lg-content-buttons">
            <button onclick="history.back()" class="lg-btn-safe">Go Back</button>
            <button onclick="window.close()" class="lg-btn-danger">Close Tab</button>
          </div>
          <p class="lg-content-footer">Protected by LinkGuard Content Analysis</p>
        </div>
      </div>
    `;
    
    this.addContentBlockStyles();
    this.linkGuard.threatCount++;
    this.linkGuard.updateStats();
  }

  showContentWarning(threats) {
    const warning = document.createElement('div');
    warning.className = 'lg-content-warning';
    warning.innerHTML = `
      <div class="lg-content-warning-inner">
        <span class="lg-warning-icon">⚠️</span>
        <div class="lg-warning-content">
          <strong>Suspicious content detected</strong>
          <div class="lg-warning-details">Score: ${(this.contentScore * 100).toFixed(0)}% | ${threats.length} threats</div>
        </div>
        <button class="lg-warning-close" onclick="this.parentElement.parentElement.remove()">×</button>
      </div>
    `;
    
    document.body.appendChild(warning);
    
    setTimeout(() => {
      if (warning.parentElement) {
        warning.remove();
      }
    }, 8000);
  }

  showFormWarning(form, threats) {
    const warning = document.createElement('div');
    warning.className = 'lg-form-warning';
    warning.innerHTML = `
      <div class="lg-form-warning-content">
        <h3>🚨 Form Submission Blocked</h3>
        <p>This form requests sensitive information and may be malicious:</p>
        <ul>
          ${threats.map(threat => `<li>${threat}</li>`).join('')}
        </ul>
        <div class="lg-form-buttons">
          <button onclick="this.closest('.lg-form-warning').remove()" class="lg-btn-safe">Cancel</button>
          <button onclick="this.submitAnyway()" class="lg-btn-warning">Submit Anyway</button>
        </div>
      </div>
    `;
    
    document.body.appendChild(warning);
  }

  addContentBlockStyles() {
    const style = document.createElement('style');
    style.textContent = `
      .lg-content-block {
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100% !important;
        height: 100% !important;
        background: linear-gradient(135deg, #e74c3c, #c0392b) !important;
        z-index: 999999 !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
      }
      
      .lg-content-warning {
        position: fixed !important;
        top: 20px !important;
        right: 20px !important;
        background: #f39c12 !important;
        color: white !important;
        padding: 15px !important;
        border-radius: 8px !important;
        z-index: 999998 !important;
        max-width: 400px !important;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3) !important;
      }
      
      .lg-form-warning {
        position: fixed !important;
        top: 50% !important;
        left: 50% !important;
        transform: translate(-50%, -50%) !important;
        background: white !important;
        padding: 30px !important;
        border-radius: 10px !important;
        z-index: 999999 !important;
        box-shadow: 0 10px 30px rgba(0,0,0,0.5) !important;
        border: 3px solid #e74c3c !important;
      }
    `;
    document.head.appendChild(style);
  }

  getAnalysisStats() {
    return {
      contentScore: this.contentScore,
      threatsDetected: this.analysisResults.size,
      suspiciousElements: this.suspiciousElements.size
    };
  }
}