# 🛡️ BogaGuard - Phishing Detection Extension

**Built for Hackathon 2025** - A lightweight browser extension that protects users from phishing attacks in real-time.

## 🚀 Features

- **Real-time Link Scanning**: Automatically analyzes all links on web pages
- **Multi-layer Detection**: Uses heuristics, pattern matching, and domain analysis
- **Visual Warnings**: Clear indicators for suspicious and dangerous links
- **Threat Blocking**: Prevents accidental clicks on malicious links
- **Live Statistics**: Track threats blocked and protection status
- **Zero Configuration**: Works immediately after installation

## 🔧 Installation

1. Open Chrome/Edge and go to `chrome://extensions/`
2. Enable "Developer mode" (top right toggle)
3. Click "Load unpacked" and select this folder
4. The LinkGuard shield icon will appear in your toolbar

## 🎯 How It Works

LinkGuard uses a unique multi-factor risk assessment:

- **Pattern Analysis**: Detects URL shorteners, suspicious domains
- **Heuristic Scanning**: Identifies phishing keywords and structures  
- **Domain Reputation**: Checks against known safe/unsafe patterns
- **Homograph Detection**: Catches internationalized domain attacks
- **Real-time Alerts**: Blocks dangerous clicks with confirmation dialogs

## 📊 Risk Calculation

The extension calculates risk scores (0-100%) based on:
- Suspicious URL patterns (+30%)
- Domain characteristics (+20%)
- Homograph attacks (+40%)
- Trusted domain whitelist (-50%)

## 🎨 Visual Indicators

- 🟢 **Safe Links**: No marking (trusted domains)
- 🟡 **Suspicious**: Orange dotted underline
- 🔴 **Dangerous**: Red background with warning icon
- ⚠️ **Blocked**: Click prevention with risk dialog

## 📈 Statistics Dashboard

Click the extension icon to view:
- Threats blocked this session
- Total links scanned
- Protection status
- Real-time threat level

## 🛠️ Technical Stack

- **Frontend**: Vanilla JavaScript (ES6+)
- **Styling**: Custom CSS with animations
- **Architecture**: Manifest V3 service worker
- **Storage**: Chrome Extension Storage API
- **Detection**: Custom heuristic algorithms

## 🏆 Hackathon Notes

This extension was built in 3 days with focus on:
- Minimal dependencies (no external libraries)
- Unique detection algorithms
- Custom UI/UX design
- Real-world phishing protection

## 🔒 Privacy

LinkGuard processes all data locally - no external API calls or data collection.

---

*Built with ❤️ for safer browsing*
