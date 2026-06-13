document.addEventListener("DOMContentLoaded", function() {
    // Get current tab URL
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
        if (tabs.length > 0) {
            let url = tabs[0].url;
            document.getElementById("url-input").value = url;
            checkPhishing(url, "status-check");
        } else {
            console.error("No active tab detected.");
            document.getElementById("status-check").innerHTML = "❌ No active tab found";
        }
    });

    // Handle URL form submission
    document.getElementById("url-form").addEventListener("submit", function(event) {
        event.preventDefault();
        let url = document.getElementById("url-input1").value;
        if (url) {
            // Add http:// if missing
            if (!url.startsWith('http://') && !url.startsWith('https://')) {
                url = 'https://' + url;
            }
            checkPhishing(url, "status-result");
            renderHistory();
        } else {
            document.getElementById("status-result").innerHTML = "❌ Please enter a URL";
        }
    });

    const copyBtn = document.getElementById("copy-url");
    if (copyBtn) {
        copyBtn.addEventListener("click", async function() {
            const val = document.getElementById("url-input").value || "";
            try {
                await navigator.clipboard.writeText(val);
                copyBtn.textContent = "Copied!";
                setTimeout(() => copyBtn.textContent = "Copy Current URL", 1500);
            } catch {
                copyBtn.textContent = "Copy failed";
                setTimeout(() => copyBtn.textContent = "Copy Current URL", 1500);
            }
        });
    }

    enforceHistoryLimit().then(() => renderHistory());


});

// Function to check if a URL is phishing
function checkPhishing(url, elementId) {
    let resultDiv = document.getElementById(elementId);
    resultDiv.innerHTML = "⏳ Checking...";
    resultDiv.className = "loading";

    console.log("Checking URL:", url);

    // Use aggressive local detection first, then try API if needed
    const localResult = aggressiveLocalPhishingCheck(url);

    if (localResult.isPhishing) {
        displayLocalResult(localResult, resultDiv);
        saveCheckHistory(url, localResult).then(() => renderHistory());
    } else {
        callPhishingApi(url)
            .then(apiData => {
                handleApiResponse(apiData, resultDiv);
                saveCheckHistory(url, apiToLocalShape(apiData)).then(() => renderHistory());
            })
            .catch(error => {
                console.log("API failed, using local result:", error);
                displayLocalResult(localResult, resultDiv);
                saveCheckHistory(url, localResult).then(() => renderHistory());
            });
    }
}

// Call the phishing API
async function callPhishingApi(url) {
    try {
        const response = await fetch(`https://phishing-api.onrender.com/predict?url=${encodeURIComponent(url)}`, {
            method: 'GET',
            timeout: 5000
        });

        if (!response.ok) {
            throw new Error(`API returned ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.log("API call failed:", error);
        throw error;
    }
}

function handleApiResponse(data, resultDiv) {
    console.log("API Response data:", data);

    if (!data) {
        throw new Error("No data from API");
    }

    let isMalicious = false;
    let message = "✅ Safe Website";

    // Handle different API response formats
    if (data.malicious === 1 || data.prediction === 1 || data.is_phishing === true) {
        isMalicious = true;
        message = "🚨 Warning: Malicious Website!";
    } else if (data.result === "phishing" || data.class === "phishing") {
        isMalicious = true;
        message = "🚨 Warning: Phishing Website!";
    } else if (data.probability && data.probability > 0.6) {
        isMalicious = true;
        message = `🚨 Suspicious Website (${Math.round(data.probability * 100)}% risk)`;
    } else if (data.score && data.score > 0.6) {
        isMalicious = true;
        message = `🚨 Suspicious Website (${Math.round(data.score * 100)}% risk)`;
    }

    resultDiv.innerHTML = message;
    resultDiv.className = isMalicious ? "malicious" : "safe";

    // Add API source info
    const sourceSpan = document.createElement('span');
    sourceSpan.style.fontSize = '10px';
    sourceSpan.style.marginLeft = '5px';
    sourceSpan.style.opacity = '0.7';
    sourceSpan.textContent = '(API Detection)';
    resultDiv.appendChild(sourceSpan);
}

function displayLocalResult(result, resultDiv) {
    if (result.isPhishing) {
        resultDiv.innerHTML = `🚨 ${result.message}`;
        resultDiv.className = "malicious";
    } else {
        resultDiv.innerHTML = `✅ ${result.message}`;
        resultDiv.className = "safe";
    }

    // Show detailed warnings
    if (result.warnings.length > 0) {
        const warningDiv = document.createElement('div');
        warningDiv.style.fontSize = '11px';
        warningDiv.style.marginTop = '8px';
        warningDiv.style.padding = '5px';
        warningDiv.style.background = '#2a2a2a';
        warningDiv.style.borderRadius = '4px';
        warningDiv.style.color = '#ffbb33';
        warningDiv.innerHTML = `<strong>⚠️ Detection Reasons:</strong> ${result.warnings.join(', ')}`;
        resultDiv.appendChild(warningDiv);
    }

    // Add local detection source info
    const sourceSpan = document.createElement('span');
    sourceSpan.style.fontSize = '10px';
    sourceSpan.style.marginLeft = '5px';
    sourceSpan.style.opacity = '0.7';
    sourceSpan.textContent = '(Local Detection)';
    resultDiv.appendChild(sourceSpan);
}

// AGGRESSIVE local phishing detection
function aggressiveLocalPhishingCheck(url) {
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname.toLowerCase();

        let riskScore = 0;
        const warnings = [];

        // ===== HIGH RISK PATTERNS (IMMEDIATE FLAGS) =====

        // 1. Brand name + suspicious words (VERY COMMON in phishing)
        const brandPatterns = [
            // Amazon patterns
            /amazon[^.]*\.(security|verify|login|account|update)/i,
            /amazon-[^.]*\.(com|net|org)/i,
            /security[-_]?amazon/i,
            // PayPal patterns
            /paypal[^.]*\.(security|verify|login|confirm)/i,
            /paypal-[^.]*\.(com|net|org)/i,
            // Bank patterns
            /bank[^.]*\.(security|verify|login)/i,
            /security[-_]?bank/i,
            // Social media patterns
            /facebook[^.]*\.(security|verify|login)/i,
            /instagram[^.]*\.(security|verify)/i,
            // Tech company patterns
            /microsoft[^.]*\.(update|security|verify)/i,
            /apple[^.]*\.(id|security|verify)/i,
            /google[^.]*\.(security|verify|login)/i
        ];

        brandPatterns.forEach(pattern => {
            if (pattern.test(hostname)) {
                riskScore += 10; // Immediate red flag
                warnings.push("Brand name + suspicious words pattern");
            }
        });

        // 2. URL shorteners (common in phishing)
        const shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'bc.vc', 'adf.ly', 'shorte.st', 'cutt.ly', 'bitly.com',
            'tiny.cc', 'is.gd', 'cli.gs', 'yep.it', 'pic.gd'
        ];

        // Match URL shorteners by exact domain or subdomain, not substring
        if (shorteners.some(s => hostname === s || hostname.endsWith('.' + s))) {
            riskScore += 8;
            warnings.push("URL shortener service");
        }

        // 3. IP address instead of domain
        if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
            riskScore += 8;
            warnings.push("IP address used as domain");
        }

        // 4. @ symbol in domain (always suspicious)
        if (hostname.includes('@')) {
            riskScore += 10;
            warnings.push("Suspicious @ symbol in domain");
        }

        // ===== MEDIUM RISK PATTERNS =====

        // 5. Hyphenated domains (common in phishing)
        const hyphenCount = (hostname.match(/-/g) || []).length;
        if (hyphenCount >= 2) {
            riskScore += 3 * hyphenCount;
            warnings.push(`Multiple hyphens (${hyphenCount})`);
        }

        // 6. Long domain names
        if (hostname.length > 35) {
            riskScore += 4;
            warnings.push("Very long domain name");
        }

        // 7. Non-HTTPS for sensitive sites
        if (urlObj.protocol !== 'https:') {
            const sensitiveKeywords = ['login', 'bank', 'pay', 'account', 'secure'];
            if (sensitiveKeywords.some(keyword => hostname.includes(keyword))) {
                riskScore += 5;
                warnings.push("No HTTPS on sensitive site");
            }
        }

        // 8. Too many subdomains
        const subdomainCount = hostname.split('.').length - 2;
        if (subdomainCount > 3) {
            riskScore += 3;
            warnings.push("Too many subdomains");
        }

        // ===== KNOWN SAFE DOMAINS (REDUCE RISK) =====
        const safeDomains = [
            'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
            'github.com', 'microsoft.com', 'apple.com', 'netflix.com',
            'twitter.com', 'instagram.com', 'linkedin.com', 'wikipedia.org',
            'paypal.com', 'ebay.com', 'reddit.com', 'stackoverflow.com',
            'openai.com', 'chatgpt.com'
        ];

        // Treat official known hosts as safe too
        const officialHosts = [
            'chat.openai.com', 'accounts.google.com', 'secure.paypal.com',
            'login.microsoftonline.com'
        ];

        if (safeDomains.some(safe => hostname === safe || hostname.endsWith('.' + safe)) || officialHosts.includes(hostname)) {
            riskScore = Math.max(0, riskScore - 10); // Reduce risk more for official sites
            warnings.push("Known safe/official domain (risk reduced)");
        }

        // ===== DECISION MAKING =====
        const confidence = Math.min(100, Math.round(riskScore * 6));
        const isPhishing = riskScore >= 10; // Align with background to reduce false positives

        let message = isPhishing ?
            `High Risk Website (${confidence}% confidence)` :
            `Likely Safe Website (${confidence}% confidence)`;

        return {
            isPhishing: isPhishing,
            riskScore: riskScore,
            warnings: warnings,
            message: message,
            confidence: confidence
        };

    } catch (error) {
        console.error("URL parsing error:", error);
        return {
            isPhishing: false,
            riskScore: 0,
            warnings: ["Invalid URL format"],
            message: "Invalid URL format",
            confidence: 0
        };
    }
}

// Add timeout to fetch
const originalFetch = window.fetch;
window.fetch = function(resource, options = {}) {
    const timeout = options.timeout || 5000;
    const controller = new AbortController();
    const signal = controller.signal;

    options.signal = signal;

    const timeoutId = setTimeout(() => controller.abort(), timeout);

    return originalFetch(resource, options)
        .then(response => {
            clearTimeout(timeoutId);
            return response;
        })
        .catch(error => {
            clearTimeout(timeoutId);
            throw error;
        });
};

// Store last 5 checks globally with time, url, and status
function apiToLocalShape(data) {
    if (!data) return { isPhishing: false, message: "✅ Safe Website", warnings: [] };
    let isMalicious = false;
    let message = "✅ Safe Website";
    if (data.malicious === 1 || data.prediction === 1 || data.is_phishing === true) {
        isMalicious = true;
        message = "🚨 Warning: Malicious Website!";
    } else if (data.result === "phishing" || data.class === "phishing") {
        isMalicious = true;
        message = "🚨 Warning: Phishing Website!";
    } else if ((typeof data.probability === 'number' && data.probability > 0.6) || (typeof data.score === 'number' && data.score > 0.6)) {
        isMalicious = true;
        message = "🚨 Suspicious Website!";
    }
    return { isPhishing: isMalicious, message, warnings: [] };
}

async function saveCheckHistory(url, result) {
    try {
        const status = result.isPhishing ? "Risky" : "Safe";
        const { globalHistory } = await chrome.storage.local.get({ globalHistory: [] });
        const list = Array.isArray(globalHistory) ? globalHistory : [];
        list.unshift({ time: Date.now(), url, status });
        const trimmed = list.slice(0, 5);
        await chrome.storage.local.set({ globalHistory: trimmed });
    } catch (e) {
        console.warn("Failed to save history", e);
    }
}

async function enforceHistoryLimit() {
    try {
        const { globalHistory } = await chrome.storage.local.get({ globalHistory: [] });
        const list = Array.isArray(globalHistory) ? globalHistory : [];
        const trimmed = list.slice(0, 5);
        if (trimmed.length !== list.length) {
            await chrome.storage.local.set({ globalHistory: trimmed });
        }
    } catch {}
}

// Render global history
async function renderHistory() {
    const container = document.getElementById("history-list");
    if (!container) return;
    container.innerHTML = "";
    try {
        const { globalHistory } = await chrome.storage.local.get({ globalHistory: [] });
        const list = Array.isArray(globalHistory) ? globalHistory : [];
        const trimmed = list.slice(0, 5);
        if (trimmed.length !== list.length) {
            await chrome.storage.local.set({ globalHistory: trimmed });
        }
        trimmed.forEach(item => {
            const li = document.createElement("li");
            const t = new Date(item.time).toLocaleTimeString();
            li.textContent = `${t} — ${item.status}: ${item.url}`;
            li.style.fontSize = "12px";
            li.style.color = item.status === "Risky" ? "#ff6b6b" : "#8be9fd";
            container.appendChild(li);
        });
        if (trimmed.length === 0) {
            const li = document.createElement("li");
            li.textContent = "No history yet";
            container.appendChild(li);
        }
    } catch (e) {
        const li = document.createElement("li");
        li.textContent = "History unavailable";
        container.appendChild(li);
    }
}
chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === "local" && changes.globalHistory) {
        const val = changes.globalHistory.newValue;
        if (Array.isArray(val) && val.length > 5) {
            chrome.storage.local.set({ globalHistory: val.slice(0, 5) });
        }
    }
});
// removed duplicate DOMContentLoaded and whitelist init

// removed duplicate apiToLocalShape

// removed old per-host history implementation

// removed old per-host renderHistory

// removed whitelist toggle code