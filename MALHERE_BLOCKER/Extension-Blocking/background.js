console.log("Phishing Detector Background Script Loaded");

function aggressiveLocalPhishingCheck(url) {
    try {
        const urlObj = new URL(url);

        // Ignore internal protocols and local files
        if (["chrome:", "chrome-extension:", "about:", "file:", "edge:", "moz-extension:"].includes(urlObj.protocol)) {
            return { isPhishing: false, riskScore: 0, warnings: [], confidence: 0, hostname: urlObj.hostname };
        }

        const hostname = urlObj.hostname.toLowerCase();
        let riskScore = 0;
        const warnings = [];
        const brandPatterns = [
            /amazon[^.]*\.(security|verify|login|account|update)/i, /amazon-[^.]*\.(com|net|org)/i, /security[-_]?amazon/i,
            /paypal[^.]*\.(security|verify|login|confirm)/i, /paypal-[^.]*\.(com|net|org)/i, /bank[^.]*\.(security|verify|login)/i,
            /security[-_]?bank/i, /facebook[^.]*\.(security|verify|login)/i, /instagram[^.]*\.(security|verify)/i,
            /microsoft[^.]*\.(update|security|verify)/i, /apple[^.]*\.(id|security|verify)/i, /google[^.]*\.(security|verify|login)/i
        ];
        brandPatterns.forEach(pattern => {
            if (pattern.test(hostname)) {
                riskScore += 10;
                warnings.push("Brand name + suspicious words pattern");
            }
        });
        const shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "bc.vc", "adf.ly", "shorte.st", "cutt.ly", "bitly.com",
            "tiny.cc", "is.gd", "cli.gs", "yep.it", "pic.gd"
        ];
        if (shorteners.some(shortener => hostname.includes(shortener))) {
            riskScore += 8;
            warnings.push("URL shortener service");
        }
        if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
            riskScore += 8;
            warnings.push("IP address used as domain");
        }
        if (hostname.includes("@")) {
            riskScore += 10;
            warnings.push("Suspicious @ symbol in domain");
        }
        const hyphenCount = (hostname.match(/-/g) || []).length;
        if (hyphenCount >= 2) {
            riskScore += 3 * hyphenCount;
            warnings.push(`Multiple hyphens (${hyphenCount})`);
        }
        if (hostname.length > 35) {
            riskScore += 4;
            warnings.push("Very long domain name");
        }
        if (urlObj.protocol !== "https:") {
            const sensitiveKeywords = ["login", "bank", "pay", "account", "secure"];
            if (sensitiveKeywords.some(keyword => hostname.includes(keyword))) {
                riskScore += 5;
                warnings.push("No HTTPS on sensitive site");
            }
        }
        const subdomainCount = hostname.split(".").length - 2;
        if (subdomainCount > 3) {
            riskScore += 3;
            warnings.push("Too many subdomains");
        }
        // Known safe domains and official hosts (reduce risk significantly)
        const safeDomains = [
            "google.com", "youtube.com", "facebook.com", "amazon.com", "github.com", "microsoft.com",
            "apple.com", "netflix.com", "twitter.com", "instagram.com", "linkedin.com", "wikipedia.org", "paypal.com",
            "ebay.com", "reddit.com", "stackoverflow.com"
        ];
        const officialHosts = [
            "accounts.google.com", "secure.paypal.com", "login.microsoftonline.com", "www.facebook.com", "www.amazon.com",
            "www.linkedin.com", "www.wikipedia.org", "github.com"
        ];
        if (safeDomains.some(safe => hostname === safe || hostname.endsWith(`.${safe}`)) || officialHosts.includes(hostname)) {
            warnings.push("Official/known safe domain");
            riskScore = Math.max(0, riskScore - 10);
        }
        const confidence = Math.min(100, Math.round(riskScore * 6));
        const isPhishing = riskScore >= 10; // tighten threshold to reduce false positives
        return { isPhishing, riskScore, warnings, confidence, hostname };
    } catch (error) {
        console.error("URL parsing error:", error);
        return { isPhishing: false, riskScore: 0, warnings: ["Invalid URL format"], confidence: 0, hostname: "unknown" };
    }
}

// Remote API confirmation to reduce false positives
async function callPhishingApi(url) {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 12000); // 12 seconds timeout

        const response = await fetch(`https://phishing-api.onrender.com/predict?url=${encodeURIComponent(url)}`, {
            method: "GET",
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!response.ok) throw new Error(`API returned ${response.status}`);
        return await response.json();
    } catch (error) {
        console.warn("API call failed:", error);
        throw error;
    }
}

function apiSaysMalicious(data) {
    if (!data) return false;
    if (data.malicious === 1 || data.prediction === 1 || data.is_phishing === true) return true;
    if (data.result === "phishing" || data.class === "phishing") return true;
    if (typeof data.probability === "number" && data.probability > 0.6) return true;
    if (typeof data.score === "number" && data.score > 0.6) return true;
    return false;
}

// Combine local detection with API confirmation to decide blocking
async function shouldBlockUrl(url) {
    console.log("Checking if URL should be blocked:", url);
    const localResult = aggressiveLocalPhishingCheck(url);

    // No whitelist bypass (removed per request)

    let apiData = null;
    let apiMalicious = false;
    try {
        apiData = await callPhishingApi(url);
        apiMalicious = apiSaysMalicious(apiData);
    } catch (e) {
        // API failure should not force blocking; rely on local heuristics
    }

    // Block if local heuristics say phishing OR API confirms malicious
    const shouldBlock = localResult.isPhishing || apiMalicious;

    if (shouldBlock) {
        const reason =
            localResult.isPhishing && apiMalicious ?
            "Local + API confirmed" :
            (localResult.isPhishing ? "Local risk" : "API confirmed");
        console.log("Blocking:", reason);
        await reportMalwareUrl(url);
        return {
            shouldBlock: true,
            reason,
            details: {...localResult, api: apiData }
        };
    }

    return {
        shouldBlock: false,
        reason: apiData ? "API confirmed safe" : "Local safe",
        details: {...localResult, api: apiData }
    };
}

async function reportMalwareUrl(url) {
    try {
        const response = await fetch("http://10.57.140.28:5000/report", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
        });
        const data = await response.json();
        console.log("Report API response:", data);
    } catch (error) {
        console.error("Error reporting malware URL:", error);
    }
}

chrome.webNavigation.onBeforeNavigate.addListener(async(details) => {
    if (details.frameId !== 0) return;
    const blockResult = await shouldBlockUrl(details.url);
    if (blockResult.shouldBlock) {
        await chrome.storage.local.set({
            blockedUrl: details.url,
            blockReason: blockResult.reason,
            blockDetails: blockResult.details,
            timestamp: Date.now(),
        });
        const warningUrl = chrome.runtime.getURL("warning.html");
        chrome.tabs.update(details.tabId, { url: warningUrl });
    }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "checkUrl") {
        shouldBlockUrl(request.url)
            .then((result) => sendResponse(result))
            .catch((error) =>
                sendResponse({ shouldBlock: false, reason: "Error", error: error.message })
            );
        return true;
    }
});

console.log("Phishing Detector Background Script Ready - Website blocking active!");