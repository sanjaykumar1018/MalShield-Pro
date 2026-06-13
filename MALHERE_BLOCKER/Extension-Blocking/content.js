
// Content script for additional page blocking and user notifications
console.log("Phishing Detector Content Script Loaded on:", window.location.href);

// Check if current page should be blocked (additional safety check)
async function checkCurrentPage() {
    const currentUrl = window.location.href;

    try {
        const response = await chrome.runtime.sendMessage({
            action: "checkUrl",
            url: currentUrl
        });

        if (response && response.shouldBlock) {
            console.log("Content script detected malicious page, blocking...");
            blockCurrentPage(response);
        }
    } catch (error) {
        console.log("Content script check failed:", error);
    }
}

// Block the current page by replacing content with warning
function blockCurrentPage(blockInfo) {
    // Stop all loading immediately
    window.stop();

    // Replace entire page content with warning
    document.documentElement.innerHTML = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>⚠️ Malicious Website Blocked</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: linear-gradient(135deg, #ff4444, #cc0000);
                    color: white;
                    text-align: center;
                    padding: 50px 20px;
                    margin: 0;
                    min-height: 100vh;
                    display: flex;
                    flex-direction: column;
                    justify-content: center;
                    align-items: center;
                }
                .warning-container {
                    background: rgba(0, 0, 0, 0.8);
                    padding: 40px;
                    border-radius: 20px;
                    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
                    max-width: 600px;
                    animation: slideIn 0.5s ease-out;
                }
                @keyframes slideIn {
                    from { transform: translateY(-50px); opacity: 0; }
                    to { transform: translateY(0); opacity: 1; }
                }
                .warning-icon {
                    font-size: 80px;
                    margin-bottom: 20px;
                    animation: pulse 2s infinite;
                }
                @keyframes pulse {
                    0%, 100% { transform: scale(1); }
                    50% { transform: scale(1.1); }
                }
                h1 {
                    font-size: 2.5em;
                    margin-bottom: 20px;
                    text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
                }
                .blocked-url {
                    background: rgba(255, 255, 255, 0.1);
                    padding: 15px;
                    border-radius: 10px;
                    font-family: monospace;
                    margin: 20px 0;
                    word-break: break-all;
                    border-left: 5px solid #ffff00;
                }
                .reason {
                    background: rgba(255, 255, 255, 0.1);
                    padding: 15px;
                    border-radius: 10px;
                    margin: 20px 0;
                    border-left: 5px solid #ff9900;
                }
                .buttons {
                    margin-top: 30px;
                }
                button {
                    padding: 15px 30px;
                    margin: 10px;
                    border: none;
                    border-radius: 10px;
                    font-size: 16px;
                    font-weight: bold;
                    cursor: pointer;
                    transition: all 0.3s ease;
                }
                .safe-button {
                    background: #28a745;
                    color: white;
                }
                .safe-button:hover {
                    background: #218838;
                    transform: translateY(-2px);
                }
                .danger-button {
                    background: #ff6b6b;
                    color: white;
                }
                .danger-button:hover {
                    background: #ff5252;
                    transform: translateY(-2px);
                }
                .details {
                    font-size: 14px;
                    opacity: 0.9;
                    margin-top: 20px;
                    text-align: left;
                }
                @media (max-width: 768px) {
                    .warning-container { padding: 20px; }
                    h1 { font-size: 2em; }
                    .warning-icon { font-size: 60px; }
                    button { width: 100%; margin: 5px 0; }
                }
            </style>
        </head>
        <body>
            <div class="warning-container">
                <div class="warning-icon">🚨</div>
                <h1>Malicious Website Blocked!</h1>
                <p style="font-size: 1.2em; margin-bottom: 20px;">
                    Our phishing detector has identified this website as potentially dangerous.
                </p>

                <div class="blocked-url">
                    <strong>Blocked URL:</strong><br>
                    ${blockInfo.details?.hostname || window.location.hostname}
                </div>

                <div class="reason">
                    <strong>Detection Method:</strong> ${blockInfo.reason}<br>
                    <strong>Risk Level:</strong> ${blockInfo.details?.confidence || 'High'}% confidence
                </div>

                ${blockInfo.details?.warnings ? `
                    <div class="details">
                        <strong>Warning Indicators:</strong>
                        <ul style="text-align: left; margin-top: 10px;">
                            ${blockInfo.details.warnings.map(warning => `<li>${warning}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}

                <div class="buttons">
                    <button class="safe-button" onclick="goBack()">
                        🔒 Go Back to Safety
                    </button>
                    <button class="danger-button" onclick="proceedAnyway()" 
                            style="background: #666; font-size: 14px;">
                        ⚠️ Proceed Anyway (Not Recommended)
                    </button>
                </div>

                <p style="font-size: 12px; opacity: 0.7; margin-top: 30px;">
                    Protected by Phishing Detector Extension
                </p>
            </div>

            <script>
                function goBack() {
                    if (window.history.length > 1) {
                        window.history.back();
                    } else {
                        window.location.href = 'about:blank';
                    }
                }

                function proceedAnyway() {
                    const warning = '⚠️ WARNING: You are about to visit a potentially malicious website.\n\nThis site may:\n• Steal your personal information\n• Install malware\n• Perform phishing attacks\n\nAre you absolutely sure you want to continue?';

                    if (confirm(warning)) {
                        // Store override decision and reload original URL
                        window.location.href = '${window.location.href}';
                    }
                }
            </script>
        </body>
        </html>
    `;
}

// Run check when page loads
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', checkCurrentPage);
} else {
    checkCurrentPage();
}

// Monitor for suspicious redirects (additional security)
let redirectCount = 0;
const originalLocation = window.location.href;

// Override common redirect methods used by malicious sites
const originalReplace = window.location.replace;
window.location.replace = function(url) {
    redirectCount++;
    if (redirectCount > 3) {
        console.log("Multiple redirects detected, potential malicious behavior");
    }
    return originalReplace.call(this, url);
};

console.log("Content script protection active for:", window.location.href);
