function checkFraud() {
    let text = document.getElementById("inputText").value;

    fetch("https://sms-detector.onrender.com/check", {  // ✅ Use live backend
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text })  // ✅ Sending JSON data
    })
    .then(response => response.json())
    .then(data => { 
        document.getElementById("result").innerText = data.result; 
    })
    .catch(error => console.error("Error:", error));
}
// Integrated detection function
async function scanEverything() {
    const url = document.getElementById('url-input').value;
    const appUrl = document.getElementById('app-url').value;
    
    const results = await comprehensiveScan(url, appUrl);
    
    // Display combined results
    displayCombinedResults(results);
}

function displayCombinedResults(results) {
    let html = `
        <div class="combined-results">
            <h3>Comprehensive Security Scan</h3>
            <div class="website-result">
                <h4>🌐 Website: ${results.website.is_fraudulent ? '🚨 Risky' : '✅ Safe'}</h4>
                <p>Score: ${results.website.confidence}%</p>
            </div>
    `;
    
    if (results.app) {
        html += `
            <div class="app-result">
                <h4>📱 App: ${results.app.is_fake ? '🚨 Fake' : '✅ Legitimate'}</h4>
                <p>Score: ${results.app.confidence}%</p>
            </div>
        `;
    }
    
    html += `</div>`;
    document.getElementById('result').innerHTML = html;
}