document.addEventListener('DOMContentLoaded', async function() {
  // Retrieve blocked URL info and details
  const data = await chrome.storage.local.get(['blockedUrl', 'blockDetails']);
  // Set blocked URL
  document.getElementById('blocked-url').textContent = data.blockedUrl || "Unknown";

  // Get detection warnings from blockDetails
  const flawsList = document.getElementById('security-flaws');
  flawsList.innerHTML = '';

  if (data.blockDetails && data.blockDetails.warnings && data.blockDetails.warnings.length > 0) {
    data.blockDetails.warnings.forEach(flaw => {
      const li = document.createElement('li');
      li.textContent = flaw;
      flawsList.appendChild(li);
    });
  } else {
    const li = document.createElement('li');
    li.textContent = "No detailed security flaws listed.";
    flawsList.appendChild(li);
  }
});
