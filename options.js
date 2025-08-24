// Options page script for managing API keys
document.addEventListener('DOMContentLoaded', async () => {
    const googleApiKeyInput = document.getElementById('googleApiKey');
    const virusTotalApiKeyInput = document.getElementById('virusTotalApiKey');
    const saveButton = document.getElementById('saveButton');
    const statusDiv = document.getElementById('status');

    // Load existing API keys
    try {
        const result = await chrome.storage.local.get(['GOOGLE_SAFE_BROWSING_API_KEY', 'VIRUSTOTAL_API_KEY']);
        googleApiKeyInput.value = result.GOOGLE_SAFE_BROWSING_API_KEY || '';
        virusTotalApiKeyInput.value = result.VIRUSTOTAL_API_KEY || '';
    } catch (error) {
        console.error('Error loading API keys:', error);
    }

    // Save API keys
    saveButton.addEventListener('click', async () => {
        try {
            const settings = {
                GOOGLE_SAFE_BROWSING_API_KEY: googleApiKeyInput.value.trim(),
                VIRUSTOTAL_API_KEY: virusTotalApiKeyInput.value.trim()
            };

            await chrome.storage.local.set(settings);
            
            showStatus('Settings saved successfully!', 'success');
        } catch (error) {
            console.error('Error saving API keys:', error);
            showStatus('Error saving settings. Please try again.', 'error');
        }
    });

    function showStatus(message, type) {
        statusDiv.textContent = message;
        statusDiv.className = `status ${type}`;
        statusDiv.style.display = 'block';
        
        setTimeout(() => {
            statusDiv.style.display = 'none';
        }, 3000);
    }
});
