// Run this script in the browser console on your extension's options page
// to automatically load API keys from your environment

async function loadApiKeysFromEnv() {
    // You'll need to manually copy the API_KEY value from your .env.local file
    const googleApiKey = 'YOUR_API_KEY_FROM_ENV_LOCAL'; // Replace with actual key from .env.local
    const virusTotalApiKey = 'YOUR_VIRUSTOTAL_KEY'; // Replace with actual VirusTotal key if you have one
    
    try {
        await chrome.storage.local.set({
            'GOOGLE_SAFE_BROWSING_API_KEY': googleApiKey,
            'VIRUSTOTAL_API_KEY': virusTotalApiKey
        });
        
        console.log('API keys loaded successfully!');
        
        // Refresh the options page to show the loaded keys
        location.reload();
    } catch (error) {
        console.error('Error loading API keys:', error);
    }
}

// Instructions:
// 1. Open the extension options page (right-click extension icon → Options)
// 2. Open browser console (F12)
// 3. Replace 'YOUR_API_KEY_FROM_ENV_LOCAL' with your actual API key from .env.local
// 4. Run: loadApiKeysFromEnv()
