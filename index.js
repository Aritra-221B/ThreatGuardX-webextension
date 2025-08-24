const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors'); // Import cors
const fetch = require('node-fetch'); // For making HTTP requests in Node.js

dotenv.config(); // Load environment variables from .env

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cors()); // Enable CORS for all routes

// Google Safe Browsing Proxy Endpoint
app.post('/api/google-safe-browsing', async (req, res) => {
    const GOOGLE_SAFE_BROWSING_API_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    if (!GOOGLE_SAFE_BROWSING_API_KEY) {
        return res.status(500).json({ error: 'Google Safe Browsing API key not configured on server.' });
    }

    try {
        const { url } = req.body;
        const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_API_KEY}`;
        
        const requestBody = {
            client: {
                clientId: "safe-browsing-extension",
                clientVersion: "1.0.0"
            },
            threatInfo: {
                threatTypes: [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [
                    { url: url }
                ]
            }
        };

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestBody)
        });

        const data = await response.json();
        res.json(data);

    } catch (error) {
        console.error('Proxy Google Safe Browsing error:', error);
        res.status(500).json({ error: 'Failed to proxy Google Safe Browsing request.' });
    }
});

// VirusTotal Proxy Endpoint
app.post('/api/virustotal', async (req, res) => {
    const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
    if (!VIRUSTOTAL_API_KEY) {
        return res.status(500).json({ error: 'VirusTotal API key not configured on server.' });
    }

    try {
        const { url } = req.body;
        const encodedUrl = Buffer.from(url).toString('base64'); // Node.js uses Buffer for base64
        const endpoint = `https://www.virustotal.com/vtapi/v2/url/report?apikey=${VIRUSTOTAL_API_KEY}&resource=${encodedUrl}`;
        
        const response = await fetch(endpoint);
        const data = await response.json();
        res.json(data);

    } catch (error) {
        console.error('Proxy VirusTotal error:', error);
        res.status(500).json({ error: 'Failed to proxy VirusTotal request.' });
    }
});

app.get('/', (req, res) => {
    res.send('ThreatGuardX Proxy is running!');
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
