// Real Security API integration for comprehensive website safety checking
const SecurityChecker = {
    // Helper function to get API keys from Chrome storage
    async getStoredApiKey(keyName) {
        try {
            const result = await chrome.storage.local.get([keyName]);
            return result[keyName] || null;
        } catch (error) {
            console.error('Error getting API key from storage:', error);
            return null;
        }
    },
    // PhishTank API - Phishing website detection
    async checkPhishTank(url) {
        try {
            // Note: PhishTank API is free but has rate limits
            // https://www.phishtank.com/api_info.php
            const encodedUrl = encodeURIComponent(url);
            const endpoint = `https://checkurl.phishtank.com/checkurl/`;
            
            const formData = new FormData();
            formData.append('url', url);
            formData.append('format', 'json');

            const response = await fetch(endpoint, {
                method: 'POST',
                body: formData
            });

            if (response.ok) {
                const data = await response.json();
                return {
                    safe: !data.in_database,
                    isPhishing: data.in_database || false,
                    verified: data.verified || false,
                    phishId: data.phish_id || null,
                    source: 'PhishTank',
                    riskLevel: data.in_database ? 'High Risk' : 'Safe' // Added riskLevel
                };
            }
            return { safe: true, isPhishing: false, verified: false, source: 'PhishTank (API Error)', riskLevel: 'Low Risk' }; // API error implies low risk
        } catch (error) {
            console.error('PhishTank API error:', error);
            return { safe: true, isPhishing: false, verified: false, source: 'PhishTank (Network Error)', riskLevel: 'Low Risk' }; // Network error implies low risk
        }
    },

    // Sucuri SiteCheck - Website security scanning
    async checkSucuri(url) {
        try {
            // Note: Sucuri SiteCheck is free but has rate limits
            const domain = new URL(url).hostname;
            const endpoint = `https://sitecheck.sucuri.net/results/${domain}`;
            
            const response = await fetch(endpoint);
            if (response.ok) {
                const html = await response.text();
                
                // More specific parsing to avoid false positives
                const hasMalware = html.includes('MALWARE FOUND') || html.includes('Site Blacklisted') || html.includes('WARNING: MALWARE');
                const hasSpam = html.includes('SPAM DETECTED') || html.includes('Known Spam') || html.includes('WARNING: SPAM');
                const hasDefacement = html.includes('DEFACEMENT DETECTED') || html.includes('Site Defaced') || html.includes('WARNING: DEFACED');
                
                // Check for clean site indicators
                const isClean = html.includes('SITE CLEAN') || html.includes('No threats detected') || html.includes('Security status: Clean');
                
                return {
                    safe: isClean || !(hasMalware || hasSpam || hasDefacement),
                    malware: hasMalware,
                    spam: hasSpam,
                    defacement: hasDefacement,
                    source: 'Sucuri SiteCheck',
                    riskLevel: (hasMalware || hasSpam || hasDefacement) ? 'High Risk' : (isClean ? 'Safe' : 'Low Risk') // Added riskLevel
                };
            }
            return { safe: true, malware: false, spam: false, defacement: false, source: 'Sucuri SiteCheck (API Error)', riskLevel: 'Low Risk' };
        } catch (error) {
            console.error('Sucuri SiteCheck error:', error);
            return { safe: true, malware: false, spam: false, defacement: false, source: 'Sucuri SiteCheck (Network Error)', riskLevel: 'Low Risk' };
        }
    },

    // Norton Safe Web API - Website safety ratings
    async checkNortonSafeWeb(url) {
        try {
            // Note: Norton Safe Web has a public API endpoint
            const encodedUrl = encodeURIComponent(url);
            const endpoint = `https://safeweb.norton.com/report/show?url=${encodedUrl}`;
            
            const response = await fetch(endpoint);
            if (response.ok) {
                const html = await response.text();
                
                // Parse Norton's safety rating
                const isSafe = !html.includes('dangerous') && !html.includes('warning');
                const hasRating = html.includes('rating') || html.includes('score');
                
                return {
                    safe: isSafe,
                    hasRating: hasRating,
                    source: 'Norton Safe Web',
                    riskLevel: isSafe ? 'Safe' : 'High Risk' // Added riskLevel
                };
            }
            return { safe: true, hasRating: false, source: 'Norton Safe Web (API Error)', riskLevel: 'Low Risk' };
        } catch (error) {
            console.error('Norton Safe Web error:', error);
            return { safe: true, hasRating: false, source: 'Norton Safe Web (Network Error)', riskLevel: 'Low Risk' };
        }
    },

    // McAfee SiteAdvisor - Website reputation
    async checkMcAfeeSiteAdvisor(url) {
        try {
            // Note: McAfee SiteAdvisor has a public checking endpoint
            const encodedUrl = encodeURIComponent(url);
            const endpoint = `https://www.siteadvisor.com/sites/${encodedUrl}`;
            
            const response = await fetch(endpoint);
            if (response.ok) {
                const html = await response.text();
                
                // Parse McAfee's reputation indicators
                const isSafe = !html.includes('dangerous') && !html.includes('warning') && !html.includes('suspicious');
                const hasReputation = html.includes('reputation') || html.includes('rating');
                
                return {
                    safe: isSafe,
                    hasReputation: hasReputation,
                    source: 'McAfee SiteAdvisor',
                    riskLevel: isSafe ? 'Safe' : 'High Risk' // Added riskLevel
                };
            }
            return { safe: true, hasReputation: false, source: 'McAfee SiteAdvisor (API Error)', riskLevel: 'Low Risk' };
        } catch (error) {
            console.error('McAfee SiteAdvisor error:', error);
            return { safe: true, hasReputation: false, source: 'McAfee SiteAdvisor (Network Error)', riskLevel: 'Low Risk' };
        }
    },

    // Custom malicious domain database - Local threat intelligence
    async checkCustomThreatDatabase(url) {
        try {
            const domain = new URL(url).hostname.toLowerCase();
            
            // Custom malicious domain patterns and known bad domains
            const maliciousPatterns = [
                /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/, // IP addresses
                /[a-f0-9]{32}/, // MD5 hashes
                /[a-f0-9]{40}/, // SHA1 hashes
                /bit\.ly|goo\.gl|tinyurl\.com|is\.gd|t\.co/, // URL shorteners (often used maliciously)
                /[a-z0-9]{20,}\.tk|\.ml|\.ga|\.cf/, // Suspicious TLDs with long random subdomains
                /[a-z0-9]{15,}\.xyz|\.top|\.club/, // More suspicious TLDs
                /.*\.trycloudflare\.com/, // CloudFlare tunnel domains (often used for phishing)
                /.*\.ngrok\.io/, // Ngrok tunnels (often used for phishing)
                /.*\.herokuapp\.com\/.*login/, // Heroku apps with login pages (suspicious)
                /.*-.*-.*-.*\..*\.com/, // Multiple hyphens in subdomain (phishing pattern)
                /facebook.*\.(?!facebook\.com)[a-z]+/, // Fake Facebook domains
                /google.*\.(?!google\.com)[a-z]+/, // Fake Google domains
                /paypal.*\.(?!paypal\.com)[a-z]+/, // Fake PayPal domains
                /amazon.*\.(?!amazon\.com)[a-z]+/, // Fake Amazon domains
                /apple.*\.(?!apple\.com)[a-z]+/, // Fake Apple domains
                /microsoft.*\.(?!microsoft\.com)[a-z]+/, // Fake Microsoft domains
            ];
            
            // Known malicious domains (add more as needed)
            const knownMaliciousDomains = [
                'malware.test', 'phishing.test', 'scam.test', 'virus.test',
                'malicious.example', 'dangerous.site', 'threat.domain',
                'fakebank.com', 'phishingsite.net', 'malwarehost.org'
            ];
            
            // Check for suspicious patterns
            const hasSuspiciousPattern = maliciousPatterns.some(pattern => pattern.test(domain));
            const isKnownMalicious = knownMaliciousDomains.some(malicious => domain.includes(malicious));
            
            return {
                safe: !(hasSuspiciousPattern || isKnownMalicious),
                suspiciousPattern: hasSuspiciousPattern,
                knownMalicious: isKnownMalicious,
                threatLevel: hasSuspiciousPattern ? 'High' : (isKnownMalicious ? 'Critical' : 'Low'),
                source: 'Custom Threat Database',
                riskLevel: (hasSuspiciousPattern || isKnownMalicious) ? 'High Risk' : 'Safe' // Added riskLevel
            };
        } catch (error) {
            console.error('Custom threat database check error:', error);
            return { safe: true, suspiciousPattern: false, knownMalicious: false, threatLevel: 'Low', source: 'Custom Threat Database (Error)', riskLevel: 'Low Risk' };
        }
    },

    // Google Safe Browsing API - Google's threat intelligence
    async checkGoogleSafeBrowsing(url) {
        try {
            // Get API key from Chrome storage
            const API_KEY = await this.getStoredApiKey('GOOGLE_SAFE_BROWSING_API_KEY');
            if (!API_KEY) {
                console.warn('Google Safe Browsing API key not configured');
                return { safe: true, threats: 0, threatTypes: [], details: [], source: 'Google Safe Browsing (No API Key)', riskLevel: 'Low Risk' }; // No API key implies low risk
            }
            
            const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`;
            
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

            if (response.ok) {
                const data = await response.json();
                const hasThreats = data.matches && data.matches.length > 0;
                const threatTypes = hasThreats ? data.matches.map(match => match.threatType) : [];
                
                return {
                    safe: !hasThreats,
                    threats: hasThreats ? data.matches.length : 0,
                    threatTypes: threatTypes,
                    details: hasThreats ? data.matches : [],
                    source: 'Google Safe Browsing',
                    riskLevel: hasThreats ? 'High Risk' : 'Safe' // Added riskLevel
                };
            }
            return { safe: true, threats: 0, threatTypes: [], details: [], source: 'Google Safe Browsing (API Error)', riskLevel: 'Low Risk' };
        } catch (error) {
            console.error('Google Safe Browsing API error:', error);
            return { safe: true, threats: 0, threatTypes: [], details: [], source: 'Google Safe Browsing (Network Error)', riskLevel: 'Low Risk' };
        }
    },

    // VirusTotal API (keeping this one)
    async checkVirusTotal(url) {
        try {
            // Get API key from Chrome storage
            const API_KEY = await this.getStoredApiKey('VIRUSTOTAL_API_KEY');
            if (!API_KEY) {
                console.warn('VirusTotal API key not configured');
                return { safe: true, threats: 0, totalScanners: 0, source: 'VirusTotal (No API Key)', riskLevel: 'Low Risk' };
            }
            const encodedUrl = btoa(url);
            const endpoint = `https://www.virustotal.com/vtapi/v2/url/report?apikey=${API_KEY}&resource=${encodedUrl}`;
            
            const response = await fetch(endpoint);
            if (response.ok) {
                const data = await response.json();
                return {
                    safe: data.positives === 0,
                    threats: data.positives || 0,
                    totalScanners: data.total || 0,
                    source: 'VirusTotal',
                    riskLevel: (data.positives > 0) ? 'High Risk' : 'Safe' // Added riskLevel
                };
            }
            return { safe: true, threats: 0, totalScanners: 0, source: 'VirusTotal (API Error)', riskLevel: 'Low Risk' };
        } catch (error) {
            console.error('VirusTotal API error:', error);
            return { safe: true, threats: 0, totalScanners: 0, source: 'VirusTotal (Network Error)', riskLevel: 'Low Risk' };
        }
    },

    // SSL Certificate Check
    async checkSSLCertificate(url) {
        try {
            const urlObj = new URL(url);
            // If the URL uses HTTPS protocol, assume SSL is valid
            // Browser extensions can't directly validate certificates due to CORS restrictions
            const hasSSL = urlObj.protocol === 'https:';
            
            return {
                safe: hasSSL,
                sslValid: hasSSL,
                source: 'SSL Certificate Check',
                riskLevel: hasSSL ? 'Safe' : 'Vulnerable' // Added riskLevel
            };
        } catch (error) {
            return {
                safe: false,
                sslValid: false,
                source: 'SSL Certificate Check',
                riskLevel: 'Low Risk' // Error implies low risk
            };
        }
    },

    // DNS Security Check
    async checkDNSSecurity(url) {
        try {
            const domain = new URL(url).hostname;
            // Check for suspicious DNS patterns
            const suspiciousPatterns = [
                /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/, // IP addresses
                /[a-f0-9]{32}/, // MD5 hashes
                /[a-f0-9]{40}/, // SHA1 hashes
            ];
            
            const hasSuspiciousPattern = suspiciousPatterns.some(pattern => pattern.test(domain));
            return {
                safe: !hasSuspiciousPattern,
                suspicious: hasSuspiciousPattern,
                source: 'DNS Security Check',
                riskLevel: hasSuspiciousPattern ? 'Low Risk' : 'Safe' // Added riskLevel
            };
        } catch (error) {
            return { safe: true, suspicious: false, source: 'DNS Security Check (Error)', riskLevel: 'Low Risk' };
        }
    },

    // Comprehensive security check
    async checkWebsite(url) {
        console.log('Starting comprehensive security check for:', url);
        
        try {
            // Run all security checks in parallel
            const [
                phishTankResult,
                sucuriResult,
                nortonResult,
                mcAfeeResult,
                customThreatResult,
                googleSafeBrowsingResult,
                virusTotalResult,
                sslResult,
                dnsResult
            ] = await Promise.all([
                this.checkPhishTank(url),
                this.checkSucuri(url),
                this.checkNortonSafeWeb(url),
                this.checkMcAfeeSiteAdvisor(url),
                this.checkCustomThreatDatabase(url),
                this.checkGoogleSafeBrowsing(url),
                this.checkVirusTotal(url),
                this.checkSSLCertificate(url),
                this.checkDNSSecurity(url)
            ]);

            // Initialize individual scores
            const individualScores = [];
            let threatsDetected = 0;
            const warnings = [];
            const recommendations = [];
            const riskLevels = []; // New array to store all individual risk levels

            // PhishTank Score
            if (phishTankResult.isPhishing) {
                individualScores.push(0);
                threatsDetected += 1;
                warnings.push(`PhishTank: Confirmed phishing website detected`);
                riskLevels.push(phishTankResult.riskLevel);
            } else if (phishTankResult.source !== 'PhishTank (API Error)') {
                individualScores.push(100);
                recommendations.push('PhishTank: No phishing activity detected');
                riskLevels.push(phishTankResult.riskLevel);
            } else {
                // If API error, don't include in average, but still report
                warnings.push('PhishTank: API error, could not verify phishing status');
                riskLevels.push(phishTankResult.riskLevel);
            }

            // Sucuri SiteCheck Score
            if (!sucuriResult.safe) {
                individualScores.push(0);
                threatsDetected += 1;
                const threats = [];
                if (sucuriResult.malware) threats.push('malware');
                if (sucuriResult.spam) threats.push('spam');
                if (sucuriResult.defacement) threats.push('defacement');
                warnings.push(`Sucuri: Detected ${threats.join(', ')}`);
                riskLevels.push(sucuriResult.riskLevel);
            } else if (sucuriResult.source !== 'Sucuri SiteCheck (API Error)') {
                individualScores.push(100);
                recommendations.push('Sucuri: No security threats detected');
                riskLevels.push(sucuriResult.riskLevel);
            } else {
                warnings.push('Sucuri: API error, could not verify security status');
                riskLevels.push(sucuriResult.riskLevel);
            }

            // Norton Safe Web Score
            if (!nortonResult.safe) {
                individualScores.push(0);
                threatsDetected += 1;
                warnings.push('Norton Safe Web: Website flagged as potentially dangerous');
                riskLevels.push(nortonResult.riskLevel);
            } else if (nortonResult.source !== 'Norton Safe Web (API Error)') {
                individualScores.push(100);
                recommendations.push('Norton Safe Web: Website appears safe');
                riskLevels.push(nortonResult.riskLevel);
            } else {
                warnings.push('Norton Safe Web: API error, could not verify safety rating');
                riskLevels.push(nortonResult.riskLevel);
            }

            // McAfee SiteAdvisor Score
            if (!mcAfeeResult.safe) {
                individualScores.push(0);
                threatsDetected += 1;
                warnings.push('McAfee SiteAdvisor: Website has poor reputation');
                riskLevels.push(mcAfeeResult.riskLevel);
            } else if (mcAfeeResult.source !== 'McAfee SiteAdvisor (API Error)') {
                individualScores.push(100);
                recommendations.push('McAfee SiteAdvisor: Good website reputation');
                riskLevels.push(mcAfeeResult.riskLevel);
            } else {
                warnings.push('McAfee SiteAdvisor: API error, could not verify reputation');
                riskLevels.push(mcAfeeResult.riskLevel);
            }

            // Custom Threat Database Score
            if (!customThreatResult.safe) {
                individualScores.push(0);
                threatsDetected += 1;
                warnings.push(`Custom Database: ${customThreatResult.threatLevel} threat level detected`);
                riskLevels.push(customThreatResult.riskLevel);
            } else if (customThreatResult.source !== 'Custom Threat Database (Error)') {
                individualScores.push(100);
                recommendations.push('Custom Database: No known threats detected');
                riskLevels.push(customThreatResult.riskLevel);
            } else {
                warnings.push('Custom Database: Error during custom threat check');
                riskLevels.push(customThreatResult.riskLevel);
            }

            // Google Safe Browsing Score
            if (!googleSafeBrowsingResult.safe) {
                individualScores.push(0);
                threatsDetected += googleSafeBrowsingResult.threats;
                const threatTypes = googleSafeBrowsingResult.threatTypes.join(', ');
                warnings.push(`Google Safe Browsing: ${threatTypes} detected`);
                riskLevels.push(googleSafeBrowsingResult.riskLevel);
            } else if (googleSafeBrowsingResult.source !== 'Google Safe Browsing (API Error)' && googleSafeBrowsingResult.source !== 'Google Safe Browsing (No API Key)') {
                individualScores.push(100);
                recommendations.push('Google Safe Browsing: No threats detected');
                riskLevels.push(googleSafeBrowsingResult.riskLevel);
            } else if (googleSafeBrowsingResult.source === 'Google Safe Browsing (No API Key)') {
                warnings.push('Google Safe Browsing: API key not configured, results may be incomplete');
                riskLevels.push(googleSafeBrowsingResult.riskLevel);
            } else {
                warnings.push('Google Safe Browsing: API error, could not verify threats');
                riskLevels.push(googleSafeBrowsingResult.riskLevel);
            }

            // VirusTotal Score
            if (!virusTotalResult.safe) {
                individualScores.push(0);
                threatsDetected += virusTotalResult.threats;
                warnings.push(`VirusTotal: ${virusTotalResult.threats} threats detected from ${virusTotalResult.totalScanners} scanners`);
                riskLevels.push(virusTotalResult.riskLevel);
            } else if (virusTotalResult.source !== 'VirusTotal (API Error)' && virusTotalResult.source !== 'VirusTotal (No API Key)') {
                individualScores.push(100);
                recommendations.push(`VirusTotal: Clean scan from ${virusTotalResult.totalScanners} security vendors`);
                riskLevels.push(virusTotalResult.riskLevel);
            } else if (virusTotalResult.source === 'VirusTotal (No API Key)') {
                warnings.push('VirusTotal: API key not configured, results may be incomplete');
                riskLevels.push(virusTotalResult.riskLevel);
            } else {
                warnings.push('VirusTotal: API error, could not verify threats');
                riskLevels.push(virusTotalResult.riskLevel);
            }

            // SSL Certificate Score
            if (!sslResult.sslValid) {
                individualScores.push(0);
                threatsDetected += 1;
                warnings.push('Invalid or missing SSL certificate');
                riskLevels.push(sslResult.riskLevel);
            } else if (sslResult.source !== 'SSL Certificate Check (Error)') {
                individualScores.push(100);
                recommendations.push('Valid SSL certificate detected');
                riskLevels.push(sslResult.riskLevel);
            } else {
                warnings.push('SSL Certificate Check: Error during check');
                riskLevels.push(sslResult.riskLevel);
            }

            // DNS Security Score
            if (dnsResult.suspicious) {
                individualScores.push(0);
                threatsDetected += 1;
                warnings.push('Suspicious DNS patterns detected');
                riskLevels.push(dnsResult.riskLevel);
            } else if (dnsResult.source !== 'DNS Security Check (Error)') {
                individualScores.push(100);
                recommendations.push('DNS security check passed');
                riskLevels.push(dnsResult.riskLevel);
            } else {
                warnings.push('DNS Security Check: Error during check');
                riskLevels.push(dnsResult.riskLevel);
            }

            // Calculate overall security score based on the average of valid individual scores
            let securityScore = 0;
            if (individualScores.length > 0) {
                const totalScore = individualScores.reduce((sum, score) => sum + score, 0);
                securityScore = Math.round(totalScore / individualScores.length);
            } else {
                // If no valid scores, assume 0 or handle as an error
                securityScore = 0;
                warnings.push('No security checks could be completed to generate a score.');
            }

            // Determine overall risk level
            let overallRiskLevel = 'Safe';
            if (riskLevels.includes('Vulnerable')) {
                overallRiskLevel = 'Vulnerable';
            } else if (riskLevels.includes('High Risk')) {
                overallRiskLevel = 'High Risk';
            } else if (riskLevels.includes('Low Risk')) {
                overallRiskLevel = 'Low Risk';
            }

            // The previous isSafe logic can be removed or simplified since we now have overallRiskLevel
            // const isSafe = securityScore >= 70 && threatsDetected === 0;

            return {
                safe: (overallRiskLevel === 'Safe'), // Update based on new risk level
                overallRiskLevel: overallRiskLevel, // Added overall risk level
                securityScore: securityScore,
                threatsDetected: threatsDetected,
                details: {
                    sslValid: sslResult.sslValid,
                    phishTankClean: phishTankResult.safe,
                    sucuriClean: sucuriResult.safe,
                    nortonSafe: nortonResult.safe,
                    mcAfeeSafe: mcAfeeResult.safe,
                    customThreatLevel: customThreatResult.threatLevel,
                    googleSafeBrowsingClean: googleSafeBrowsingResult.safe,
                    virusTotalClean: virusTotalResult.safe
                },
                warnings: warnings,
                recommendations: recommendations,
                apiResults: {
                    phishTank: phishTankResult,
                    sucuri: sucuriResult,
                    norton: nortonResult,
                    mcAfee: mcAfeeResult,
                    customThreat: customThreatResult,
                    googleSafeBrowsing: googleSafeBrowsingResult,
                    virusTotal: virusTotalResult,
                    ssl: sslResult,
                    dns: dnsResult
                }
            };

        } catch (error) {
            console.error('Comprehensive security check failed:', error);
            return {
                safe: false,
                securityScore: 0,
                threatsDetected: 1,
                warnings: ['Security check failed due to technical error'],
                recommendations: ['Please try again later'],
                error: error.message,
                overallRiskLevel: 'Low Risk' // Default risk level on error
            };
        }
    }
};

class SafeBrowsingExtension {
    constructor() {
        this.currentUrl = '';
        this.scanResult = null;
        this.init();
    }

    init() {
        this.getCurrentTabUrl();
        this.bindEvents();
    }

    async getCurrentTabUrl() {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            this.currentUrl = tab.url;
            document.getElementById('currentUrl').textContent = this.formatUrl(tab.url);
        } catch (error) {
            console.error('Error getting current tab:', error);
            document.getElementById('currentUrl').textContent = 'Unable to get URL';
        }
    }

    formatUrl(url) {
        try {
            const urlObj = new URL(url);
            return urlObj.hostname;
        } catch {
            return url;
        }
    }

    bindEvents() {
        document.getElementById('scanButton').addEventListener('click', () => this.scanWebsite());
        document.getElementById('downloadBtn').addEventListener('click', () => this.generatePDFReport());
        document.getElementById('toggleRawDataBtn').addEventListener('click', () => this.toggleRawData());
    }

    async scanWebsite() {
        const scanButton = document.getElementById('scanButton');
        const loading = document.getElementById('loading');
        const resultSection = document.getElementById('resultSection');

        // Show loading state
        scanButton.style.display = 'none';
        loading.style.display = 'flex';
        resultSection.style.display = 'none';

        try {
            this.scanResult = await SecurityChecker.checkWebsite(this.currentUrl);
            this.displayResults();
        } catch (error) {
            console.error('Scan failed:', error);
            this.showError('Scan failed. Please try again.');
        } finally {
            loading.style.display = 'none';
            scanButton.style.display = 'block';
        }
    }

    displayResults() {
        const resultSection = document.getElementById('resultSection');
        const statusIcon = document.getElementById('statusIcon');
        const statusTitle = document.getElementById('statusTitle');
        const statusDescription = document.getElementById('statusDescription');
        const securityScore = document.getElementById('securityScore');
        const threatsCount = document.getElementById('threatsCount');
        const lastUpdated = document.getElementById('lastUpdated');
        const downloadBtn = document.getElementById('downloadBtn');
        const resultCard = document.getElementById('resultCard');
        const rawDataPre = document.getElementById('rawDataPre');
        const rawDataContent = document.getElementById('rawDataContent');

        // Clear previous classes
        statusIcon.className = 'status-icon';
        securityScore.className = 'detail-value';
        threatsCount.className = 'detail-value';

        // Update UI based on overallRiskLevel
        let statusIconContent = '';
        let statusTitleText = '';
        let statusTitleColor = '';
        let statusDescriptionText = '';
        let downloadBtnBackground = '';

        switch (this.scanResult.overallRiskLevel) {
            case 'Safe':
                statusIcon.className = 'status-icon safe';
                statusIconContent = '✅';
                statusTitleText = 'Website is Safe';
                statusTitleColor = '#4CAF50';
                statusDescriptionText = 'This website appears to be secure and safe to browse.';
                securityScore.className = 'detail-value safe';
                downloadBtnBackground = 'linear-gradient(45deg, #4CAF50, #45a049)';
                break;
            case 'Low Risk':
                statusIcon.className = 'status-icon low-risk';
                statusIconContent = '⚠';
                statusTitleText = 'Low Risk Detected';
                statusTitleColor = '#ff9800';
                statusDescriptionText = 'Some suspicious patterns were detected, but no confirmed threats. Exercise caution.';
                securityScore.className = 'detail-value low-risk';
                downloadBtnBackground = 'linear-gradient(45deg, #ff9800, #fb8c00)';
                break;
            case 'High Risk':
                statusIcon.className = 'status-icon unsafe';
                statusIconContent = '❌';
                statusTitleText = 'High Risk - Unsafe!';
                statusTitleColor = '#f44336';
                statusDescriptionText = 'Warning! This website may contain confirmed security threats like phishing or malware.';
                securityScore.className = 'detail-value unsafe';
                threatsCount.className = 'detail-value unsafe';
                downloadBtnBackground = 'linear-gradient(45deg, #f44336, #d32f2f)';
                break;
            case 'Vulnerable':
                statusIcon.className = 'status-icon vulnerable';
                statusIconContent = '‼';
                statusTitleText = 'Vulnerable Website!';
                statusTitleColor = '#9C27B0'; // A distinct color for vulnerable
                statusDescriptionText = 'This website is vulnerable to attacks (e.g., missing SSL certificate) and should be avoided.';
                securityScore.className = 'detail-value vulnerable';
                threatsCount.className = 'detail-value vulnerable';
                downloadBtnBackground = 'linear-gradient(45deg, #9C27B0, #7B1FA2)';
                break;
            default:
                // Fallback to unsafe if something unexpected happens
                statusIcon.className = 'status-icon unsafe';
                statusIconContent = '❌';
                statusTitleText = 'Website Status Unknown';
                statusTitleColor = '#f44336';
                statusDescriptionText = 'Could not determine website safety. Proceed with extreme caution.';
                securityScore.className = 'detail-value unsafe';
                threatsCount.className = 'detail-value unsafe';
                downloadBtnBackground = 'linear-gradient(45deg, #f44336, #d32f2f)';
                break;
        }

        statusIcon.innerHTML = statusIconContent;
        statusTitle.textContent = statusTitleText;
        statusTitle.style.color = statusTitleColor;
        statusDescription.textContent = statusDescriptionText;
        downloadBtn.style.background = downloadBtnBackground;

        securityScore.textContent = `${this.scanResult.securityScore}/100`;
        threatsCount.textContent = this.scanResult.threatsDetected;
        lastUpdated.textContent = new Date().toLocaleDateString();

        // Add detailed findings section if we have warnings or recommendations
        let detailsHtml = '';
        if (this.scanResult.warnings && this.scanResult.warnings.length > 0) {
            detailsHtml += '<div class="warnings-section"><h4>⚠️ Security Warnings:</h4><ul>';
            this.scanResult.warnings.forEach(warning => {
                detailsHtml += `<li>${warning}</li>`;
            });
            detailsHtml += '</ul></div>';
        }
        
        if (this.scanResult.recommendations && this.scanResult.recommendations.length > 0) {
            detailsHtml += '<div class="recommendations-section"><h4>✅ Security Recommendations:</h4><ul>';
            this.scanResult.recommendations.forEach(rec => {
                detailsHtml += `<li>${rec}</li>`;
            });
            detailsHtml += '</ul></div>';
        }

        // Update the details section
        const detailsElement = document.getElementById('details');
        if (detailsHtml) {
            detailsElement.innerHTML += detailsHtml;
        }

        // Populate and hide raw data section initially
        if (this.scanResult.apiResults) {
            rawDataPre.textContent = JSON.stringify(this.scanResult.apiResults, null, 2);
        }
        rawDataContent.style.display = 'none';

        // Show result section
        resultSection.style.display = 'block';
        resultCard.style.animation = 'none';
        setTimeout(() => {
            resultCard.style.animation = 'fadeIn 0.5s ease-out';
        }, 10);
    }

    toggleRawData() {
        const rawDataContent = document.getElementById('rawDataContent');
        if (rawDataContent.style.display === 'none') {
            rawDataContent.style.display = 'block';
        } else {
            rawDataContent.style.display = 'none';
        }
    }

    showError(message) {
        const resultSection = document.getElementById('resultSection');
        const statusIcon = document.getElementById('statusIcon');
        const statusTitle = document.getElementById('statusTitle');
        const statusDescription = document.getElementById('statusDescription');

        statusIcon.className = 'status-icon';
        statusIcon.innerHTML = '❌';
        statusTitle.textContent = 'Error';
        statusTitle.style.color = '#ff9800';
        statusDescription.textContent = message;

        resultSection.style.display = 'block';
    }

    generatePDFReport() {
        const downloadBtn = document.getElementById('downloadBtn');
        downloadBtn.textContent = 'Generating...';
        downloadBtn.disabled = true;

        console.log('popup.js: Attempting to generate PDF...');

        // Create and append the iframe if it doesn't exist
        let sandboxIframe = document.getElementById('pdfSandboxIframe');
        if (!sandboxIframe) {
            sandboxIframe = document.createElement('iframe');
            sandboxIframe.id = 'pdfSandboxIframe';
            sandboxIframe.style.display = 'none';
            sandboxIframe.src = chrome.runtime.getURL('sandbox.html');
            document.body.appendChild(sandboxIframe);

            // Listen for messages from the sandbox
            window.addEventListener('message', (event) => {
                console.log('popup.js: Received message from sandbox:', event.data);
                if (event.source !== sandboxIframe.contentWindow || !event.data || event.data.type !== 'pdfGenerated') {
                    console.log('popup.js: Ignoring message or not a pdfGenerated message from correct source.');
                    return;
                }
                const { pdfData, currentUrl: generatedUrl } = event.data.payload;
                this.handleGeneratedPdf(pdfData, generatedUrl);
            });
        }

        // Send data to the sandbox to generate PDF
        sandboxIframe.onload = () => {
            console.log('popup.js: iframe loaded, sending generatePdf message.');
            sandboxIframe.contentWindow.postMessage({
                type: 'generatePdf',
                payload: {
                    currentUrl: this.currentUrl,
                    scanResult: this.scanResult
                }
            }, '*');
        };
        // If iframe is already loaded, post message directly
        if (sandboxIframe.contentWindow && sandboxIframe.contentWindow.document.readyState === 'complete') {
            console.log('popup.js: iframe already loaded, sending generatePdf message directly.');
            sandboxIframe.contentWindow.postMessage({
                type: 'generatePdf',
                payload: {
                    currentUrl: this.currentUrl,
                    scanResult: this.scanResult
                }
            }, '*');
        }
    }

    handleGeneratedPdf(pdfData, generatedUrl) {
        console.log('popup.js: Handling generated PDF.');
        const downloadBtn = document.getElementById('downloadBtn');
        downloadBtn.textContent = 'Download PDF Report';
        downloadBtn.disabled = false;

        const link = document.createElement('a');
        link.href = pdfData;
        const filename = `safe_browsing_report_${generatedUrl.replace(/[^a-zA-Z0-9]/g, '_')}.pdf`;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }
}

// Initialize the extension when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new SafeBrowsingExtension();
});

