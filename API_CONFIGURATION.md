# API Configuration Guide

Before deploying this extension, you need to configure API keys for the security services.

## Required API Keys

### 1. Google Safe Browsing API (Required)
- **Get API Key**: https://console.cloud.google.com/
- **Enable**: Safe Browsing API
- **Cost**: Free tier available (10,000 requests/day)
- **File**: `popup.js` line ~177
- **Replace**: `YOUR_GOOGLE_SAFE_BROWSING_API_KEY_HERE`

### 2. VirusTotal API (Recommended)
- **Get API Key**: https://www.virustotal.com/gui/join-us
- **Cost**: Free tier available (4 requests/minute)
- **File**: `popup.js` line ~234
- **Replace**: `YOUR_VIRUSTOTAL_API_KEY_HERE`

## Optional APIs (Work without keys but provide limited functionality)

### 3. PhishTank API
- **Get API Key**: https://www.phishtank.com/api_info.php
- **Cost**: Free with rate limits
- **Note**: Currently works without API key

### 4. Other Services
- Sucuri SiteCheck - Public endpoint (no key needed)
- Norton Safe Web - Public endpoint (no key needed) 
- McAfee SiteAdvisor - Public endpoint (no key needed)

## Setup Instructions

1. **Get API Keys**: Register and obtain keys from the services above
2. **Update popup.js**: Replace placeholder text with your actual API keys
3. **Test Extension**: Load extension in developer mode and test functionality
4. **Deploy**: Package and submit to Chrome Web Store

## Rate Limits & Quotas

- **Google Safe Browsing**: 10,000 requests/day (free)
- **VirusTotal**: 4 requests/minute (free)
- **PhishTank**: Rate limited, no specific quota published
- **Other services**: Public endpoints with reasonable rate limits

## Security Note

- Never commit API keys to version control
- Use environment variables or secure configuration in production
- Regularly rotate API keys for security

## Testing

Test with known malicious URLs:
- `http://malware.testing.google.test/testing/malware/`
- `http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/`

**Important**: Only use these test URLs in development environments.
