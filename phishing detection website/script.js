// ========================================
// PHISHING DETECTION & SECURITY ANALYZER
// ========================================

// ========================================
// 1. LOCAL DATABASE - Phishing/Trusted Sites
// ========================================

const DATABASE = {
    knownPhishingDomains: [],

    // Trusted/legitimate domains (whitelist)
    trustedDomains: [
        'amazon.com',
        'paypal.com',
        'gmail.com',
        'google.com',
        'microsoft.com',
        'apple.com',
        'facebook.com',
        'twitter.com',
        'wikipedia.org',
        'github.com',
        'stackoverflow.com',
        'netflix.com',
        'banking-site.com',
        'linkedin.com',
        'instagram.com',
        'dropbox.com',
        'slack.com',
        'github.com',
        'adobe.com',
        'adobe.io'
    ]
};

const knownPhishingDomainsReady = fetch('/api/known-phishing-domains/')
    .then(response => {
        if (!response.ok) throw new Error(`Known phishing domain list request failed (${response.status})`);
        return response.json();
    })
    .then(result => {
        if (!Array.isArray(result.domains)) throw new Error('Known phishing domain list is invalid');
        DATABASE.knownPhishingDomains = result.domains;
        return result.domains;
    })
    .catch(error => {
        console.error('Known phishing domain list unavailable:', error);
        return [];
    });

// Global statistics tracker
const STATS = {
    totalScans: 0,
    safeCount: 0,
    warningCount: 0,
    dangerCount: 0,
    commonThreats: {}
};

const SCAN_HISTORY = [];

// ========================================
// 2. ANALYSIS SCORE TRACKING
// ========================================

let analysisScores = {
    totalScore: 0,
    riskFactors: [],
    recommendations: []
};

// ========================================
// 3. URL ANALYSIS FUNCTIONS
// ========================================

/**
 * Analyzes a given URL for phishing and security threats
 */
async function analyzeURL() {
    try {
        const urlInput = document.getElementById('url-input').value.trim();

        if (!urlInput) {
            showError('Please enter a URL to analyze');
            return;
        }

        if (urlInput.length > 2048) {
            showError('URL is too long (max 2048 characters)');
            return;
        }

        document.querySelectorAll('.error-notification').forEach(error => error.remove());
        document.getElementById('results-section').classList.add('hidden');
        const button = document.querySelector('#url-tab .analyze-btn');
        const loading = document.getElementById('url-loading');
        button.disabled = true;
        loading.classList.remove('hidden');

        try {
            const response = await fetch('/api/analyze/', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCookie('csrftoken')
                },
                body: JSON.stringify({ url: urlInput })
            });
            const result = await response.json().catch(() => ({}));
            if (!response.ok) {
                throw new Error(result.error || `Analysis request failed (${response.status})`);
            }
            displayBackendResults(result);
        } finally {
            button.disabled = false;
            loading.classList.add('hidden');
        }
    } catch (error) {
        console.error('URL Analysis Error:', error);
        showError(error.message || 'An error occurred while analyzing the URL. Please try again.');
    }
}

function getCookie(name) {
    const cookie = document.cookie.split('; ').find(value => value.startsWith(`${name}=`));
    return cookie ? decodeURIComponent(cookie.slice(name.length + 1)) : '';
}

function displayBackendResults(result) {
    const probability = Math.max(0, Math.min(1, Number(result.phishing_probability)));
    const riskScore = Math.max(0, Math.min(100, Number(result.risk_score)));
    const findingsRiskScore = Math.max(0, Math.min(100, Number(result.findings_risk_score)));
    if (
        ![probability, riskScore, findingsRiskScore].every(Number.isFinite) ||
        !['phishing', 'legitimate'].includes(result.prediction)
    ) {
        throw new Error('The analysis service returned an invalid result');
    }

    const riskClass = getRiskClassFromRiskScore(riskScore);
    const prediction = result.prediction === 'phishing' ? 'phishing' : 'legitimate';
    const legitimateClassification = prediction === 'legitimate';
    const securityRuleClassification = result.classification_source === 'security_rule';
    const findings = Array.isArray(result.findings) ? result.findings : [];
    const nsukLookalikeClassification = securityRuleClassification &&
        findings.some(finding => finding.code === 'nsuk_lookalike');
    const knownPhishingClassification = securityRuleClassification &&
        findings.some(finding => finding.code === 'known_phishing_domain');
    const riskCircle = document.getElementById('riskCircle');
    const riskLevel = document.getElementById('riskLevel');
    const riskMessage = document.getElementById('riskMessage');
    riskCircle.className = `risk-circle ${riskClass}`;
    riskCircle.classList.toggle('hidden', legitimateClassification);
    riskLevel.className = `risk-level ${legitimateClassification ? 'safe' : riskClass}`;
    riskLevel.textContent = legitimateClassification
        ? 'LEGITIMATE'
        : prediction === 'phishing' ? 'PHISHING'
            : riskClass === 'danger' ? 'HIGH RISK' : riskClass === 'warning' ? 'CAUTION' : 'LOW RISK';
    riskMessage.classList.toggle('legitimate-classification', legitimateClassification);
    if (legitimateClassification) {
        const title = document.createElement('strong');
        title.textContent = 'This website is legitimate';
        const description = document.createElement('span');
        description.textContent = 'No phishing threat was detected by the system.';
        riskMessage.replaceChildren(title, description);
    } else {
        document.getElementById('riskPercentage').textContent = Math.round(riskScore);
        riskMessage.textContent = securityRuleClassification
            ? nsukLookalikeClassification
                ? `This hostname resembles the official NSUK portal domain. Similarity alone does not confirm malicious intent; use an official NSUK source to verify the address.`
                : knownPhishingClassification
                    ? 'This hostname matches the known-phishing domain list. Do not enter sensitive information.'
                    : `A high-severity security finding triggered this phishing classification. The AI model's phishing probability is ${(probability * 100).toFixed(1)}%. Review the findings before proceeding.`
            : prediction === 'phishing'
                ? `The model predicts phishing (${(probability * 100).toFixed(1)}% probability). Do not enter sensitive information.`
                : `The model predicts a legitimate URL (${(probability * 100).toFixed(1)}% phishing probability). Review the findings before proceeding.`;
    }

    const analyzedUrl = new URL(result.url);
    document.getElementById('url-results').classList.remove('hidden');
    document.getElementById('analyzedDomain').textContent = analyzedUrl.hostname;
    document.getElementById('protocolStatus').textContent = analyzedUrl.protocol === 'https:'
        ? 'HTTPS (encrypted transport)' : 'HTTP (unencrypted transport)';

    const scoreBreakdownCard = document.getElementById('score-breakdown').closest('.detail-card');
    scoreBreakdownCard.classList.toggle('hidden', legitimateClassification);
    const flagsContainer = document.getElementById('url-flags');
    flagsContainer.replaceChildren(...findings.map(finding => createFlagElement({
        level: finding.severity === 'high' ? 'danger' : finding.severity === 'medium' ? 'warning' : 'safe',
        text: finding.code.replaceAll('_', ' '),
        detail: finding.message
    })));

    analysisScores = {
        ...analysisScores,
        totalScore: riskScore,
        riskFactors: findings.map(finding => ({ title: finding.code.replaceAll('_', ' '), explanation: finding.message })),
        recommendations: legitimateClassification
            ? findings.length > 0
                ? [{ title: 'Review security findings', explanation: 'The legitimate classification does not remove these security warnings.' }]
                : []
            : securityRuleClassification
                ? nsukLookalikeClassification
                    ? [{ title: 'Verify the NSUK portal address', explanation: 'This hostname resembles the official portal domain. Similarity alone does not confirm malicious intent; use an official NSUK source to verify the address.' }]
                    : knownPhishingClassification
                        ? [{ title: 'Avoid this known-phishing domain', explanation: 'Do not enter passwords, payment information, or other sensitive data.' }]
                        : [{ title: 'Review the brand-lookalike warning', explanation: 'Verify the domain through the brand\'s official website before proceeding.' }]
                : prediction === 'phishing' || riskScore >= 70
                    ? [{ title: 'Avoid this website', explanation: 'Do not enter passwords, payment information, or other sensitive data.' }]
                    : riskScore >= 30
                        ? [{ title: 'Proceed with caution', explanation: 'Verify the address through the organization\'s official website before sharing information.' }]
                        : [{ title: 'Continue to verify', explanation: 'A low model score is not a guarantee that a website is safe.' }]
    };
    displayRiskFactors();
    displayRecommendations();
    document.getElementById('recommendations').closest('.detail-card')
        .classList.toggle('hidden', legitimateClassification && findings.length === 0);

    const scoreLabels = ['ML phishing probability', 'Findings-based risk', 'Combined risk score', 'Decision threshold'];
    const scoreValues = [probability * 100, findingsRiskScore, riskScore, 50];
    document.querySelectorAll('#score-breakdown .score-label').forEach((label, index) => {
        label.textContent = `${scoreLabels[index]}:`;
    });
    ['url', 'domain', 'combined', 'security'].forEach((name, index) => {
        document.getElementById(`${name}Score`).style.width = `${scoreValues[index]}%`;
        document.getElementById(`${name}ScoreNum`).textContent = `${scoreValues[index].toFixed(1)}/100`;
    });

    document.querySelector('#results-section .results-container').classList.remove('hidden');
    document.querySelector('#results-section .analyze-btn.secondary').classList.remove('hidden');
    document.getElementById('results-section').classList.remove('hidden');
    saveToHistory({
        type: 'URL',
        value: result.url,
        domain: analyzedUrl.hostname,
        score: riskScore,
        scoreKind: 'model-risk',
        prediction,
        classificationSource: result.classification_source,
        phishingProbability: probability,
        modelVersion: result.model_version,
        timestamp: new Date().toLocaleString()
    });
    updateStats(100 - riskScore);
    document.getElementById('results-section').scrollIntoView({ behavior: 'smooth' });
}

function getRiskClassFromRiskScore(score) {
    if (score > 60) return 'danger';
    if (score > 30) return 'warning';
    return 'safe';
}

/**
 * Parses and extracts components from a URL
 */
function parseURL(urlString) {
    try {
        // Add protocol if missing
        if (!urlString.startsWith('http://') && !urlString.startsWith('https://')) {
            urlString = 'https://' + urlString;
        }

        const url = new URL(urlString);

        // Additional validation for domain structure
        if (!isValidDomain(url.hostname)) {
            return null;
        }

        return {
            original: urlString,
            protocol: url.protocol.replace(':', ''),
            domain: url.hostname,
            subdomain: getSubdomain(url.hostname),
            fullURL: url.href,
            pathname: url.pathname,
            searchParams: url.search
        };
    } catch (error) {
        return null;
    }
}

/**
 * Validates if a hostname is a properly formatted domain
 */
function isValidDomain(hostname) {
    // Check for IP addresses (basic validation)
    if (isIPAddress(hostname)) {
        return true; // Allow IP addresses
    }

    // Check for valid domain structure
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
    if (!domainRegex.test(hostname)) {
        return false;
    }

    // Must have at least one dot (except for localhost)
    if (hostname !== 'localhost' && !hostname.includes('.')) {
        return false;
    }

    // Check for valid TLD (at least 2 characters)
    const parts = hostname.split('.');
    const tld = parts[parts.length - 1];
    if (tld.length < 2) {
        return false;
    }

    // Reject obviously invalid domains
    const invalidPatterns = [
        /^[^\w]/,  // Starts with non-word character
        /[^\w]$/,  // Ends with non-word character
        /\.\./,    // Double dots
        /-\./,     // Dash followed by dot
        /\.-/,     // Dot followed by dash
        /--/,      // Double dashes
    ];

    return !invalidPatterns.some(pattern => pattern.test(hostname));
}

/**
 * Extracts subdomain from hostname
 */
function getSubdomain(hostname) {
    const parts = hostname.split('.');
    if (parts.length > 2) {
        return parts.slice(0, -2).join('.');
    }
    return null;
}

/**
 * Analyzes URL structure for suspicious patterns
 */
function analyzeURLStructure(urlData) {
    let urlPoints = 30;
    const flags = [];

    // Check 1: HTTPS Protocol
    if (urlData.protocol === 'http') {
        urlPoints -= 8;
        flags.push({
            level: 'danger',
            text: '[WARNING] Unsecure Protocol',
            detail: 'Uses HTTP instead of HTTPS. Data is not encrypted.'
        });
    }

    // Check 2: Suspicious characters in domain
    if (/[0-9]/g.test(urlData.domain.replace(/\d\./, ''))) {
        if (!isIPAddress(urlData.domain)) {
            urlPoints -= 6;
            flags.push({
                level: 'warning',
                text: '[WARNING] Numbers in Domain',
                detail: 'Domain contains numbers (common in phishing: amaz0n instead of amazon)'
            });
        }
    }

    // Check 3: IP Address instead of domain
    if (isIPAddress(urlData.domain)) {
        urlPoints -= 12;
        flags.push({
            level: 'danger',
            text: '[ERROR] IP Address Instead of Domain',
            detail: 'Uses IP address instead of domain name. Highly suspicious.'
        });
    }

    // Check 4: Very long URL
    if (urlData.fullURL.length > 100) {
        urlPoints -= 4;
        flags.push({
            level: 'warning',
            text: '[WARNING] Abnormally Long URL',
            detail: 'URL is unusually long, may be hiding parameters'
        });
    }

    // Check 5: Multiple subdomains
    if (urlData.subdomain && urlData.subdomain.split('.').length > 2) {
        urlPoints -= 5;
        flags.push({
            level: 'warning',
            text: '[WARNING] Multiple Subdomains',
            detail: 'Domain has multiple subdomain levels'
        });
    }

    // Check 6: Query parameters
    if (urlData.searchParams.length > 0) {
        urlPoints -= 2;
        flags.push({
            level: 'warning',
            text: '[INFO] URL Parameters Present',
            detail: 'URL contains query parameters'
        });
    }

    analysisScores.urlScore = Math.max(0, urlPoints);
    analysisScores.urlFlags = flags;
}

/**
 * Checks if string is an IP address
 */
function isIPAddress(str) {
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    return ipPattern.test(str);
}

/**
 * Analyzes domain reputation against known phishing/trusted lists
 */
function analyzeDomainReputation(urlData) {
    let domainPoints = 25;
    const flags = [];

    const domain = urlData.domain.toLowerCase();
    const baseDomain = domain.split('.').slice(-2).join('.');

    // Check 1: Known phishing domain
    if (DATABASE.knownPhishingDomains.includes(domain)) {
        domainPoints = 0;
        flags.push({
            level: 'danger',
            text: '[ERROR] Known Phishing Domain',
            detail: 'This domain is listed in known phishing databases'
        });
        analysisScores.riskFactors.push({
            title: 'Blacklisted Domain',
            explanation: 'This domain appears in phishing blacklists'
        });
    }

    // Check 2: Trusted/whitelisted domain
    if (DATABASE.trustedDomains.includes(domain) || DATABASE.trustedDomains.includes(baseDomain)) {
        flags.push({
            level: 'safe',
            text: '[OK] Trusted Domain',
            detail: 'This is a recognized legitimate company domain'
        });
    }

    // Check 3: Domain mimicking (homograph attacks)
    else {
        const homographMatches = findHomographMatches(domain);
        if (homographMatches.length > 0) {
            domainPoints -= 12;
            flags.push({
                level: 'danger',
                text: '[ERROR] Potential Homograph Attack',
                detail: `Domain appears to mimic: ${homographMatches.join(', ')}`
            });
            analysisScores.riskFactors.push({
                title: 'Domain Impersonation',
                explanation: `Domain closely resembles legitimate companies`
            });
        }
    }

    // Check 4: Suspicious TLD
    const tld = domain.split('.').pop();
    const suspiciousTLDs = ['tk', 'ml', 'ga', 'cf', 'pw', 'top', 'xyz'];
    if (suspiciousTLDs.includes(tld)) {
        domainPoints -= 5;
        flags.push({
            level: 'warning',
            text: '[WARNING] Suspicious TLD',
            detail: `Top-level domain .${tld} is often used in phishing`
        });
    }

    // Check 5: Brand-new domain (generic)
    if (domain.includes('verify') || domain.includes('confirm') || domain.includes('secure')) {
        domainPoints -= 6;
        flags.push({
            level: 'warning',
            text: '[WARNING] Suspicious Domain Name',
            detail: 'Domain contains generic security-related keywords'
        });
    }

    analysisScores.domainScore = Math.max(0, domainPoints);
    analysisScores.domainFlags = flags;
}

/**
 * Finds domains that appear to mimic legitimate companies
 */
function findHomographMatches(domain) {
    const matches = [];
    const commonBrands = ['amazon', 'paypal', 'gmail', 'google', 'microsoft', 'apple', 'netflix', 'facebook'];

    for (const brand of commonBrands) {
        const baseDomain = domain.split('.')[0];
        // Check for similar characters (0 vs O, 1 vs l, etc.)
        if (calculateSimilarity(baseDomain, brand) > 0.75) {
            matches.push(brand);
        }
    }

    return matches;
}

/**
 * Calculates string similarity for homograph detection
 */
function calculateSimilarity(str1, str2) {
    const longer = str1.length > str2.length ? str1 : str2;
    const shorter = str1.length > str2.length ? str2 : str1;

    if (longer.length === 0) return 1.0;

    const editDistance = getEditDistance(longer, shorter);
    return (longer.length - editDistance) / longer.length;
}

/**
 * Calculates Levenshtein distance for string comparison
 */
function getEditDistance(s1, s2) {
    const costs = [];
    for (let i = 0; i <= s1.length; i++) {
        let lastValue = i;
        for (let j = 0; j <= s2.length; j++) {
            if (i === 0) {
                costs[j] = j;
            } else if (j > 0) {
                let newValue = costs[j - 1];
                if (s1.charAt(i - 1) !== s2.charAt(j - 1)) {
                    newValue = Math.min(Math.min(newValue, lastValue), costs[j]) + 1;
                }
                costs[j - 1] = lastValue;
                lastValue = newValue;
            }
        }
        if (i > 0) costs[s2.length] = lastValue;
    }
    return costs[s2.length];
}

/**
 * Analyzes security indicators (HTTPS, headers, etc.)
 */
function analyzeSecurityIndicators(urlData) {
    let securityPoints = 20;
    const flags = [];

    // Check 1: HTTPS
    if (urlData.protocol === 'https') {
        flags.push({
            level: 'safe',
            text: '[OK] HTTPS/SSL Enabled',
            detail: 'Connection is encrypted (secure)'
        });
    }

    // Check 2: Path indicators
    if (urlData.pathname === '/' && !urlData.searchParams) {
        flags.push({
            level: 'safe',
            text: '[OK] Standard Page Structure',
            detail: 'URL follows normal directory structure'
        });
    }

    // Check 3: Suspicious paths
    if (urlData.pathname.includes('login') || urlData.pathname.includes('signin')) {
        securityPoints -= 3;
        flags.push({
            level: 'warning',
            text: '[WARNING] Login Page Detected',
            detail: 'This page contains a login form'
        });
    }

    analysisScores.securityScore = Math.max(0, securityPoints);
    analysisScores.securityFlags = flags;
}

// ========================================
// 5. RESULT DISPLAY FUNCTIONS
// ========================================

/**
 * Determines risk level based on score
 */
function getRiskLevel(score) {
    if (score >= 70) return { level: 'safe', label: '[OK] SAFE', color: 'safe' };
    if (score >= 40) return { level: 'warning', label: '[WARNING]', color: 'warning' };
    return { level: 'danger', label: '[ERROR] DANGER', color: 'danger' };
}

// ========================================
// 6. RESULT DISPLAY FUNCTIONS
// ========================================

/**
 * Displays URL analysis results
 */
function displayURLResults(urlData) {
    const urlResultsDiv = document.getElementById('url-results');
    urlResultsDiv.classList.remove('hidden');

    // Update basic info
    document.getElementById('analyzedDomain').textContent = urlData.domain;
    document.getElementById('protocolStatus').textContent = 
        urlData.protocol === 'https' ? '✓ HTTPS (Secure)' : '❌ HTTP (Unsecure)';

    // Display flags
    const flagsContainer = document.getElementById('url-flags');
    flagsContainer.innerHTML = '';
    (analysisScores.urlFlags || []).forEach(flag => {
        const flagEl = createFlagElement(flag);
        flagsContainer.appendChild(flagEl);
    });

    (analysisScores.domainFlags || []).forEach(flag => {
        const flagEl = createFlagElement(flag);
        flagsContainer.appendChild(flagEl);
    });

    (analysisScores.securityFlags || []).forEach(flag => {
        const flagEl = createFlagElement(flag);
        flagsContainer.appendChild(flagEl);
    });
}

/**
 * Creates a flag element
 */
function createFlagElement(flag) {
    const div = document.createElement('div');
    div.className = `flag ${flag.level}`;
    div.innerHTML = `
        <span class="flag-icon">${flag.level === 'danger' ? '[ERROR]' : flag.level === 'warning' ? '[WARNING]' : '[OK]'}</span>
        <div>
            <strong>${flag.text}</strong>
            <p>${flag.detail}</p>
        </div>
    `;
    return div;
}

/**
 * Displays detected risk factors
 */
function displayRiskFactors() {
    const factorsContainer = document.getElementById('risk-factors');
    factorsContainer.innerHTML = '';

    if (analysisScores.riskFactors.length === 0) {
        factorsContainer.innerHTML = '<p class="no-data">No risk factors detected</p>';
        return;
    }

    analysisScores.riskFactors.forEach(factor => {
        const div = document.createElement('div');
        div.className = 'risk-factor';
        div.innerHTML = `
            <strong>⚠️ ${factor.title}</strong>
            <div class="explanation">${factor.explanation}</div>
        `;
        factorsContainer.appendChild(div);
    });
}

/**
 * Displays security recommendations
 */
function displayRecommendations() {
    const recsContainer = document.getElementById('recommendations');
    recsContainer.innerHTML = '';

    if (analysisScores.recommendations.length === 0) {
        recsContainer.innerHTML = '<p class="no-data">No recommendations available</p>';
        return;
    }

    analysisScores.recommendations.forEach(rec => {
        const div = document.createElement('div');
        div.className = 'recommendation';
        div.innerHTML = `
            <strong>💡 ${rec.title}</strong>
            <div class="explanation">${rec.explanation}</div>
        `;
        recsContainer.appendChild(div);
    });
}

// ========================================
// 7. HISTORY MANAGEMENT
// ========================================

/**
 * Saves analysis to the current page session
 */
function saveToHistory(scanData) {
    SCAN_HISTORY.unshift(scanData);
    SCAN_HISTORY.splice(50);
    displayHistory();
}

/**
 * Displays scans from the current page session
 */
function displayHistory() {
    const historyList = document.getElementById('history-list');
    const history = SCAN_HISTORY;

    if (history.length === 0) {
        historyList.innerHTML = '<p class="no-data">No scans yet. Start by assessing a URL.</p>';
        return;
    }

    historyList.innerHTML = '';
    history.forEach((scan, index) => {
        const div = document.createElement('div');
        div.className = 'history-item';
        const isLegitimate = scan.prediction === 'legitimate';
        const isModelRisk = scan.scoreKind === 'model-risk';
        const numericScore = Number(scan.score);
        const badgeClass = isLegitimate
            ? 'safe'
            : isModelRisk
                ? getRiskClassFromRiskScore(numericScore)
                : getRiskLevel(numericScore).level;
        const badgeText = isLegitimate
            ? 'LEGITIMATE'
            : isModelRisk
                ? `Risk ${numericScore.toFixed(2)}/100`
                : `${scan.score}%`;
        const source = isLegitimate
            ? 'URL · legitimate'
            : scan.classificationSource === 'security_rule'
                ? 'URL · security rule'
                : isModelRisk
                    ? `URL · ML model ${typeof scan.modelVersion === 'string' ? scan.modelVersion.slice(0, 8) : '(version unknown)'}`
                    : 'URL · legacy heuristic';

        const header = document.createElement('div');
        header.className = 'history-item-header';
        const title = document.createElement('span');
        title.className = 'history-item-title';
        title.textContent = scan.value;
        const badge = document.createElement('span');
        badge.className = `history-item-badge badge ${badgeClass}`;
        badge.textContent = badgeText;
        const deleteButton = document.createElement('span');
        deleteButton.className = 'history-item-delete';
        deleteButton.textContent = '×';
        deleteButton.setAttribute('role', 'button');
        deleteButton.setAttribute('aria-label', `Delete scan ${index + 1}`);
        deleteButton.addEventListener('click', event => {
            event.stopPropagation();
            deleteHistoryItem(index);
        });
        header.append(title, badge, deleteButton);

        const details = document.createElement('div');
        details.className = 'history-item-details';
        const type = document.createElement('p');
        const typeLabel = document.createElement('strong');
        typeLabel.textContent = 'Type: ';
        type.append(typeLabel, document.createTextNode(source));
        const date = document.createElement('p');
        const dateLabel = document.createElement('strong');
        dateLabel.textContent = 'Date: ';
        date.append(dateLabel, document.createTextNode(scan.timestamp));
        details.append(type, date);
        div.append(header, details);

        div.addEventListener('click', (e) => {
            if (!e.target.closest('.history-item-delete')) {
                // Load previous analysis
                if (scan.type === 'URL') {
                    document.getElementById('url-input').value = scan.value;
                    // Optionally re-analyze
                }
            }
        });
        
        historyList.appendChild(div);
    });
}

/**
 * Deletes a history item
 */
function deleteHistoryItem(index) {
    SCAN_HISTORY.splice(index, 1);
    displayHistory();
}

/**
 * Clears all scan history
 */
function clearHistory() {
    if (confirm('Are you sure you want to clear all scan history?')) {
        SCAN_HISTORY.length = 0;
        displayHistory();
    }
}

/**
 * Shows error message to user
 */
function showError(message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-notification';
    errorDiv.style.cssText = 'background: #ffebee; color: #c62828; padding: 15px; border-radius: 6px; margin-bottom: 20px; border-left: 4px solid #d32f2f;';
    const heading = document.createElement('strong');
    heading.textContent = 'Error: ';
    errorDiv.append(heading, document.createTextNode(message));
    
    const resultsSection = document.getElementById('results-section');
    resultsSection.querySelector('.results-container').classList.add('hidden');
    resultsSection.querySelector('.analyze-btn.secondary').classList.add('hidden');
    if (resultsSection.firstChild) {
        resultsSection.insertBefore(errorDiv, resultsSection.firstChild);
    } else {
        resultsSection.appendChild(errorDiv);
    }
    
    resultsSection.classList.remove('hidden');
    resultsSection.scrollIntoView({ behavior: 'smooth' });
    
    // Remove error after 5 seconds
    setTimeout(() => errorDiv.remove(), 5000);
}

/**
 * Updates global statistics
 */
function updateStats(score) {
    STATS.totalScans++;
    
    if (score >= 70) STATS.safeCount++;
    else if (score >= 40) STATS.warningCount++;
    else STATS.dangerCount++;
    
    // Update display
    displayStatistics();
}

/**
 * Gets scan statistics
 */
function getStatistics() {
    return {
        totalScans: STATS.totalScans,
        safePercentage: STATS.totalScans > 0 ? Math.round((STATS.safeCount / STATS.totalScans) * 100) : 0,
        warningPercentage: STATS.totalScans > 0 ? Math.round((STATS.warningCount / STATS.totalScans) * 100) : 0,
        dangerPercentage: STATS.totalScans > 0 ? Math.round((STATS.dangerCount / STATS.totalScans) * 100) : 0,
        safeCount: STATS.safeCount,
        warningCount: STATS.warningCount,
        dangerCount: STATS.dangerCount
    };
}

/**
 * Displays statistics on the dashboard
 */
function displayStatistics() {
    const stats = getStatistics();
    
    // Update stat cards
    document.getElementById('totalScans').textContent = stats.totalScans;
    document.getElementById('safeScans').textContent = stats.safeCount;
    document.getElementById('warningScans').textContent = stats.warningCount;
    document.getElementById('dangerScans').textContent = stats.dangerCount;
    
    // Update bar chart
    document.getElementById('barSafe').style.width = stats.safePercentage + '%';
    document.getElementById('barWarning').style.width = stats.warningPercentage + '%';
    document.getElementById('barDanger').style.width = stats.dangerPercentage + '%';
    
    document.getElementById('percentSafe').textContent = stats.safePercentage + '%';
    document.getElementById('percentWarning').textContent = stats.warningPercentage + '%';
    document.getElementById('percentDanger').textContent = stats.dangerPercentage + '%';
}

// ========================================
// 8. UTILITY FUNCTIONS
// ========================================

/**
 * Clears results and resets the page
 */
function clearResults() {
    document.getElementById('results-section').classList.add('hidden');
    document.getElementById('url-input').value = '';
    document.getElementById('url-validation-feedback')?.remove();
    document.querySelectorAll('.error-notification').forEach(error => error.remove());
    analysisScores = { totalScore: 0, riskFactors: [], recommendations: [] };
}

function resetAssessmentState() {
    document.getElementById('url-input').value = '';
    document.getElementById('url-validation-feedback')?.remove();
    document.querySelectorAll('.error-notification').forEach(error => error.remove());

    document.querySelector('#url-tab .analyze-btn').disabled = false;
    document.getElementById('url-loading').classList.add('hidden');

    const resultsSection = document.getElementById('results-section');
    resultsSection.classList.add('hidden');
    resultsSection.querySelector('.results-container').classList.remove('hidden');
    resultsSection.querySelector('.analyze-btn.secondary').classList.remove('hidden');
    document.getElementById('riskCircle').className = 'risk-circle';
    document.getElementById('riskCircle').classList.remove('hidden');
    document.getElementById('riskPercentage').textContent = '0';
    document.getElementById('riskLevel').className = 'risk-level';
    document.getElementById('riskLevel').textContent = 'Assessing…';
    const riskMessage = document.getElementById('riskMessage');
    riskMessage.replaceChildren();
    riskMessage.classList.remove('legitimate-classification');
    document.getElementById('url-results').classList.add('hidden');
    document.getElementById('score-breakdown').closest('.detail-card').classList.remove('hidden');
    document.getElementById('recommendations').closest('.detail-card').classList.remove('hidden');
    document.getElementById('analyzedDomain').textContent = '-';
    document.getElementById('protocolStatus').textContent = '-';
    document.getElementById('url-flags').replaceChildren();
    document.getElementById('risk-factors').innerHTML = '<p class="no-data">No risk factors detected yet.</p>';
    document.getElementById('recommendations').innerHTML = '<p class="no-data">No action required at this time.</p>';
    document.querySelectorAll('#score-breakdown .score-fill').forEach(fill => {
        fill.style.width = '0%';
    });
    document.querySelectorAll('#score-breakdown .score-number').forEach(number => {
        number.textContent = '0.0/100';
    });

    analysisScores = { totalScore: 0, riskFactors: [], recommendations: [] };
    Object.assign(STATS, {
        totalScans: 0,
        safeCount: 0,
        warningCount: 0,
        dangerCount: 0,
        commonThreats: {}
    });
    SCAN_HISTORY.length = 0;
    try {
        localStorage.removeItem('scanHistory');
        localStorage.removeItem('scanStats');
    } catch {
        // Storage may be unavailable in restricted browser contexts.
    }
    displayHistory();
    displayStatistics();
}

/**
 * Real-time URL validation feedback
 */
function validateURLInput() {
    const urlInput = document.getElementById('url-input');
    const urlValue = urlInput.value.trim();

    // Clear existing feedback
    let feedbackDiv = document.getElementById('url-validation-feedback');
    if (feedbackDiv) feedbackDiv.remove();

    if (!urlValue) return;

    // First check: basic format validation
    if (!urlValue.includes('.') && !isIPAddress(urlValue)) {
        feedbackDiv = document.createElement('div');
        feedbackDiv.id = 'url-validation-feedback';
        feedbackDiv.style.cssText = 'color: #c62828; font-size: 0.9em; margin-top: 8px; padding: 8px; background: #ffebee; border-radius: 4px; border-left: 3px solid #d32f2f;';
        feedbackDiv.textContent = 'Invalid format: URLs must contain a domain (e.g., example.com)';
        urlInput.parentElement.appendChild(feedbackDiv);
        return;
    }

    // Second check: parse URL
    const urlData = parseURL(urlValue);
    if (!urlData) {
        feedbackDiv = document.createElement('div');
        feedbackDiv.id = 'url-validation-feedback';
        feedbackDiv.style.cssText = 'color: #c62828; font-size: 0.9em; margin-top: 8px; padding: 8px; background: #ffebee; border-radius: 4px; border-left: 3px solid #d32f2f;';
        feedbackDiv.textContent = 'Invalid URL format. Please enter a valid URL (e.g., https://example.com)';
        urlInput.parentElement.appendChild(feedbackDiv);
        return;
    }

    // Third check: domain validation
    if (!isValidDomain(urlData.domain)) {
        feedbackDiv = document.createElement('div');
        feedbackDiv.id = 'url-validation-feedback';
        feedbackDiv.style.cssText = 'color: #c62828; font-size: 0.9em; margin-top: 8px; padding: 8px; background: #ffebee; border-radius: 4px; border-left: 3px solid #d32f2f;';
        feedbackDiv.textContent = 'Invalid domain name. Domain names must contain only letters, numbers, hyphens, and periods.';
        urlInput.parentElement.appendChild(feedbackDiv);
        return;
    }

    // Check for suspicious indicators
    const warnings = [];

    if (urlData.protocol === 'http') {
        warnings.push('HTTP (unsecure) - no encryption');
    }

    if (isIPAddress(urlData.domain)) {
        warnings.push('IP address detected - suspicious');
    }

    if (/[0-9]/g.test(urlData.domain.replace(/\d\./, ''))) {
        warnings.push('Numbers in domain - possible homograph');
    }

    if (urlValue.length > 100) {
        warnings.push('Very long URL - suspicious');
    }

    if (DATABASE.knownPhishingDomains.includes(urlData.domain)) {
        warnings.push('Known phishing domain');
    }

    if (warnings.length > 0) {
        feedbackDiv = document.createElement('div');
        feedbackDiv.id = 'url-validation-feedback';
        feedbackDiv.style.cssText = 'color: #e65100; font-size: 0.9em; margin-top: 8px; padding: 10px; background: #fff3e0; border-radius: 4px; border-left: 3px solid #ff6f00;';
        feedbackDiv.innerHTML = '<strong>Quick flags:</strong> ' + warnings.join(', ');
        urlInput.parentElement.appendChild(feedbackDiv);
    } else {
        feedbackDiv = document.createElement('div');
        feedbackDiv.id = 'url-validation-feedback';
        feedbackDiv.style.cssText = 'color: #1b5e20; font-size: 0.9em; margin-top: 8px; padding: 10px; background: #e8f5e9; border-radius: 4px; border-left: 3px solid #2e7d32;';
        feedbackDiv.textContent = 'URL format looks valid - click analyze for full security scan';
        urlInput.parentElement.appendChild(feedbackDiv);
    }
}

document.addEventListener('DOMContentLoaded', function() {
    resetAssessmentState();
    displayHistory();

    // Real-time URL validation
    const urlInput = document.getElementById('url-input');
    urlInput.addEventListener('input', validateURLInput);
    urlInput.addEventListener('change', validateURLInput);
    knownPhishingDomainsReady.then(() => {
        if (urlInput.value.trim()) validateURLInput();
    });

    // Enter key support for quick analysis
    urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') analyzeURL();
    });

});

window.addEventListener('pageshow', event => {
    if (event.persisted) resetAssessmentState();
});
