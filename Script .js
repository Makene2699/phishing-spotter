/* ---------- Detection rules ---------- */
const RULES = [
  {
    category: 'Urgency & Pressure',
    severity: 'high',
    why: 'Phishing relies on rushing you past caution. Legitimate institutions rarely demand action within hours.',
    patterns: [
      /act\s+(now|immediately|fast)/i,
      /within\s+\d+\s*(hours?|days?)/i,
      /(final|last)\s+(notice|warning|reminder)/i,
      /immediate(ly)?\s+action\s+(is\s+)?required/i,
      /your\s+account\s+(will\s+be|has\s+been)\s+(suspend|lock|clos|deactivat)/i,
      /failure\s+to\s+(respond|comply|verify)/i,
      /verify\s+(your\s+account\s+)?(now|immediately|today)/i
    ]
  },
  {
    category: 'Credential / Sensitive Data Request',
    severity: 'high',
    why: 'Real companies don\'t ask you to confirm passwords, card numbers, or one-time codes over email or chat.',
    patterns: [
      /(enter|confirm|verify|re-?enter|provide|update)\s+your\s+(password|pin|otp|one[- ]time\s+(code|pass(word)?)|card\s+(number|details)|cvv|ssn|social\s+security|id\s+number)/i,
      /update\s+(your\s+)?(payment|billing)\s+(information|details|method)/i,
      /login\s+to\s+confirm/i
    ]
  },
  {
    category: 'Generic / Impersonal Greeting',
    severity: 'low',
    why: 'Real providers you have an account with usually greet you by name, not a generic title.',
    patterns: [
      /dear\s+(customer|user|valued\s+customer|member|account\s+holder|sir\/madam)/i
    ]
  },
  {
    category: 'Shortened / Obscured Link',
    severity: 'medium',
    why: 'URL shorteners hide the real destination, a common trick to disguise a malicious domain.',
    patterns: [
      /\b(bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|rebrand\.ly|ow\.ly|cutt\.ly)\b/i
    ]
  },
  {
    category: 'Suspicious Attachment Bait',
    severity: 'medium',
    why: 'Executable or script-like attachments are a common malware delivery method, especially when paired with urgency.',
    patterns: [
      /\.(exe|scr|js|jar|vbs|bat)\b/i,
      /open\s+the\s+attach(ed|ment)/i
    ]
  },
  {
    category: 'Too-Good-To-Be-True Offer',
    severity: 'medium',
    why: 'Unexpected prizes or refunds are a classic lure to get you clicking before you think.',
    patterns: [
      /you('ve|\s+have)\s+won/i,
      /claim\s+your\s+(prize|reward|refund)/i,
      /free\s+(gift|iphone|voucher)/i
    ]
  },
  {
    category: 'Threatening / Legal Language',
    severity: 'medium',
    why: 'Fear of legal or financial consequences is used to override skepticism.',
    patterns: [
      /legal\s+action\s+will\s+be\s+taken/i,
      /you\s+will\s+be\s+(fined|charged|reported)/i
    ]
  }
];

/* Known brands -> official registrable domain (South Africa-aware) */
const KNOWN_BRANDS = {
  paypal: 'paypal.com',
  apple: 'apple.com',
  microsoft: 'microsoft.com',
  amazon: 'amazon.com',
  netflix: 'netflix.com',
  google: 'google.com',
  facebook: 'facebook.com',
  instagram: 'instagram.com',
  linkedin: 'linkedin.com',
  fnb: 'fnb.co.za',
  'first national bank': 'fnb.co.za',
  'standard bank': 'standardbank.co.za',
  absa: 'absa.co.za',
  capitec: 'capitecbank.co.za',
  nedbank: 'nedbank.co.za',
  sars: 'sars.gov.za',
  discovery: 'discovery.co.za'
};

/* ---------- Helpers ---------- */
function extractUrls(text){
  const re = /\bhttps?:\/\/[^\s"'<>]+/gi;
  return text.match(re) || [];
}

function getHostname(url){
  try{
    return new URL(url).hostname.toLowerCase();
  }catch(e){
    return null;
  }
}

function registrableDomain(hostname){
  const parts = hostname.split('.');
  if(parts.length <= 2) return hostname;
  // naive heuristic good enough for .com / .co.za style TLDs
  const twoLevelTlds = ['co.za','org.za','gov.za','com.au','co.uk','org.uk'];
  const lastTwo = parts.slice(-2).join('.');
  if(twoLevelTlds.includes(lastTwo) && parts.length >= 3) return parts.slice(-3).join('.');
  return lastTwo;
}

function levenshtein(a,b){
  const m=a.length,n=b.length;
  const dp=Array.from({length:m+1},()=>new Array(n+1).fill(0));
  for(let i=0;i<=m;i++) dp[i][0]=i;
  for(let j=0;j<=n;j++) dp[0][j]=j;
  for(let i=1;i<=m;i++){
    for(let j=1;j<=n;j++){
      dp[i][j]=Math.min(
        dp[i-1][j]+1,
        dp[i][j-1]+1,
        dp[i-1][j-1]+(a[i-1]===b[j-1]?0:1)
      );
    }
  }
  return dp[m][n];
}

function findBrandDomainFlags(text, urls){
  const flags = [];
  const lowerText = text.toLowerCase();
  const mentionedBrands = Object.keys(KNOWN_BRANDS).filter(b => lowerText.includes(b));
  const hostnames = urls.map(getHostname).filter(Boolean);
  const registrables = hostnames.map(registrableDomain);

  mentionedBrands.forEach(brand => {
    const official = KNOWN_BRANDS[brand];
    if(hostnames.length === 0) return; // no links to check against

    const matchesOfficial = registrables.some(r => r === official);
    if(matchesOfficial) return; // legit, no flag for this brand

    registrables.forEach((reg, idx) => {
      if(reg === official) return;
      const dist = levenshtein(reg, official);
      const brandLabel = brand.replace(/\b\w/g, c => c.toUpperCase());
      if(dist > 0 && dist <= 3 && reg.length >= official.length - 3){
        flags.push({
          category: 'Lookalike Domain',
          severity: 'high',
          why: `The message mentions "${brandLabel}" but links to "${hostnames[idx]}" — close to, but not, the real ${official}.`,
          evidence: hostnames[idx]
        });
      } else if(hostnames[idx].includes(brand.replace(/\s+/g,''))){
        flags.push({
          category: 'Suspicious Domain Structure',
          severity: 'high',
          why: `"${brandLabel}" appears in the link's hostname, but the actual domain is "${reg}", not ${official}.`,
          evidence: hostnames[idx]
        });
      } else {
        flags.push({
          category: 'Brand / Link Mismatch',
          severity: 'medium',
          why: `The message references "${brandLabel}" but every link points to an unrelated domain (${reg}).`,
          evidence: hostnames[idx]
        });
      }
    });
  });

  return flags;
}

function findAnchorMismatchFlags(rawText){
  // only relevant if text looks like it contains HTML anchor tags
  if(!/<a\s+[^>]*href=/i.test(rawText)) return [];
  const flags = [];
  const doc = new DOMParser().parseFromString(rawText, 'text/html');
  const anchors = doc.querySelectorAll('a[href]');
  anchors.forEach(a => {
    const href = a.getAttribute('href');
    const shownText = a.textContent.trim();
    const hrefHost = getHostname(href);
    const textLooksLikeUrl = /^(https?:\/\/)?[\w-]+(\.[\w-]+)+/i.test(shownText);
    if(textLooksLikeUrl && hrefHost){
      const shownHostMatch = shownText.replace(/^https?:\/\//i,'').split('/')[0].toLowerCase();
      if(shownHostMatch && !hrefHost.includes(shownHostMatch.split('.').slice(-2).join('.'))){
        flags.push({
          category: 'Mismatched Link',
          severity: 'high',
          why: `The link displays "${shownText}" but actually points to "${href}" — the destination doesn't match what's shown.`,
          evidence: `"${shownText}" → ${href}`
        });
      }
    }
  });
  return flags;
}

function highlightEvidenceInText(text, matches){
  if(matches.length === 0) return escapeHtml(text);
  let result = '';
  let cursor = 0;
  const sorted = [...matches].sort((a,b)=>a.index-b.index);
  const merged = [];
  sorted.forEach(m => {
    if(merged.length && m.index <= merged[merged.length-1].end){
      merged[merged.length-1].end = Math.max(merged[merged.length-1].end, m.index+m.length);
    } else {
      merged.push({start:m.index, end:m.index+m.length, severity:m.severity});
    }
  });
  merged.forEach(m => {
    result += escapeHtml(text.slice(cursor, m.start));
    result += `<mark class="hl-${m.severity}">${escapeHtml(text.slice(m.start, m.end))}</mark>`;
    cursor = m.end;
  });
  result += escapeHtml(text.slice(cursor));
  return result;
}

function escapeHtml(str){
  return str.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

/* ---------- Core analysis ---------- */
function analyzeMessage(rawInput){
  const plainText = rawInput.replace(/<[^>]+>/g, ' ').replace(/\s+/g,' ').trim() || rawInput;

  const flags = [];
  const highlightRanges = [];

  RULES.forEach(rule => {
    rule.patterns.forEach(pattern => {
      const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
      let m;
      while((m = re.exec(plainText)) !== null){
        flags.push({
          category: rule.category,
          severity: rule.severity,
          why: rule.why,
          evidence: m[0].trim()
        });
        highlightRanges.push({index: m.index, length: m[0].length, severity: rule.severity});
        if(m.index === re.lastIndex) re.lastIndex++;
      }
    });
  });

  const urls = extractUrls(rawInput);
  const domainFlags = findBrandDomainFlags(plainText, urls);
  flags.push(...domainFlags);

  const anchorFlags = findAnchorMismatchFlags(rawInput);
  flags.push(...anchorFlags);

  // dedupe near-identical flags (same category + evidence)
  const seen = new Set();
  const deduped = flags.filter(f => {
    const key = f.category + '|' + f.evidence;
    if(seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return { flags: deduped, displayText: plainText, highlightRanges };
}

function scoreFlags(flags){
  const weight = {high:3, medium:2, low:1};
  let score = 0;
  let highCount = 0;
  flags.forEach(f => {
    score += weight[f.severity] || 0;
    if(f.severity === 'high') highCount++;
  });
  return {score, highCount};
}

function verdictFromScore(score, highCount, flagCount){
  if(flagCount === 0) return {level:'NO OBVIOUS RED FLAGS', color:'var(--green)', pct: 6};
  if(highCount >= 2 || score >= 10) return {level:'CRITICAL RISK', color:'var(--red)', pct: 96};
  if(highCount >= 1 || score >= 6) return {level:'HIGH RISK', color:'var(--red)', pct: 78};
  if(score >= 3) return {level:'MEDIUM RISK', color:'var(--amber)', pct: 52};
  return {level:'LOW RISK', color:'var(--green)', pct: 22};
}

/* ---------- Gauge SVG ---------- */
function gaugeSvg(pct, color){
  const angle = -90 + (pct/100)*180;
  const cx = 48, cy = 50, r = 40;
  return `
  <svg class="gauge" viewBox="0 0 96 60">
    <path d="M 8 50 A 40 40 0 0 1 88 50" stroke="#223049" stroke-width="7" fill="none" stroke-linecap="round"/>
    <path d="M 8 50 A 40 40 0 0 1 88 50" stroke="${color}" stroke-width="7" fill="none" stroke-linecap="round"
      stroke-dasharray="${(pct/100)*125.6} 200" opacity="0.9"/>
    <line x1="${cx}" y1="${cy}" x2="${cx + r*0.72*Math.cos(angle*Math.PI/180)}" y2="${cy + r*0.72*Math.sin(angle*Math.PI/180)}"
      stroke="${color}" stroke-width="2.5" stroke-linecap="round"/>
    <circle cx="${cx}" cy="${cy}" r="3.5" fill="${color}"/>
  </svg>`;
}

/* ---------- Rendering ---------- */
const thread = document.getElementById('thread');
const input = document.getElementById('input');
const sendBtn = document.getElementById('sendBtn');

function scrollToBottom(){
  thread.scrollTop = thread.scrollHeight;
}

function addUserBubble(text){
  const row = document.createElement('div');
  row.className = 'row user';
  row.innerHTML = `<div class="bubble"></div>`;
  row.querySelector('.bubble').textContent = text.length > 600 ? text.slice(0,600) + '…' : text;
  thread.appendChild(row);
  scrollToBottom();
}

function addTypingIndicator(){
  const row = document.createElement('div');
  row.className = 'row bot';
  row.id = 'typingRow';
  row.innerHTML = `<div class="bubble"><div class="typing"><span></span><span></span><span></span></div></div>`;
  thread.appendChild(row);
  scrollToBottom();
}

function removeTypingIndicator(){
  const row = document.getElementById('typingRow');
  if(row) row.remove();
}

function severityIcon(sev){
  return '●';
}

function addBotAnalysis(analysis){
  const {flags, displayText, highlightRanges} = analysis;
  const {score, highCount} = scoreFlags(flags);
  const verdict = verdictFromScore(score, highCount, flags.length);

  const row = document.createElement('div');
  row.className = 'row bot';

  let flagsHtml = '';
  if(flags.length === 0){
    flagsHtml = `<p style="color:var(--muted);font-size:0.85rem;margin:6px 0 0;">No matches against my current rule set — but pattern-matching only catches known patterns. Still check the sender's actual email address and hover over links before clicking.</p>`;
  } else {
    flagsHtml = '<div class="flag-list">' + flags.map(f => `
      <div class="flag ${f.severity}">
        <div class="cat">${severityIcon(f.severity)} ${f.category} · ${f.severity}</div>
        <span class="evidence">${escapeHtml(f.evidence)}</span>
        <div class="why">${escapeHtml(f.why)}</div>
      </div>
    `).join('') + '</div>';
  }

  const highlighted = highlightEvidenceInText(displayText, highlightRanges);

  row.innerHTML = `
    <div class="bubble" style="max-width:94%;">
      <div class="bot-label">Analysis</div>
      <div class="verdict">
        ${gaugeSvg(verdict.pct, verdict.color)}
        <div class="verdict-text">
          <p class="level" style="color:${verdict.color};">${verdict.level}</p>
          <p class="sub">${flags.length} flag${flags.length===1?'':'s'} found · score ${score}</p>
        </div>
      </div>
      ${flagsHtml}
      <details style="margin-top:12px;">
        <summary style="cursor:pointer;font-size:0.78rem;color:var(--muted);">View marked-up message</summary>
        <div style="font-family:var(--mono);font-size:0.78rem;line-height:1.6;margin-top:8px;color:var(--text);white-space:pre-wrap;">${highlighted}</div>
      </details>
      <div class="footnote">Heuristic pattern-matching only — a clean result isn't a guarantee. When in doubt, verify through an official site or number you look up yourself, not one in the message.</div>
    </div>
  `;
  thread.appendChild(row);
  scrollToBottom();
}

function handleSend(){
  const val = input.value.trim();
  if(!val) return;
  addUserBubble(val);
  input.value = '';
  sendBtn.disabled = true;
  addTypingIndicator();
  setTimeout(() => {
    removeTypingIndicator();
    const analysis = analyzeMessage(val);
    addBotAnalysis(analysis);
    sendBtn.disabled = false;
  }, 650 + Math.random()*400);
}

input.addEventListener('keydown', (e) => {
  if(e.key === 'Enter' && !e.shiftKey){
    e.preventDefault();
    handleSend();
  }
});

/* ---------- Samples ---------- */
const SAMPLES = {
  phish: `Dear Customer,

We detected unusual activity on your FNB account. Your account will be suspended within 24 hours unless you verify your details immediately.

Please confirm your password and card number at the link below to avoid permanent account closure:
https://fnb-secure-verify.com/login

Failure to respond will result in legal action.

Regards,
FNB Security Team`,
  clean: `Hi Khaya,

Just confirming our meeting for Thursday at 2pm to go over the CarRental capstone PaymentService review. Let me know if that still works for you.

Thanks,
Tanatswa`,
  html: `Dear valued customer,

Your Netflix payment failed. Please update your billing details immediately by clicking the link below:

<a href="http://netfl1x-billing-update.ru/pay">www.netflix.com/account/update</a>

Thank you.`
};

function loadSample(key){
  input.value = SAMPLES[key];
  input.focus();
}