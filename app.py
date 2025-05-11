import streamlit as st
import re  # For regular expressions
from urllib.parse import urlparse # For parsing URLs

# --- GLOBAL STYLE CONSTANTS ---
PRIMARY_HEADING_COLOR = "#1A1A1A" 
PRIMARY_TEXT_COLOR = "#2E3D50"  
SECONDARY_TEXT_COLOR = "#5A6474" 
ACCENT_COLOR_BLUE = "#007AFF"   
SAFE_COLOR = "#34C759" 
LOW_RISK_COLOR = "#5AC8FA" 
MEDIUM_RISK_COLOR = "#FF9500" 
HIGH_RISK_COLOR = "#FF3B30" 
CRITICAL_RISK_COLOR = "#BF1A2F" 
BACKGROUND_COLOR = "#F9FAFB"   
CARD_BACKGROUND_COLOR = "#FFFFFF" 
BORDER_COLOR = "#D1D1D6"       
FONT_FAMILY_SYSTEM = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol'"
BORDER_RADIUS = "10px"
BOX_SHADOW = "0 4px 12px rgba(0, 0, 0, 0.08)"
BOX_SHADOW_SM = "0 2px 4px rgba(0,0,0,0.05)"


# --- CLASS DEFINITIONS ---

class InputProcessor:
    def __init__(self, text_from_user):
        self.raw_text = text_from_user
        self.processed_text = self.clean_text(text_from_user)
    def clean_text(self, text):
        cleaned_text = text.strip().lower()
        cleaned_text = re.sub(r'\s+', ' ', cleaned_text)
        return cleaned_text
    def get_processed_text(self): return self.processed_text
    def get_raw_text(self): return self.raw_text
    def is_likely_email_format(self):
        text = self.processed_text
        if any(kw in text for kw in ["subject:", "from:", "to:"]) and "@" in text: return True
        if re.search(r"subject:.*\n\s*\n\s*(dear|hello|hi)", text, re.IGNORECASE | re.MULTILINE): return True
        if sum(1 for kw in ["dear", "regards", "sincerely", "unsubscribe", "click here", "opt out"] if kw in text) >= 2: return True
        return False

class BaseRule:
    def __init__(self, name, description=""): 
        self.name = name; self.description = description 
    def check(self, text_to_check, **kwargs): raise NotImplementedError("BaseRule check method not implemented")
    def get_match_info(self): raise NotImplementedError("BaseRule get_match_info method not implemented")

class UrgencyKeywordRule(BaseRule):
    def __init__(self):
        super().__init__(name="🚨 Urgency & Threat Detector")
        self.keywords = ["urgent", "immediately", "action required", "verify now", "limited time", "warning", "account suspended", "password expired", "critical alert", "final notice", "response needed", "important update", "act fast", "don't delay", "security risk", "unauthorized access", "immediate attention", "important: read now", "account will be locked", "your account is restricted"]
        self.found_keywords_for_match_info = []
    def check(self, text_to_check, **kwargs):
        self.found_keywords_for_match_info = []
        score = 0
        for keyword in self.keywords:
            if re.search(r'\b' + re.escape(keyword) + r'\b', text_to_check):
                self.found_keywords_for_match_info.append(keyword)
                score += 2
        return min(score, 8) 
    def get_match_info(self):
        if self.found_keywords_for_match_info:
            k_str = ', '.join(f"**`{k}`**" for k in self.found_keywords_for_match_info)
            return (f"🚩 **Finding:** Uses urgent words like {k_str}.\n\n"
                    f"🤔 **Why it's risky & What to do:** Scammers use these to rush you. Always pause and verify urgent requests via official channels you already know, not from the suspicious message.")
        return None

class SuspiciousURLRule(BaseRule):
    def __init__(self):
        super().__init__(name="🔗 Suspicious URL Analyzer")
        self.url_regex = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+')
        self.url_shorteners = ["bit.ly", "t.co", "tinyurl.com", "is.gd", "goo.gl", "ow.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "qr.ae", "cli.gs", "shorte.st"]
        self.common_phish_targets = {"paypal.com": ["paypa1.com", "paypal-login.net", "paypalservice.org", "paypal-secure.com"], "amazon.com": ["amaz0n.co.uk", "amazon-primeoffers.net", "amaozn.com", "amazonrewards.net"], "google.com": ["g00gle.services.org", "google-support.net", "google-login.com"], "microsoft.com": ["microsftonline.com", "office365-login.org", "live-security.com", "ms-support.net"], "apple.com": ["app1e.id.org", "icloud-support.net", "appleid-verify.com", "apple-security.org"], "netflix.com": ["netfl1x.info", "netflix-accounts.com", "netflixsupport.net"], "facebook.com": ["faceb00k.org", "fb-security.com", "meta-logins.com", "fb-verify.com"]}
        self.char_replacements = {'o': '0', 'l': '1', 'i': '!', 'e': '3', 'a': '@', 's': '$', 'g':'9', 'b':'8', 'u':'v'}
        self.findings_for_match_info = []

    def _is_ip_address(self, domain): return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain) and all(0 <= int(p) <= 255 for p in domain.split(".")))
    
    def _check_typo(self, domain):
        norm_dom = re.sub(r'^www\.', '', domain)
        for target, typos in self.common_phish_targets.items():
            if norm_dom in typos or any(typo_variation in norm_dom for typo_variation in typos):
                return f"The domain **`{norm_dom}`** looks like a fake version of **`{target}`**."
        temp_dom = norm_dom
        # Corrected the logic for character replacement check
        original_temp_dom = temp_dom # Store original before modification
        modified_by_replacement = False
        for original_char, replacement_char in self.char_replacements.items():
            if replacement_char in temp_dom:
                temp_dom = temp_dom.replace(replacement_char, original_char)
                modified_by_replacement = True
        
        if modified_by_replacement: # Only check if modifications were made
            if any(temp_dom == target for target in self.common_phish_targets):
                return f"The domain **`{norm_dom}`** might use sneaky character swaps (like '0' for 'o') to impersonate a known site like **`{temp_dom}`**." # Use the potentially reverted domain name
        return None


    def check(self, text_to_check, **kwargs):
        self.findings_for_match_info = [] 
        urls = self.url_regex.findall(text_to_check)
        if not urls: return 0
        
        total_score = 0
        all_url_alerts_details = []

        for url_orig in urls:
            url = url_orig.rstrip('.,!?;:\'"')
            current_alerts_tuples = [] 
            url_score_contrib = 0
            
            parsed_url_str = url if url.startswith(("http://", "https://")) else "http://" + url
            try:
                p_url = urlparse(parsed_url_str)
                domain = p_url.netloc
                
                if p_url.scheme == 'http': 
                    url_score_contrib += 3; current_alerts_tuples.append(("Uses Insecure 'http'", f"Safe sites use **'https'**. 'http' (`{url}`) is less secure."))
                if self._is_ip_address(domain): 
                    url_score_contrib += 8; current_alerts_tuples.append((f"Uses a Direct IP Address (`{domain}`)", f"Trusted sites use domain names (like google.com). Linking to an IP (`{url}`) is very suspicious."))
                
                is_shortener = False
                for s in self.url_shorteners:
                    if s in domain:
                        url_score_contrib += 5; current_alerts_tuples.append(("Uses a URL Shortener", f"The domain (`{s}`) in `{url}` hides the real link. Scammers use this.")); is_shortener = True; break
                
                if not is_shortener: 
                    if typo_msg := self._check_typo(domain): # Python 3.8+ walrus operator
                        url_score_contrib += 7; current_alerts_tuples.append(("Potential Typosquatting / Impersonation", f"{typo_msg} This is a trick to make you think it's a real site. (URL: `{url}`)"))
                
                path_q = (p_url.path + "?" + p_url.query).lower()
                kws = ["login", "verify", "secure", "account", "password", "bank", "support", "appleid", "microsoft", "paypal", "webscr", "update", "confirm", "activity", "signin", "cmd", "recovery", "payment", "invoice", "alert", "customer-support", "service", "security", "auth"]
                found_kws = [kw for kw in kws if re.search(r'\b' + re.escape(kw) + r'\b', path_q)]
                if found_kws: 
                    url_score_contrib += (2*len(found_kws)); current_alerts_tuples.append((f"Path Contains Suspicious Keywords: `'{', '.join(found_kws)}'`", f"These words in `{url}` often lead to fake login or scam pages."))
                if len(url) > 80: 
                    url_score_contrib += 2; current_alerts_tuples.append(("URL is Unusually Long", f"This URL (`{url}`) is very long ({len(url)} chars). Long URLs can hide the real destination."))
                
                if current_alerts_tuples:
                    url_detail_header = f"🔗 **Analysis for URL:** `{url}`\n"
                    url_detail_items = "".join([f"<li><b>{finding[0]}:</b> {finding[1]}</li>" for finding in current_alerts_tuples])
                    all_url_alerts_details.append(f"{url_detail_header}<ul>{url_detail_items}</ul>")

                total_score += url_score_contrib
            except ValueError: 
                total_score += 1; all_url_alerts_details.append(f"🚩 **Finding:** Malformed URL \"`{url}`\".\n🤔 **Why it's risky:** This URL could not be parsed. This might be an attempt to confuse detectors or users.")
        
        if all_url_alerts_details:
            self.findings_for_match_info = all_url_alerts_details
        return total_score

    def get_match_info(self):
        if self.findings_for_match_info:
            return "\n\n".join(self.findings_for_match_info)
        return None

class TooGoodToBeTrueRule(BaseRule):
    def __init__(self):
        super().__init__(name="💰 'Too Good To Be True' Detector")
        self.phrases = ["you have won", "lottery winner", "claim your prize", "free money", "guaranteed income", "risk-free investment", "inheritance notification", "transfer funds", "get rich quick", "financial assistance", "prize notification", "unexpected money", "congratulations you've been selected", "earn thousands daily", "secret to wealth", "claim your winnings", "government compensation", "exclusive offer just for you", "you are a winner"]
        self.found_phrases, self.found_sums = [], []
    def check(self, text, **kwargs):
        self.found_phrases, self.found_sums = [], []
        score = sum(3 for p in self.phrases if re.search(r'\b'+re.escape(p)+r'\b', text, re.IGNORECASE) and self.found_phrases.append(p))
        regex = r"((?:[\$€£₹]|rs\.?|inr|dollars|pounds|euros|usd|eur|gbp|rupees)\s*)?([\d,]+(?:\.\d+)?)\s*(million|billion|thousand|lakh|crore)?"
        for m in re.finditer(regex, text, re.IGNORECASE):
            curr, num_str, unit = (m.group(1) or "").strip(), m.group(2), (m.group(3) or "").lower()
            try:
                val = float(num_str.replace(',', ''))
                susp = (unit == "million" and val >= 0.05) or (unit == "billion" and val >= 0.005) or \
                       (unit == "lakh" and val >= 2) or (unit == "crore" and val >= 0.05) or \
                       (unit == "thousand" and val >= 20) or (not unit and curr and val >= 20000)
                if susp: self.found_sums.append(f"`{curr} {num_str} {unit}`".strip().replace("  "," ")); score += 5
            except ValueError: pass
        if self.found_phrases and self.found_sums: score += 5
        return min(score, 15)
    def get_match_info(self):
        parts = []
        if self.found_phrases: 
            phrases_str = ', '.join(f"**`{p}`**" for p in self.found_phrases)
            parts.append(f"🚩 **Finding:** Uses enticing phrases like {phrases_str}.\n🤔 **Why it's risky & What to do:** These often signal unrealistic promises. If an offer sounds too good to be true, it probably is. Be very skeptical and don't share personal info or send money.")
        if self.found_sums: 
            sums_str = ' / '.join(f"**{s}**" for s in sorted(list(set(self.found_sums))))
            parts.append(f"🚩 **Finding:** Mentions unusually large sums (e.g., {sums_str}).\n🤔 **Why it's risky & What to do:** Scammers use big money (lottery, inheritance) as bait. Real windfalls don't require upfront fees or your details via unsolicited messages.")
        return "\n\n".join(parts) if parts else None

class EmailAnalysisRule(BaseRule):
    def __init__(self):
        super().__init__(name="📧 Email Anomaly Analyzer")
        self.findings = [] 
        self.salutations = ["dear user", "dear customer", "dear valued customer", "dear account holder", "greetings user", "dear client", "dear sir or madam", "dear recipient", "valued member", "dear [your email here]", "hello valued member", "attention user"]
        self.pressure = ["account will be closed", "legal action", "immediate suspension", "failure to comply", "access will be revoked", "final warning", "account compromised", "unauthorized transaction", "action pending", "prevent service interruption", "your account is in danger", "respond within 24 hours"]
        self.subject_kws = ["urgent", "action required", "warning", "alert", "security update", "verify your account", "payment confirmation", "unusual login", "important notification", "account issue", "password notification", "suspicious sign-in", "invoice", "important message"]
        self.attach_kws = ["attachment", "attached file", "document attached", "see attached", "invoice attached", "download form", "open the attachment", "review the attached", "click on the attachment", "attached document"]
    def check(self, text, is_likely_email=False, **kwargs):
        self.findings = []
        if not is_likely_email: return 0
        score = 0
        if any(re.search(r"(?:^subject:.*\n)?\s*\b"+re.escape(s)+r'\b', text, re.I|re.M) for s in self.salutations):
            score += 3; self.findings.append(("Generic Salutation", "e.g., 'Dear User'. Real services often use your name. This suggests a mass phishing email."))
        if subj_m := re.search(r"subject:\s*(.*)", text, re.I): # Python 3.8+ walrus operator
            subj = subj_m.group(1).strip()
            if subj == subj.upper() and len(subj) > 8: 
                score += 2; self.findings.append(("Subject in ALL CAPS", "Often a spam/scam tactic for false urgency or attention."))
            if any(kw in subj for kw in self.subject_kws): 
                kws_found = [kw for kw in self.subject_kws if kw in subj]
                score += 4; self.findings.append((f"Suspicious/Urgent Keywords in Subject (e.g., `'{kws_found[0]}'`)", "These aim to make you act impulsively. Verify independently."))
        if any(p in text for p in self.pressure): 
            p_found = [p for p in self.pressure if p in text]
            score += 3*len(p_found); self.findings.append((f"Pressure Tactics or Threats (e.g., `'{p_found[0]}'`)", "Scammers use fear (e.g., 'account will be closed') to force quick action. Legitimate companies give notice."))
        if any(a in text for a in self.attach_kws): 
            a_found = [a for a in self.attach_kws if a in text]
            score += 4; self.findings.append((f"Mentions Email Attachments (e.g., `'{a_found[0]}'`)", "Be very careful. Never open attachments from unknown senders; they can contain malware."))
        
        reply_to_m = re.search(r"reply-to:\s*<?([\w\.-]+@[\w\.-]+)>?", text, re.I)
        from_m = re.search(r"from:\s*(?:.*<)?([\w\.-]+@[\w\.-]+)>?", text, re.I)
        if reply_to_m and from_m and (reply_to_m.group(1).lower() != from_m.group(1).lower()):
            score += 7; self.findings.append((f"Reply-To (`{reply_to_m.group(1)}`) Mismatches 'From' (`{from_m.group(1)}`)", "A very common phishing tactic. The 'From' address might look real, but your reply goes to the scammer."))
        return min(score, 20)
    def get_match_info(self):
        if not self.findings: return None
        return "\n\n".join([f"🚩 **Finding:** {f[0]}\n🤔 **Why it's risky & What to do:** {f[1]}" for f in self.findings])

class RuleEngine:
    def __init__(self): self.rules = []
    def add_rule(self, rule): 
        if isinstance(rule, BaseRule): self.rules.append(rule)
    def analyse_text(self, processor):
        alerts_data, score = [], 0
        text, is_email = processor.get_processed_text(), processor.is_likely_email_format()
        for rule in self.rules:
            s = rule.check(text, is_likely_email=is_email)
            if s > 0:
                score += s
                if info := rule.get_match_info(): # Python 3.8+ walrus operator
                    alerts_data.append((rule.name, s, info))
        if not alerts_data:
            return (["✅ **All Clear & Looking Good!** 🎉 Our Cyber Scam Detector scanned your text and found no common scam indicators. Remember to always stay vigilant online and trust your instincts!"], 0)
        return (alerts_data, score)

# --- STREAMLIT APP CODE ---

st.set_page_config(page_title="Cyber Scam Detector", page_icon="🛡️", layout="centered") 

st.markdown(f"""
<style>
    body {{ font-family: {FONT_FAMILY_SYSTEM}; }} 
    .stApp {{ background-color: {BACKGROUND_COLOR}; color: {PRIMARY_TEXT_COLOR}; }}
    h1 {{ font-family: {FONT_FAMILY_SYSTEM}; color: {PRIMARY_HEADING_COLOR}; font-weight: 700; letter-spacing: -0.5px; text-align: center;}}
    h2 {{ font-family: {FONT_FAMILY_SYSTEM}; color: {PRIMARY_HEADING_COLOR}; font-weight: 600; text-align: center;}}
    h3 {{ font-family: {FONT_FAMILY_SYSTEM}; color: {PRIMARY_TEXT_COLOR}; font-weight: 600; text-align: center;}}
    h4 {{ font-family: {FONT_FAMILY_SYSTEM}; color: {PRIMARY_TEXT_COLOR}; font-weight: 500; text-align: center;}}
    
    .stButton>button {{ 
        background-color: {ACCENT_COLOR_BLUE}; color: white; font-weight: 600;
        border-radius: {BORDER_RADIUS}; border: none; padding: 0.8rem 1.75rem; 
        box-shadow: {BOX_SHADOW}; transition: all 0.2s ease-in-out;
        font-size: 1.05em; 
    }}
    .stButton>button:hover {{ background-color: #005ECB; transform: scale(1.03); box-shadow: 0 6px 12px rgba(0,0,0,0.12);}}
    .stButton>button:active {{ transform: scale(0.99); }}
    
    .stTextArea textarea {{ 
        border-radius: {BORDER_RADIUS}; border: 1px solid {BORDER_COLOR}; 
        background-color: {CARD_BACKGROUND_COLOR}; font-size: 1rem;
        min-height: 200px; box-shadow: {BOX_SHADOW}; padding: 0.75rem;
    }}
    .stTextArea label {{ font-weight: 600; color: {PRIMARY_TEXT_COLOR}; margin-bottom: 0.5rem;}} 
    
    .report-card {{
        background-color: {CARD_BACKGROUND_COLOR}; padding: 1.75rem; 
        border-radius: {BORDER_RADIUS}; box-shadow: {BOX_SHADOW}; 
        border-left: 7px solid; margin-bottom: 2rem; 
    }}
    .risk-progress-bar-bg {{
        width: 100%; background-color: #e9ecef; border-radius: {BORDER_RADIUS}; 
        margin-bottom: 1rem; height: 24px; position: relative; border: 1px solid #ced4da;
    }}
    .risk-progress-bar-fg {{
        height: 100%; border-radius: {BORDER_RADIUS}; 
        transition: width 0.6s ease-in-out;
    }}
    .risk-progress-text {{
        position: absolute; top: 0; left: 0; width: 100%; height: 100%; 
        display: flex; align-items: center; justify-content: center; 
        font-weight: 600; font-size:0.9em;
    }}

    .stExpander {{
        border: 1px solid {BORDER_COLOR} !important;
        border-radius: {BORDER_RADIUS} !important;
        box-shadow: {BOX_SHADOW_SM} !important;
        margin-bottom: 1rem !important;
        background-color: {CARD_BACKGROUND_COLOR} !important;
    }}
    .stExpander header {{ 
        font-weight: 600 !important;
        font-size: 1.05em !important;
        color: {PRIMARY_TEXT_COLOR} !important;
        padding: 0.8rem 1rem !important; 
        background-color: transparent !important; 
    }}
     .stExpander header:hover {{
        background-color: #E9ECEF !important; 
    }}
    .stExpander div[data-testid="stExpanderDetails"] {{ 
        padding: 0.5rem 1rem 1rem 1.25rem !important; 
        font-size: 0.95em !important;
        color: {SECONDARY_TEXT_COLOR} !important; /* Using SECONDARY_TEXT_COLOR for expander content */
        line-height: 1.6 !important; 
    }}
    .stExpander div[data-testid="stExpanderDetails"] p {{ margin-bottom: 0.5em;}} 
    .stExpander div[data-testid="stExpanderDetails"] ul {{ padding-left: 20px; margin-top:0.5em; }}
    .stExpander div[data-testid="stExpanderDetails"] li {{ margin-bottom: 0.3em; }}

    .url-analysis-container {{ padding: 0.5rem; font-size: 0.95em;}}
    .url-card {{ border: 1px solid #e0e0e0; padding: 12px; margin-top: 12px; border-radius: {BORDER_RADIUS}; background-color:#fdfdfd; box-shadow: {BOX_SHADOW_SM};}}
    .url-card ul {{ margin-bottom: 0; padding-left: 25px; list-style-type: '➡️ '; }} 
    .url-card li {{ margin-bottom: 8px; }}
    .url-card b {{ color: {PRIMARY_TEXT_COLOR};}}
</style>
""", unsafe_allow_html=True)

with st.container():
    st.markdown(f"""
        <div style="text-align: center; margin-bottom: 2rem; padding-top:1rem;">
            <span style="font-size: 4.5rem;">🛡️</span>
            <h1 style="margin-bottom: 0.25rem;">Cyber Scam Detector</h1>
            <p style="color: {PRIMARY_TEXT_COLOR}; font-size: 1.2em; margin-bottom: 1rem; font-weight:500;">
                Your Smart Tool to Unmask Online Deception! 🕵️‍♀️
            </p>
            <p style="font-size: 1em; color: {PRIMARY_TEXT_COLOR};">
                Feeling suspicious about a message, email, or URL? Paste it below! Our Detector will analyze it for common scam indicators and give you a clear risk assessment. Stay one step ahead of scammers! ✨
            </p>
        </div>
    """, unsafe_allow_html=True)

if 'rule_engine' not in st.session_state:
    engine = RuleEngine()
    engine.add_rule(UrgencyKeywordRule()); engine.add_rule(SuspiciousURLRule())
    engine.add_rule(TooGoodToBeTrueRule()); engine.add_rule(EmailAnalysisRule())
    st.session_state.rule_engine = engine
my_rule_engine = st.session_state.rule_engine

st.markdown(f"<h3 style='text-align: center; font-weight:600; color: {PRIMARY_TEXT_COLOR}; margin-bottom:0.75rem;'>📝 Enter Text for Analysis</h3>", unsafe_allow_html=True)
user_text_input = st.text_area(
    "**Paste suspicious content here:** (e.g., full email, message, or a URL)", 
    height=220,
    placeholder="Example: Subject: URGENT Security Alert! Your account requires immediate verification at http://suspicious-login-page.com/verify to avoid suspension..."
)

show_cleaned_checkbox = st.checkbox("🔬 Show cleaned input (for debugging)", False, help="View the text after basic cleaning and lowercasing. This is what the Detector sees.")

if st.button("🛡️ Detect Scam Now!", help="Click to start the scam detection analysis", use_container_width=True): 
    if user_text_input:
        processor = InputProcessor(user_text_input)
        
        if show_cleaned_checkbox: 
            st.markdown("<hr style='border:1px dashed #ccc; margin: 1.5rem 0;'>", unsafe_allow_html=True)
            st.markdown(f"<h4 style='color:{PRIMARY_TEXT_COLOR}; text-align:left;'>🧹 Cleaned Input (for analysis):</h4>", unsafe_allow_html=True)
            st.code(processor.get_processed_text(), language=None)
        
        with st.spinner('🤖 Analyzing... Uncovering potential threats... Please wait a moment...'):
            triggered_alerts_data, total_score = my_rule_engine.analyse_text(processor)

        st.markdown("<hr style='border:1px solid #D1D1D6; margin: 2.5rem 0;'>", unsafe_allow_html=True) 
        st.markdown(f"<h2 style='text-align: center; font-weight:700; color: {PRIMARY_HEADING_COLOR};'>📊 Cyber Scam Detector: Report Card</h2>", unsafe_allow_html=True)
        
        max_scores = [8, 30, 15, 20] 
        max_hypothetical_score = sum(max_scores) 
        progress_p = min((total_score / max_hypothetical_score) * 100, 100) if max_hypothetical_score > 0 else 0
        
        risk_color, risk_level, risk_emoji, risk_advice = SAFE_COLOR, "Low Risk", "🔵", "This content has some minor indicators. Review carefully, but immediate danger is less likely. Always double-check any requests before proceeding."
        if total_score == 0: risk_level, risk_emoji, risk_color, risk_advice = "No Specific Threats Detected", "✅", SAFE_COLOR, "🎉 Excellent! Our Cyber Scam Detector found no common scam indicators. This content appears to be safe based on our checks. However, always stay vigilant online and trust your instincts!"
        elif 0 < total_score <= 10: risk_level, risk_emoji, risk_color, risk_advice = "Low Risk", "🔵", LOW_RISK_COLOR, "Some minor potential issues were detected. It's wise to be cautious and independently verify any information or links. Don't rush into any action, and if in doubt, don't proceed."
        elif 10 < total_score <= 25: risk_color, risk_level, risk_emoji, risk_advice = MEDIUM_RISK_COLOR, "Medium Risk", "🟠", "Several suspicious signs were found. Proceed with extreme caution. Independently verify any information or links before trusting this content. Avoid sharing personal details unless you are 100% certain of the source's legitimacy. This could be a scam attempt."
        elif 25 < total_score <= 40: risk_color, risk_level, risk_emoji, risk_advice = HIGH_RISK_COLOR, "High Risk", "🔴", "Multiple strong indicators of a potential scam detected! It is STRONGLY ADVISED to AVOID clicking any links, providing personal information, or taking any action requested. This is very likely a scam or phishing attempt. "
        elif total_score > 40: risk_color, risk_level, risk_emoji, risk_advice = CRITICAL_RISK_COLOR, "Critical Risk", "🛑", "🚨 Numerous critical alerts triggered! This content is EXTREMELY LIKELY to be malicious. Avoid ALL interaction immediately. Do not click, reply, or provide any information. Consider reporting this to relevant authorities or platforms if it involves impersonation or financial fraud."

        st.markdown(f"""
            <div class='report-card' style='border-left-color: {risk_color};'>
                <h3 style='text-align: center; color: {risk_color}; margin-top:0; margin-bottom: 1rem; font-family:{FONT_FAMILY_SYSTEM}; font-weight:600;'>{risk_emoji} Detector's Verdict: {risk_level} (Score: {total_score})</h3>
                <div class="risk-progress-bar-bg">
                    <div class="risk-progress-bar-fg" style="width: {progress_p}%; background-color: {risk_color};"></div>
                    <div class="risk-progress-text" style="color: {'white' if progress_p > 30 else PRIMARY_TEXT_COLOR};">
                        {int(progress_p)}% Suspicion Level
                    </div>
                </div>
                <p style="text-align: center; font-size: 1.05em; color: {PRIMARY_TEXT_COLOR}; font-family: {FONT_FAMILY_SYSTEM};"><strong>🛡️ Our Advice:</strong> {risk_advice}</p>
            </div>
        """, unsafe_allow_html=True)
        
        if total_score == 0 and isinstance(triggered_alerts_data, list) and triggered_alerts_data[0].startswith("✅"):
            st.balloons()
        elif triggered_alerts_data:
            st.markdown(f"#### <span style='color:{PRIMARY_TEXT_COLOR}'>📜 Detailed Findings & Explanations</span>", unsafe_allow_html=True)
            triggered_alerts_data.sort(key=lambda x: x[1], reverse=True) 
            for i, (rule_name, score_contrib, info) in enumerate(triggered_alerts_data):
                with st.expander(f"{rule_name} (Risk Points: +{score_contrib})", expanded=(i < 2 and score_contrib >=5) or (score_contrib >=7)):
                    # For URL rule, info might be HTML. For others, it's Markdown-like.
                    if "🔗" in rule_name: # Check if it's the URL rule
                         st.markdown(f"<div class='url-analysis-container'>{info}</div>" if info else "No specific URL details.", unsafe_allow_html=True)
                    else:
                        st.markdown(info if info else "No specific details for this finding.", unsafe_allow_html=True) # Allow markdown
    else:
        st.warning("⚠️ Oops! Please paste some text into the box above to analyze. Cyber Scam Detector needs something to work with! 😊")

st.markdown("<hr style='border:1px solid #e0e0e0; margin: 2.5rem 0;'>", unsafe_allow_html=True)
st.markdown(f"""
    <div style="text-align: center; font-size: 0.9em; color: {PRIMARY_TEXT_COLOR}; font-family:{FONT_FAMILY_SYSTEM};">
        <p>Developed with 🛡️, Python & Streamlit by <strong>Anoosha Qasim</strong> (GIAIC Student).</p>
        <p><strong>Disclaimer:</strong> This tool is for educational and illustrative purposes. It provides automated analysis and may not be 100% accurate or exhaustive. Always exercise critical thinking and verify information from trusted official sources. Your online safety is your responsibility.</p>
        <p style="font-size:0.85em; margin-top:0.5rem;"><em>Remember: If something feels suspicious, it probably is! Trust your instincts. 💡</em></p>
    </div>
""", unsafe_allow_html=True)