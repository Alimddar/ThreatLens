
import bannerImg from './assets/banner.png'

function App() {
  return (
    <>
      <nav className="navbar container">
        <div className="logo">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z" stroke="#10b981" strokeWidth="2"/>
            <path d="M12 8C14.2091 8 16 9.79086 16 12C16 14.2091 14.2091 16 12 16C9.79086 16 8 14.2091 8 12C8 9.79086 9.79086 8 12 8Z" fill="#10b981" opacity="0.5"/>
            <circle cx="12" cy="12" r="2" fill="#10b981"/>
          </svg>
          Threat<span>Lens</span>
        </div>
        <a href="https://addons.mozilla.org/en-US/firefox/search/?q=threatlens" target="_blank" rel="noreferrer" className="btn-primary">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
          </svg>
          Add to Firefox
        </a>
      </nav>

      <section className="hero container">
        <div className="badge">✨ Now Available on Firefox Add-ons</div>
        <h1>SOC-Grade Threat Intelligence,<br /> <span className="text-gradient">Directly Inside Gmail</span></h1>
        <p>Get instant, AI-powered analysis of any email. ThreatLens combines real-time VirusTotal tracking, DNS/WHOIS checks, and Claude AI to deliver a plain-English vulnerability verdict — no security expertise required.</p>
        
        <div className="hero-cta">
          <a href="https://addons.mozilla.org/en-US/firefox/search/?q=threatlens" target="_blank" rel="noreferrer" className="btn-primary" style={{ padding: "1rem 2.5rem", fontSize: "1.1rem" }}>
            Install Extension Free
          </a>
        </div>

        <div className="hero-image-wrapper">
          <img src={bannerImg} alt="ThreatLens Dashboard" className="hero-image" />
        </div>
      </section>

      <section className="features-section">
        <div className="container">
          <div className="section-header">
            <h2>9 Parallel Security Engines</h2>
            <p>Every link, domain, and IP address is automatically vetted against industry-leading threat feeds.</p>
          </div>
          
          <div className="features-grid">
            <div className="feature-card">
              <div className="feature-icon">🔍</div>
              <h3>URL Reputation</h3>
              <p>Checks every embedded link against VirusTotal (90+ antivirus engines) to catch zero-day phishing sites instantly.</p>
            </div>
            
            <div className="feature-card">
              <div className="feature-icon">🧠</div>
              <h3>Claude AI Analysis</h3>
              <p>A sophisticated LLM synthesizes technical IOCs to provide a human-readable, actionable threat summary.</p>
            </div>
            
            <div className="feature-card">
              <div className="feature-icon">🛡️</div>
              <h3>DNS Authentication</h3>
              <p>Automatically verifies SPF, DKIM, and DMARC records to catch dangerous email spoofing and impersonation.</p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">🌍</div>
              <h3>WHOIS Domain Age</h3>
              <p>Cross-references domain registration data to automatically flag newly registered domains (under 30 days old).</p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">📜</div>
              <h3>TLS Transparency</h3>
              <p>Queries crt.sh certificate logs to identify untrusted, self-signed, or forged TLS/SSL certificates.</p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">🚫</div>
              <h3>Spamhaus Intelligence</h3>
              <p>Checks all extracted IP addresses and domains against global spam, botnet, and malware blocklists.</p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">🦠</div>
              <h3>URLScan Network</h3>
              <p>Analyzes historical footprints and screenshots of embedded links via the URLScan.io network sandbox.</p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">🔒</div>
              <h3>PII Sanitization</h3>
              <p>A strict client-side regex engine strips sensitive data (credit cards, SSNs, passwords) before any external processing.</p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">🕸️</div>
              <h3>Deep DOM Heuristics</h3>
              <p>An advanced local scraper parses the active Gmail thread to extract hidden sender addresses and obfuscated links.</p>
            </div>
          </div>
        </div>
      </section>

      <section className="details-section container">
        <div className="details-grid">
          <div className="detail-content">
            <h2>Absolute Privacy, Built-In.</h2>
            <p>We designed ThreatLens with the strict privacy standards required by executives and SOC analysts. Your email body never touches our database.</p>
            
            <ul className="check-list">
              <li>
                <div className="check-icon">✓</div>
                <span>Zero Retention: Emails are processed strictly in-memory and discarded.</span>
              </li>
              <li>
                <div className="check-icon">✓</div>
                <span>Local Sanitization: Credit cards, SSNs, and passwords are regex-stripped in the browser.</span>
              </li>
              <li>
                <div className="check-icon">✓</div>
                <span>Your API Keys: Bring your own Enterprise VirusTotal and Anthropic keys.</span>
              </li>
            </ul>
          </div>
          
          <div className="integration-box">
            <h3 style={{ marginBottom: "1.5rem", fontSize: "1.5rem" }}>Under the Hood</h3>
            <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
               <div style={{ background: "rgba(255,255,255,0.05)", padding: "1rem", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.1)" }}>
                 <strong>1. DOM Extraction</strong>
                 <div style={{ fontSize: "0.9rem", color: "var(--text-secondary)", marginTop: "0.5rem" }}>Content scraper pulls sender, links, and body from the active Gmail tab.</div>
               </div>
               <div style={{ background: "rgba(255,255,255,0.05)", padding: "1rem", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.1)" }}>
                 <strong>2. OSINT Parallel Fetch</strong>
                 <div style={{ fontSize: "0.9rem", color: "var(--text-secondary)", marginTop: "0.5rem" }}>FastAPI queries VirusTotal, URLScan, Spamhaus, WHOIS, and crt.sh simultaneously.</div>
               </div>
               <div style={{ background: "rgba(16, 185, 129, 0.1)", padding: "1rem", borderRadius: "8px", border: "1px solid rgba(16, 185, 129, 0.2)" }}>
                 <strong style={{ color: "var(--acc-green)" }}>3. AI Synthesis</strong>
                 <div style={{ fontSize: "0.9rem", color: "var(--text-secondary)", marginTop: "0.5rem" }}>Claude 3.5 Sonnet normalizes the threat intelligence into a SAFE, SUSPICIOUS, or MALICIOUS verdict.</div>
               </div>
            </div>
          </div>
        </div>
      </section>

      <footer className="footer container">
        <p>ThreatLens Dashboard v3.0 &bull; Built for advanced email security.</p>
        <p style={{ marginTop: "0.5rem" }}>
          View source on <a href="https://github.com/Alimddar/ThreatLens" target="_blank" rel="noreferrer">GitHub</a>
          {" "}&bull;{" "}
          Explore the <a href="https://threat-lens-vie2.vercel.app/docs" target="_blank" rel="noreferrer">API Docs</a>
        </p>
      </footer>
    </>
  )
}

export default App
