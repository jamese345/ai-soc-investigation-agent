# 🛡️ AI SOC Investigation Agent

An AI-powered Security Operations Center (SOC) investigation agent that automatically investigates security alerts by combining **security logs, threat intelligence, MITRE ATT&CK, RAG-based cybersecurity knowledge, evidence evaluation, adaptive investigation planning, and LLM reasoning**.

The goal is to simulate how an AI-assisted SOC analyst can move from a raw security alert to a structured investigation, evidence-backed conclusion, and actionable SOC recommendations.

---

## 🎯 Project Goal

Traditional SOC investigations often require analysts to manually collect evidence from multiple sources before determining whether an alert represents a genuine security incident.

This project automates that workflow.

The AI SOC Investigation Agent:

1. Receives a security alert.
2. Creates an investigation plan based on the alert context and severity.
3. Prioritizes investigation steps.
4. Executes investigation tools.
5. Collects evidence from multiple sources.
6. Evaluates whether the evidence is sufficient.
7. Performs controlled escalation when evidence gaps remain.
8. Uses cybersecurity knowledge through RAG.
9. Sends the investigation context to an LLM for analysis.
10. Generates structured findings and recommendations.
11. Produces a SOC investigation report.

---

## 🧠 Core Capabilities

### 🔎 Automated Investigation

The agent automatically investigates alerts instead of requiring every investigation step to be manually selected.

### 📋 Context-Aware Planning

Investigation plans are generated based on:

- Alert severity
- Username
- Source IP
- Detection rule
- Investigation context

High and critical alerts receive higher-priority investigation steps.

### ⚡ Priority-Aware Execution

Investigation steps are executed according to priority:

```text
CRITICAL
   ↓
HIGH
   ↓
MEDIUM
   ↓
LOW
```

Each investigation step tracks its execution status:

```text
PENDING
   ↓
IN_PROGRESS
   ↓
COMPLETED
```

Failed or unavailable steps are also tracked.

### 🌐 Threat Intelligence

The agent enriches indicators using **AlienVault OTX**.

For example:

```text
Source IP
    ↓
AlienVault OTX
    ↓
IOC Reputation
    ↓
Threat Intelligence Evidence
```

Threat intelligence is treated as one evidence source rather than being used as the sole basis for declaring an indicator malicious.

### 📜 Security Log Investigation

The agent searches authentication logs for activity associated with the affected account.

It can identify:

- Authentication events
- Failed login attempts
- Source IPs
- Account activity
- Behavioral evidence

### 🎯 MITRE ATT&CK Mapping

Detection rules are mapped to MITRE ATT&CK techniques.

Example:

```text
Brute Force
     ↓
T1110
     ↓
Credential Access
```

### 📚 RAG Knowledge Retrieval

The agent retrieves relevant cybersecurity knowledge before generating its final analysis.

Current knowledge includes:

- Brute-force attacks
- Suspicious logins
- Phishing
- MITRE ATT&CK context

This provides additional domain context to the reasoning process.

### 🧮 Evidence Evaluation

Collected evidence is scored based on:

- Evidence confidence
- Evidence relevance
- Number of independent sources
- Coverage of investigation categories

The system determines whether the evidence is sufficient to support an investigation conclusion.

### 🔄 Adaptive Investigation

If the evidence is insufficient, the agent can perform a controlled additional investigation step.

Example:

```text
Initial Investigation
        ↓
Evidence Evaluation
        ↓
Is evidence sufficient?
     ↙       ↘
   YES        NO
    ↓          ↓
Reasoning   Escalation
               ↓
        Additional Evidence
               ↓
        Evidence Evaluation
```

The escalation process is intentionally limited to prevent uncontrolled investigation loops.

### 🤖 AI SOC Reasoning

The LLM receives:

- Alert information
- Investigation findings
- Evidence
- Evidence evaluation
- Relevant cybersecurity knowledge

It produces:

- Investigation summary
- Conclusion
- Severity
- Confidence
- Key findings
- Recommended actions

### 📊 Structured SOC Recommendations

AI-generated recommendations are converted into structured SOC recommendations with priority levels.

Example:

```text
HIGH
Review and secure the affected admin account.

HIGH
Monitor the source IP for continued activity.

HIGH
Investigate additional authentication events.
```

### 📄 Automated SOC Reports

Completed investigations are automatically converted into Markdown reports containing:

- Investigation summary
- Investigation plan
- Step priorities
- Step statuses
- Evidence evaluation
- Findings
- AI analysis
- Key findings
- Recommended actions
- SOC recommendations

---

# 🏗️ Architecture

```text
                    ┌──────────────────────┐
                    │    Security Alert    │
                    │                      │
                    │  Rule / Severity     │
                    │  Source IP / User    │
                    └──────────┬───────────┘
                               │
                               ▼
                 ┌──────────────────────────┐
                 │   AI SOC Investigation    │
                 │          Agent            │
                 └────────────┬─────────────┘
                              │
                              ▼
                 ┌──────────────────────────┐
                 │ Investigation Planner    │
                 │                          │
                 │ Context + Severity       │
                 │ Priority-aware Plan      │
                 └────────────┬─────────────┘
                              │
                              ▼
                 ┌──────────────────────────┐
                 │ Investigation Executor   │
                 └────────────┬─────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
          ▼                   ▼                   ▼
   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
   │ Security    │     │ AlienVault  │     │ MITRE       │
   │ Logs        │     │ OTX         │     │ ATT&CK      │
   └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
          │                   │                   │
          └───────────────────┼───────────────────┘
                              ▼
                    ┌──────────────────────┐
                    │ Evidence Collection  │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Evidence Evaluator   │
                    │                      │
                    │ Confidence           │
                    │ Relevance            │
                    │ Source Coverage      │
                    └──────────┬───────────┘
                               │
                         ┌─────┴─────┐
                         │           │
                     Sufficient   Insufficient
                         │           │
                         │           ▼
                         │     ┌─────────────┐
                         │     │ Controlled  │
                         │     │ Escalation  │
                         │     └──────┬──────┘
                         │            │
                         └────────────┘
                              │
                              ▼
                    ┌──────────────────────┐
                    │ RAG Knowledge Base   │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │    LLM Reasoner      │
                    │                      │
                    │ Analysis + Conclusion│
                    │ Findings + Actions   │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ SOC Recommendations  │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Investigation Report │
                    │       Markdown       │
                    └──────────────────────┘
```

---

# 🔍 Investigation Workflow

The complete investigation lifecycle is:

```text
Alert
  ↓
Plan Investigation
  ↓
Prioritize Steps
  ↓
Execute Tools
  ↓
Collect Evidence
  ↓
Evaluate Evidence
  ↓
Evidence Sufficient?
  ↓
Adaptive Escalation if Required
  ↓
Retrieve Cybersecurity Knowledge
  ↓
AI Analysis
  ↓
Generate Findings
  ↓
Generate Recommendations
  ↓
Generate SOC Report
```

---

# 🧪 Example Investigation

The test alert used in the investigation workflow:

```text
Alert ID: ALT-001
Rule: Brute Force
Severity: HIGH
Source IP: 185.10.10.20
Username: admin
Failed Attempts: 35
```

The agent generated the following investigation plan:

| Step | Action | Priority |
|---|---|---|
| 1 | LOG_SEARCH | HIGH |
| 2 | IOC_LOOKUP | HIGH |
| 3 | MITRE_LOOKUP | MEDIUM |

### Security Log Evidence

```text
Found 5 security events for username 'admin'.
3 events were failed authentication attempts.
Associated source IPs: 185.10.10.20.
```

### Threat Intelligence Evidence

```text
IOC 185.10.10.20 was classified as having
no known malicious pulses in AlienVault OTX.
```

The important principle here is that **lack of malicious threat-intelligence reputation does not automatically make the activity safe**.

Behavioral evidence is still important.

### MITRE ATT&CK Evidence

```text
Brute Force
    ↓
T1110
    ↓
Credential Access
```

### Evidence Evaluation

```text
Evidence Score: 120
Sufficient: YES
Missing Evidence: None
```

### AI SOC Analysis

```text
Severity: HIGH
Confidence: HIGH
```

The evidence was considered consistent with brute-force activity.

### Recommendations

```text
1. Review and secure the affected admin account.
2. Monitor the source IP for continued activity.
3. Investigate additional authentication events.
```

---

# 📊 Investigation Evidence Model

The agent combines multiple evidence sources instead of relying on a single signal.

```text
                Investigation
                      │
        ┌─────────────┼─────────────┐
        │             │             │
        ▼             ▼             ▼
   Behavioral     Threat Intel   Attack Context
    Evidence       Evidence        Evidence
        │             │             │
        └─────────────┼─────────────┘
                      ▼
              Evidence Evaluation
                      │
                      ▼
                AI Reasoning
```

This multi-source approach helps reduce the risk of making conclusions from a single indicator.

---

# 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application |
| Pydantic | Data validation and models |
| Pandas | Security log analysis |
| OpenAI API | AI reasoning |
| RAG | Cybersecurity knowledge retrieval |
| AlienVault OTX | Threat intelligence |
| MITRE ATT&CK | Attack technique mapping |
| unittest | Automated testing |
| python-dotenv | Environment configuration |
| Markdown | Investigation reports |

---

# 📁 Project Structure

```text
ai-soc-investigation-agent/
│
├── data/
│   ├── alerts/
│   ├── logs/
│   │   └── security_events.csv
│   └── knowledge/
│       ├── brute_force.md
│       ├── suspicious_login.md
│       ├── phishing.md
│       └── enterprise-attack.json
│
├── src/
│   ├── agent/
│   │   ├── planner.py
│   │   ├── executor.py
│   │   ├── investigation.py
│   │   ├── evidence_evaluator.py
│   │   ├── reasoner.py
│   │   └── tool_registry.py
│   │
│   ├── tools/
│   │   ├── base.py
│   │   ├── ioc_tool.py
│   │   ├── ioc_lookup.py
│   │   ├── log_search.py
│   │   ├── mitre_tool.py
│   │   └── evidence_builder.py
│   │
│   ├── rag/
│   │   └── retriever.py
│   │
│   ├── models/
│   │   └── schemas.py
│   │
│   └── reports/
│       └── investigation_report.py
│
├── tests/
│
├── reports/
│
├── main.py
├── requirements.txt
├── .env.example
├── .gitignore
├── LICENSE
└── README.md
```

---

# 🧪 Testing

The project uses Python's built-in `unittest` framework.

The final automated test suite contains:

```text
70 tests
```

Final result:

```text
----------------------------------------------------------------------
Ran 70 tests in 17.527s

OK
```

The test suite covers major components including:

- Data models
- Investigation planning
- Priority handling
- Tool execution
- Security log searching
- MITRE ATT&CK lookup
- IOC enrichment
- Evidence evaluation
- Adaptive escalation
- RAG retrieval
- AI reasoning
- API error handling
- Report generation
- Investigation integration

---

# 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/jamese345/ai-soc-investigation-agent.git
cd ai-soc-investigation-agent
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# ⚙️ Configuration

Create a `.env` file based on `.env.example`.

Configure the required API credentials for the external services used by the project.

Example:

```env
OPENAI_API_KEY=your_openai_api_key
OTX_API_KEY=your_otx_api_key
```

Never commit real API keys to GitHub.

---

# ▶️ Running the Project

Run the investigation agent with:

```bash
python main.py
```

The investigation report will be generated under:

```text
reports/
```

Example:

```text
reports/
└── INV-XXXXXXXX.md
```

---

# 🔐 Security Design Principles

This project follows several principles important to real SOC workflows.

### Evidence Before Conclusions

The agent collects evidence before generating its final assessment.

### Multi-Source Investigation

Threat intelligence, behavioral logs, and MITRE ATT&CK context are combined.

### Explainability

Investigation steps contain explicit reasons explaining why they were selected.

### Priority Awareness

Higher-severity alerts receive higher-priority investigation actions.

### Controlled Automation

Adaptive investigation is limited to prevent uncontrolled escalation loops.

### Structured Output

Investigation results are represented using validated Pydantic models.

### Fail-Safe API Handling

External AI service failures are handled explicitly rather than silently ignored.

---

# ⚠️ API Validation Note

The project successfully reaches the OpenAI API, but real API execution depends on an OpenAI account with available API credits.

During development, an API request reached OpenAI successfully but returned a `429` error because the account had no remaining API credits.

The application handles this condition and returns a clear service-unavailable error.

The automated test suite uses mocked AI responses where appropriate, allowing the complete application logic to be tested without consuming API credits.

---

# 📈 Project Evolution

This project represents the sixth stage of my AI SOC development roadmap.

```text
Project 1
SOC Log Analyzer
       ↓
Project 2
Automated Alert Triage Engine
       ↓
Project 3
ML-Based Anomaly Detector
       ↓
Project 4
Threat Intelligence Enrichment Engine
       ↓
Project 5
Cybersecurity RAG Assistant
       ↓
Project 6
AI SOC Investigation Agent
       ↓
Project 7
Full AI SOC Analyst Platform
```

Each project builds on capabilities developed in the previous stage.

---

# 🔮 Future Improvements

Potential future improvements include:

- Multi-agent SOC architecture
- Automated incident response actions
- SIEM integration
- Real-time alert ingestion
- Additional threat intelligence providers
- More advanced semantic RAG retrieval
- Vector database integration
- Long-term investigation memory
- Analyst feedback loops
- Investigation dashboards
- Case management integration
- Automated incident timelines
- Human-in-the-loop approval workflows

---

# 🎯 Learning Outcomes

Through this project I strengthened my ability to build systems combining:

- Cybersecurity
- Python
- Threat intelligence
- MITRE ATT&CK
- RAG
- LLMs
- Tool calling
- Automated investigation
- Evidence evaluation
- Structured data models
- SOC reporting
- Automated testing

The project demonstrates how AI can be used to **assist SOC analysts with investigation and decision support rather than simply generating text**.

---

# 👨‍💻 About

I am building a portfolio focused on combining **Cybersecurity + Python + AI** with the long-term goal of becoming an **AI SOC Analyst**.

This project is part of my practical AI SOC development journey.

---

## ⭐ If you find this project useful

Feel free to:

- ⭐ Star the repository
- 💡 Open an issue with suggestions
- 🔧 Contribute improvements
- 💬 Share ideas for extending the investigation agent

---

## 📌 Project Status

**Status:** ✅ Completed

**Automated Tests:** `70/70 Passed`

**Current Stage:** AI SOC Investigation Agent

**Next Stage:** 🚀 Full AI SOC Analyst Platform