<<<<<<< HEAD
# 🛡️ Cyber Scam Detector

An intelligent application built with Python and Streamlit to analyze text, emails, and URLs for potential cyber scams and phishing attempts. This tool helps users identify common scam patterns and assess risks associated with suspicious content.

Developed by **Anoosha Qasim** (GIAIC Student).

## 🚀 Features

- **Multi-faceted Analysis:** Detects various scam indicators including:
  - 🚨 **Urgency & Threats:** Identifies high-pressure language and threatening phrases.
  - 🔗 **Suspicious URLs:** Analyzes URLs for:
    - Insecure HTTP protocols.
    - Direct IP address usage.
    - Presence of URL shorteners.
    - Potential typosquatting or brand impersonation.
    - Suspicious keywords in path or query.
    - Unusually long URLs.
  - 💰 **"Too Good To Be True" Patterns:** Flags unrealistic offers, lottery wins, and mentions of large, unsolicited sums of money.
  - 📧 **Email Anomalies:** If the input resembles an email, it checks for:
    - Generic salutations.
    - Suspicious subject lines (ALL CAPS, excessive urgency).
    - Pressure tactics within the email body.
    - Mentions of attachments (as a caution).
    - Mismatch between 'From' and 'Reply-To' addresses.
- **Weighted Risk Scoring:** Each detected anomaly contributes to an overall risk score, providing a quantitative measure of suspicion.
- **Clear Verdict & Advice:** Presents a clear "Detector's Verdict" (No Threats, Low, Medium, High, Critical Risk) along with actionable advice based on the calculated score.
- **Detailed Findings:** Shows a breakdown of all detected issues, explaining why each finding is risky and what the user should look out for.
- **User-Friendly Interface:** Clean, modern, and intuitive UI built with Streamlit, making it easy for anyone to use.
- **Object-Oriented Design:** Developed using OOP principles for a well-structured, maintainable, and extensible codebase.

## 🛠️ Technology Stack

- **Language:** Python
- **Framework:** Streamlit (for the web application UI)
- **Libraries:**
  - `re` (for regular expression-based pattern matching)
  - `urllib.parse` (for URL parsing)

## ⚙️ How It Works

The Cyber Scam Detector employs a rule-based engine. Each rule is designed as a Python class (inheriting from a base `BaseRule` class) to identify specific types of scam indicators:

1.  **Input Processing:** User-provided text is first cleaned (converted to lowercase, extra spaces removed).
2.  **Rule Application:** The cleaned text is then passed through a series of specialized rules:
    - `UrgencyKeywordRule`
    - `SuspiciousURLRule`
    - `TooGoodToBeTrueRule`
    - `EmailAnalysisRule` (this rule is conditionally applied if the input is detected as an email format).
3.  **Scoring:** Each rule, if triggered, contributes a pre-defined score to a total risk score. The more (or more severe) rules triggered, the higher the total score.
4.  **Reporting:** The application presents:
    - An overall risk verdict and score.
    - A visual risk indicator (progress bar).
    - Actionable advice based on the risk level.
    - Detailed explanations for each detected anomaly.

## 🏁 Getting Started

To run this application locally:

1.  **Prerequisites:**

    - Python 3.8 or higher installed.
    - `pip` (Python package installer) installed.

2.  **Clone the Repository (Optional - if you've pushed to GitHub):**

    ```bash
    git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY_NAME.git
    cd YOUR_REPOSITORY_NAME
    ```

3.  **Create a Virtual Environment (Recommended):**

    ```bash
    python -m venv myenv
    # On Windows
    myenv\Scripts\activate
    # On macOS/Linux
    source myenv/bin/activate
    ```

4.  **Install Dependencies:**
    The primary dependency is Streamlit.

    ```bash
    pip install streamlit
    ```

    (If you add other libraries later, list them here or in a `requirements.txt` file).

5.  **Run the Application:**
    Navigate to the project directory in your terminal and run:
    ```bash
    streamlit run app.py
    ```
    The application will open in your default web browser.

## 📸 Screenshots (Optional)

_(You can add screenshots of your application's UI here if you like. This makes the README more engaging.)_

- Example: Main Interface
  `[Link to Screenshot 1]`
- Example: Analysis Report - High Risk
  `[Link to Screenshot 2]`

## 💡 Future Enhancements (Ideas)

- Integration with external threat intelligence APIs (e.g., VirusTotal for URLs).
- More sophisticated NLP techniques for sentiment analysis and intent detection.
- User feedback mechanism for reporting false positives/negatives.
- Machine Learning model for adaptive scam detection.
- Multi-language support.

## 🙏 Acknowledgements

- Developed as part of a project for GIAIC (Generative AI and Cloud Intensive).
- Inspiration from various cybersecurity awareness resources.

---

Feel free to contribute, report issues, or suggest improvements!
=======
# cyber-scam-detector
Stay safe online! 🛡️ This Cyber Scam Detector analyzes suspicious messages, emails, and links to identify common scam patterns and assess potential risks. Built with Python &amp; Streamlit by Anoosha Qasim
>>>>>>> c94f180729339ef4f3426271d8fe1c03a113f23f
