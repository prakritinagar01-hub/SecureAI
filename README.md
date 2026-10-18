
# 🛡️ SecureAI — AI-Powered Threat Detection System

SecureAI is an AI-powered cybersecurity web application that helps users analyze suspicious messages and URLs, assess potential threats, and review scan reports through an interactive dashboard.

## ✨ Features

- 🔍 **Message Scanner** — Analyze suspicious messages for potential phishing and scams.
- 🌐 **URL Scanner** — Assess URLs for potential security risks.
- 🤖 **AI-Powered Analysis** — Generate threat assessments using AI.
- ⚠️ **Risk Classification** — Categorize results as Low, Medium, High, or Unknown.
- 📊 **Interactive Dashboard** — View scan statistics and risk distribution.
- 🗄️ **Scan History** — Save scan reports in an SQLite database.
- 🔎 **Search & Filters** — Find previous scans and filter by risk level.
- 📥 **CSV Export** — Download scan reports for further analysis.
- 🎨 **User-Friendly Interface** — Simple web interface for security analysis.

## 🛠️ Tech Stack

- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Python, Flask
- **Database:** SQLite
- **AI Integration:** OpenAI API
- **Data Export:** CSV

## 📁 Project Structure

```text
SecureAI/
├── app.py
├── ai_service.py
├── requirements.txt
├── .env
├── .gitignore
├── templates/
│   ├── index.html
│   └── dashboard.html
└── static/
    ├── style.css
    └── script.js
```

## 🚀 Installation & Setup

### 1. Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd YOUR_REPOSITORY_FOLDER
```

Replace the placeholders with your actual repository URL and folder name.

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

Activate it on Windows:

```powershell
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure the API Key

Create a `.env` file in the root directory:

```env
OPENAI_API_KEY=your_api_key_here
```

Never share your API key or upload your `.env` file to GitHub.

### 5. Run the Application

```bash
python app.py
```

Open the following address in your browser:

http://127.0.0.1:5000

## 🔄 How It Works

1. Enter a suspicious message or URL.
2. Submit the input for analysis.
3. The application uses its configured AI service to assess potential security risks.
4. Review the risk classification and analysis details.
5. Open the dashboard to view saved scan history.
6. Search, filter, and export reports as CSV.

## 🔐 Security Disclaimer

SecureAI provides AI-assisted security assessments for educational and informational purposes. Results may be inaccurate and should not be treated as definitive proof that a message or URL is safe or malicious.

Avoid opening suspicious URLs. Never enter passwords, API keys, or other sensitive information into the scanner.

## 🔮 Future Improvements

- Real-time threat intelligence integration
- URL reputation checking
- Advanced phishing detection
- Explainable AI-based threat analysis
- User authentication
- Enhanced security analytics

## 👩‍💻 Author

**Prakriti Nagar**

GitHub: [prakritinagar01-hub](https://github.com/prakritinagar01-hub)

---

⭐ If you find SecureAI useful, consider giving the repository a star!
