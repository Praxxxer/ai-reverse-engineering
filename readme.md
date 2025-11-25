# 🕵️‍♂️ AI-Powered Reverse Engineering Lab

A local, privacy-first web interface for reverse engineering binaries. This tool combines the decompilation power of **Ghidra** with the reasoning capabilities of local LLMs (via **Ollama**) to assist analysts in understanding malware, extracting strings, and analyzing functions.

## 🚀 Features

* **Privacy First:** Runs 100% locally. No data is sent to the cloud.
* **AI Assistance:** Chat with your binary. Ask questions like "What does the main function do?" or "Are there any hardcoded IP addresses?".
* **Ghidra Integration:** Automated headless analysis in the background.
* **Malware Friendly:** Supports uploading password-protected ZIPs (e.g., `infected`) directly from the UI.
* **Streaming Chat:** Real-time AI responses with Markdown rendering and syntax highlighting.
* **Tool Use (MCP):** The AI can autonomous call Ghidra scripts (`list_functions`, `decompile`, `get_xrefs`) to answer your questions accurately.

---

## 🛠️ Prerequisites

Before running the lab, ensure you have the following installed:

1.  **Python 3.10+**
2.  **Ollama**: For running the LLM locally. [Download Here](https://ollama.com).
3.  **Ghidra**: Headless Docker Container --- You must have a headless Ghidra server or the compatible scripts from this repository running.
4.  **Browser**: Chrome, Firefox, or Edge.

---

#### Uses a headless Ghidra analysis results exposed as REST API

### 1. Clone the Repository
```bash
git clone [https://github.com/yourusername/ai-reverse-engineering.git](https://github.com/yourusername/ai-reverse-engineering.git)
cd ai-reverse-engineering

```

2.  Pull the Docker image biniamfd/ghidra-headless-rest:latest and run it with the below command
   ```bash
docker run --rm -p 9090:9090 -v $(pwd)/data:/data/ghidra_projects biniamfd/ghidra-headless-rest:latest

```
4. Set your Ollama model (and download it) https://ollama.com/download/windows
5. Change the ghidra_assistant.py to reflect your chosen model in ollama
6. Run the app

```bash
python webui/app.py
```

6. Navigate to the flask URL 127.0.0.1:5000 in your browser

