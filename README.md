# CodeGuardian: Vulnerability Detection in Programming Languages

CodeGuardian is a machine learning-based framework developed to detect and classify software vulnerabilities in source code written in **C**, **C++**, **Java**, **Python**, and **C#**. It supports severity classification and line-level localization, helping developers proactively identify and fix security issues early in the development lifecycle.

---

## 🧠 Abstract

Software vulnerabilities are a significant concern in modern software development, leading to critical failures and security breaches. CodeGuardian addresses this issue using a machine learning-based framework that detects and classifies the severity of vulnerabilities in source code across multiple languages.

The model applies a **three-fold feature extraction** strategy:
- **Structural analysis** via Code Property Graphs (using Semgrep),
- **Semantic understanding** with CodeBERT,
- **Lexical analysis** using FastText.

An ensemble of classification algorithms, including **Graph Convolutional Networks (GCNs)**, enables CodeGuardian to not only identify the presence and severity of vulnerabilities (**no, low, medium, high**) but also pinpoint the **exact line number** where the issue occurs.

---

## 🛠️ Technologies Used

### 🔹 Programming Language:
- Python

### 🔹 Machine Learning & NLP Libraries:
- `scikit-learn`
- `FastText`
- `CodeBERT`

### 🔹 Code Graph Analysis:
- Code Property Graphs via **Joern/Semgrep**

### 🔹 Deep Learning:
- Graph Convolutional Networks (GCNs)

### 🔹 Web Development:
- Flask

### 🔹 Python Utilities:
- `numpy`
- `matplotlib`
- `scipy`

### 🔹 Datasets:
- **Software Assurance Reference Dataset (SARD)**
  - C/C++ Suite: 64,099 samples (118 CWEs)
  - Java Suite: 28,881 samples
  - C# Suite: 28,942 samples (105 CWEs)
- **Exploit-DB** for Python code samples

---

## 🌟 Features

✅ **Multi-language Support**  
Detects vulnerabilities in:  
→ C, C++, Java, Python, and C#

✅ **Severity Classification**  
Classifies each detected vulnerability into:
- No
- Low
- Medium
- High

✅ **Line Number Localization**  
Pinpoints the exact line of code where a vulnerability exists.

✅ **Three-fold Feature Extraction**
- **Structural**: Code Property Graph (via Semgrep)
- **Semantic**: CodeBERT embeddings
- **Lexical**: FastText vectors

✅ **Ensemble Learning Framework**  
Uses a combination of ML models and GCNs to improve prediction accuracy.
