import os
import tempfile
import torch
import numpy as np
from flask import Flask, render_template, request, redirect, url_for
import sqlite3
from transformers import AutoTokenizer, AutoModel
import re
from collections import Counter

app = Flask(__name__, static_folder='static')

# Initialize CodeBERT with attention
tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
model = AutoModel.from_pretrained("microsoft/codebert-base", output_attentions=True)

# Severity mapping with more granular levels
SEVERITY_MAP = {
    0: "No vulnerability",
    1: "Low severity",
    2: "Medium severity",
    3: "High severity",
    4: "Critical severity"
}

# Enhanced vulnerability patterns with more specific detection
VULNERABILITY_PATTERNS = {
    'sql_injection': [
        (re.compile(r'(select\s.+from|insert\s+into|update\s+.+\s+set|delete\s+from).*?\$.+?\$', re.I), 3)],
    'xss': [
        (re.compile(r'(document\.cookie|innerHTML\s*=|<\s*script\b)', re.I), 3),
        (re.compile(r'(eval\s*\(|setTimeout\s*\(|setInterval\s*\()', re.I), 2)],
    'command_injection': [
        (re.compile(r'(system|exec|popen|passthru|proc_open|shell_exec)\s*\(.+?\$.+?\)', re.I), 4),
        (re.compile(r'(\bexec\s+|\brun\s+|\bstart\s+).*?\$', re.I), 3)],
    'hardcoded_credentials': [
        (re.compile(r'(password|passwd|pwd|secret|api[_-]?key)\s*=\s*[\'"][^\'"]+[\'"]', re.I), 2),
        (re.compile(r'(aws_|api_)?(access_?key|secret_?key)\s*=\s*[\'"][^\'"]+[\'"]', re.I), 3)],
    'weak_crypto': [
        (re.compile(r'(md2|md4|md5|sha1|des|rc4|rc2)\s*\(', re.I), 2),
        (re.compile(r'crypto\.createHash\s*\(\s*[\'"](md5|sha1)[\'"]', re.I), 2)],
    'path_traversal': [
        (re.compile(r'(\.\./|\.\.\\).+?[\'"\)]', re.I), 3),
        (re.compile(r'(\./|\.\\)etc/passwd', re.I), 4)],
    'buffer_overflow': [
        (re.compile(r'(strcpy|strcat|sprintf|gets)\s*\(', re.I), 3),
        (re.compile(r'\b(alloca|scanf)\s*\(', re.I), 2)],
    'insecure_deserialization': [
        (re.compile(r'(pickle|yaml|marshal)\.loads?\s*\(', re.I), 3),
        (re.compile(r'ObjectInputStream\s*\(', re.I), 3)],
    'ssrf': [
        (re.compile(r'(curl|file_get_contents|fopen)\s*\(.+?(http|ftp|file):', re.I), 3)],
    'log_forging': [
        (re.compile(r'System\.(out|err)\.print|console\.log.*[\'"]\s*\+\s*.+?\$', re.I), 2)]
}

def get_line_numbers(code, token_ids):
    """Improved line number tracking with better token handling"""
    line_numbers = []
    current_line = 1
    char_pos = 0
    lines = code.split('\n')
    
    for token_id in token_ids:
        token = tokenizer.decode(token_id).strip()
        if not token or token in [tokenizer.cls_token, tokenizer.sep_token]:
            line_numbers.append(-1)
            continue
            
        # Find token position in code
        token_pos = code.find(token, char_pos)
        if token_pos == -1:
            line_numbers.append(-1)
            continue
            
        # Get exact line number
        current_line = code.count('\n', 0, token_pos) + 1
        line_numbers.append(current_line)
        char_pos = token_pos + len(token)
    
    return line_numbers

def detect_vulnerability_patterns(code):
    """Enhanced vulnerability pattern detection with line context"""
    vulnerabilities = []
    lines = code.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        for vuln_type, patterns in VULNERABILITY_PATTERNS.items():
            for pattern, severity in patterns:
                matches = pattern.finditer(line)
                for match in matches:
                    # Get 3 lines of context
                    start_line = max(0, line_num - 2)
                    end_line = min(len(lines), line_num + 2)
                    context = [(i+1, lines[i]) for i in range(start_line-1, end_line)]
                    
                    vulnerabilities.append({
                        'type': vuln_type,
                        'line': line_num,
                        'code': line.strip(),
                        'severity': severity,
                        'match': match.group(),
                        'context': context
                    })
    
    return vulnerabilities

def analyze_attention_patterns(attention_weights, line_numbers):
    """Analyze attention patterns to detect suspicious code structures"""
    # Normalize attention weights
    attention_weights = attention_weights / attention_weights.sum()
    
    # Get top 5% most attended tokens
    top_indices = torch.topk(attention_weights, k=max(1, int(len(attention_weights)*0.05))).indices
    
    # Get corresponding line numbers
    suspicious_lines = [line_numbers[i] for i in top_indices if line_numbers[i] != -1]
    
    if not suspicious_lines:
        return None
    
    # Count occurrences of each line
    line_counts = Counter(suspicious_lines)
    return line_counts.most_common(3)  # Return top 3 most suspicious lines

def calculate_severity_score(features, attention_weights):
    """Calculate a more nuanced severity score using multiple factors"""
    # Feature-based score (semantic meaning)
    feature_score = torch.norm(features).item() / 10
    
    # Attention-based score (how focused the attention is)
    attention_score = (attention_weights.max() - attention_weights.mean()).item() * 10
    
    # Complexity score (based on variance)
    complexity_score = attention_weights.var().item() * 5
    
    # Combine scores with different weights
    combined_score = (feature_score * 0.4) + (attention_score * 0.4) + (complexity_score * 0.2)
    
    # Map to severity levels with better thresholds
    if combined_score < 0.2:
        return 0  # No vulnerability
    elif 0.2 <= combined_score < 1.0:
        return 1  # Low
    elif 1.0 <= combined_score < 2.5:
        return 2  # Medium
    elif 2.5 <= combined_score < 4.0:
        return 3  # High
    else:
        return 4  # Critical

def analyze_code_with_codebert(code):
    """Comprehensive code analysis with improved severity detection"""
    # First check for known vulnerability patterns
    pattern_results = detect_vulnerability_patterns(code)
    if pattern_results:
        # Group by severity and get the most critical ones
        severity_groups = {}
        for vuln in pattern_results:
            if vuln['severity'] not in severity_groups:
                severity_groups[vuln['severity']] = []
            severity_groups[vuln['severity']].append(vuln)
        
        max_severity = max(severity_groups.keys())
        critical_vulns = severity_groups[max_severity]
        
        return {
            'prediction': SEVERITY_MAP.get(max_severity, "High severity"),
            'line_no': critical_vulns[0]['line'],
            'code_snippet': critical_vulns[0]['code'],
            'description': f"Detected {len(critical_vulns)} {critical_vulns[0]['type'].replace('_', ' ')} vulnerabilities",
            'confidence': "High",
            'pattern_matches': pattern_results,
            'severity_score': max_severity
        }
    
    # If no patterns found, use CodeBERT's deep analysis
    inputs = tokenizer(code, return_tensors="pt", truncation=True, max_length=512)
    line_numbers = get_line_numbers(code, inputs.input_ids[0])
    
    with torch.no_grad():
        outputs = model(**inputs)
    
    # Analyze attention weights from all layers
    all_attentions = torch.stack([attn[:, :, 0, :].mean(dim=1)[0] for attn in outputs.attentions])
    combined_attention = all_attentions.mean(dim=0)
    
    # Get semantic features for classification
    semantic_features = outputs.last_hidden_state.mean(dim=1)
    
    # Calculate severity score using multiple factors
    severity_score = calculate_severity_score(semantic_features, combined_attention)
    
    # If no vulnerability detected
    if severity_score == 0:
        return {
            'prediction': "No vulnerability",
            'line_no': -1,
            'code_snippet': "",
            'description': "No vulnerabilities detected",
            'confidence': "0%",
            'severity_score': 0
        }
    
    # Find suspicious lines through attention analysis
    attention_patterns = analyze_attention_patterns(combined_attention, line_numbers)
    if not attention_patterns:
        return {
            'prediction': SEVERITY_MAP.get(severity_score),
            'line_no': -1,
            'code_snippet': "",
            'description': "Potential architectural vulnerability detected",
            'confidence': f"{combined_attention.max().item()*100:.1f}%",
            'severity_score': severity_score
        }
    
    # Get details for the most suspicious line
    most_suspicious_line = attention_patterns[0][0]
    lines = code.split('\n')
    
    # Get surrounding context (5 lines before and after)
    start_line = max(0, most_suspicious_line - 3)
    end_line = min(len(lines), most_suspicious_line + 3)
    context_lines = [(i+1, lines[i]) for i in range(start_line, end_line)]
    
    return {
        'prediction': SEVERITY_MAP.get(severity_score),
        'line_no': most_suspicious_line,
        'code_snippet': lines[most_suspicious_line-1] if most_suspicious_line <= len(lines) else "",
        'description': "Potential vulnerability detected through deep analysis",
        'full_code': context_lines,
        'confidence': f"{combined_attention.max().item()*100:.1f}%",
        'severity_score': severity_score,
        'attention_patterns': attention_patterns
    }

# ... [rest of the Flask routes remain exactly the same as in your original code] ...

@app.route('/')
def home():
    return render_template('signup-in.html')

@app.route("/signup")
def signup():
    name = request.args.get('username', '')
    number = request.args.get('number', '')
    email = request.args.get('email', '')
    password = request.args.get('psw', '')

    con = sqlite3.connect('signup.db')
    cur = con.cursor()
    cur.execute("INSERT INTO `detail` (`name`,`number`,`email`, `password`) VALUES (?, ?, ?, ?)",
                (name, number, email, password))
    con.commit()
    con.close()

    return render_template("signup-in.html")

@app.route("/signin")
def signin():
    mail1 = request.args.get('name', '')
    password1 = request.args.get('psw', '')
    con = sqlite3.connect('signup.db')
    cur = con.cursor()
    cur.execute("SELECT `name`, `password` FROM detail WHERE `name` = ? AND `password` = ?",
                (mail1, password1))
    data = cur.fetchone()

    if data is None:
        return render_template("signup-in.html")
    elif mail1 == 'admin' and password1 == 'admin':
        return render_template("index1.html")
    elif mail1 == str(data[0]) and password1 == str(data[1]):
        return render_template("index1.html")
    else:
        return render_template("signup-in.html")

@app.route('/signout')
def signout():
    return render_template('signup-in.html')

@app.route("/index1", methods=["GET", "POST"])
def index1():
    return render_template('index1.html')

@app.route("/predict1", methods=["POST"])
def predict1():
    if "file" not in request.files:
        return redirect(request.url)

    file = request.files["file"]
    if file.filename == "":
        return redirect(request.url)

    if file:
        # Save the uploaded file temporarily
        file_path = os.path.join(tempfile.gettempdir(), file.filename)
        file.save(file_path)
        
        # Read the code
        with open(file_path, 'r') as f:
            code = f.read()
        
        try:
            # Analyze the code with CodeBERT
            result = analyze_code_with_codebert(code)
            
            # Prepare the full code with line numbers if we have a specific line
            full_code = None
            if result.get('line_no', -1) != -1:
                full_code = [(i+1, line) for i, line in enumerate(code.split('\n'))]
            
            # Prepare pattern matches if they exist
            pattern_matches = result.get('pattern_matches', None)
            
            return render_template('index1.html',
                                prediction=result['prediction'],
                                line_no=result.get('line_no', -1),
                                code_snippet=result.get('code_snippet', ""),
                                description=result.get('description', ""),
                                full_code=full_code,
                                confidence=result.get('confidence', "0%"),
                                pattern_matches=pattern_matches,
                                severity_score=result.get('severity_score', 0))
        
        except Exception as e:
            return render_template('index1.html',
                                prediction=f"Error during processing: {str(e)}",
                                error=True)
    
    return render_template('index1.html')

if __name__ == "__main__":
    app.run(debug=True, threaded=True)