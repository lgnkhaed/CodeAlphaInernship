# Secure Code Review
## Code Alpha Internship
### By LAGGOUN Khaled

---

### What is Secure Code Review?

Secure code review is the process of analyzing source code to identify potential security vulnerabilities. It can be performed manually (by reading and inspecting the code) or automatically using specialized tools.

Secure code review helps ensure that an application follows security best practices and is resistant to common threats such as SQL injection, command injection, and insecure use of system resources.

---

### Tools for Secure Code Review

Different tools are available depending on the programming language. Some popular tools include:

- **Bandit** – for Python
- **SonarQube** – for multiple languages
- **Brakeman** – for Ruby on Rails
- **FindBugs / SpotBugs** – for Java
- **ESLint (with security plugins)** – for JavaScript

For this project, we will focus on **Python** and use **Bandit** to analyze vulnerabilities.


--- 

### Analyzing Some Common Vulnerabilities with **Bandit** 

#### Note:  
In this part, I am going to give a code example that contains one of the vulnerabilities. I will use Bandit to inspect the code and show what Bandit reports. Then, I will present the fixed code and Bandit's analysis, followed by the key point of the solution.

---


-**SQL Injection** 

**Definition :**
SQL Injection is a web security vulnerability that allows an attacker to inject malicious SQL code into a query, which is then executed by the server. This can allow the attacker to access, modify, or delete data without proper authorization, and in some cases, even take full control of the database. 

**Unsecure code :** 

This code is a simple example of a login system built using Flask and Python, which is vulnerable to SQL injection.


```python 
import sqlite3
from flask import Flask, request

app = Flask(__name__)

def create_database():
    conn = sqlite3.connect('example.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute("INSERT INTO users (username, password) VALUES ('admin', 'adminpass')")
    conn.commit()
    conn.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    username = request.args.get('username')
    password = request.args.get('password')
    conn = sqlite3.connect('example.db')
    c = conn.cursor()
    
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print("Executing query:", query)
    c.execute(query)
    result = c.fetchone()
    conn.close()
    if result:
        return "Login successful"
    else:
        return "Login failed"

if __name__ == '__main__':
    create_database()
    app.run(debug=True)
```

**Bandit's Analysis :**

To analyze the code and print the output in JSON format, I used the following command:

` bandit -r sqli.py -f json -o report.json `

**The Output :** 

```json 
{
  "errors": [],
  "generated_at": "2025-06-30T09:20:28Z",
  "metrics": {
    "./sqli.py": {
      "CONFIDENCE.HIGH": 0,
      "CONFIDENCE.LOW": 1,
      "CONFIDENCE.MEDIUM": 1,
      "CONFIDENCE.UNDEFINED": 0,
      "SEVERITY.HIGH": 1,
      "SEVERITY.LOW": 0,
      "SEVERITY.MEDIUM": 1,
      "SEVERITY.UNDEFINED": 0,
      "loc": 28,
      "nosec": 0,
      "skipped_tests": 0
    },
    "_totals": {
      "CONFIDENCE.HIGH": 0,
      "CONFIDENCE.LOW": 1,
      "CONFIDENCE.MEDIUM": 1,
      "CONFIDENCE.UNDEFINED": 0,
      "SEVERITY.HIGH": 1,
      "SEVERITY.LOW": 0,
      "SEVERITY.MEDIUM": 1,
      "SEVERITY.UNDEFINED": 0,
      "loc": 28,
      "nosec": 0,
      "skipped_tests": 0
    }
  },
  "results": [
    {
      "code": "20     \n21     query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"\n22     print(\"Executing query:\", query)\n",
      "col_offset": 14,
      "end_col_offset": 52,
      "filename": "./sqli.py",
      "issue_confidence": "LOW",
      "issue_cwe": {
        "id": 89,
        "link": "https://cwe.mitre.org/data/definitions/89.html"
      },
      "issue_severity": "MEDIUM",
      "issue_text": "Possible SQL injection vector through string-based query construction.",
      "line_number": 21,
      "line_range": [
        21
      ],
      "more_info": "https://bandit.readthedocs.io/en/1.7.10/plugins/b608_hardcoded_sql_expressions.html",
      "test_id": "B608",
      "test_name": "hardcoded_sql_expressions"
    },
    {
      "code": "32     create_database()\n33     app.run(debug=True)\n",
      "col_offset": 4,
      "end_col_offset": 23,
      "filename": "./sqli.py",
      "issue_confidence": "MEDIUM",
      "issue_cwe": {
        "id": 94,
        "link": "https://cwe.mitre.org/data/definitions/94.html"
      },
      "issue_severity": "HIGH",
      "issue_text": "A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.",
      "line_number": 33,
      "line_range": [
        33
      ],
      "more_info": "https://bandit.readthedocs.io/en/1.7.10/plugins/b201_flask_debug_true.html",
      "test_id": "B201",
      "test_name": "flask_debug_true"
    }
  ]
}                                                            
```

We can clearly see the warning messages regarding issue severity:

    MEDIUM: Possible SQL injection in line 21

    HIGH: Flask application is running with debug=True, which is dangerous

In this code, we are going to focus on the SQL injection vulnerability, and not on the Flask debug mode, because we are using Flask just for demonstration purposes.


**Issue :**
The reason our code is vulnerable to SQL injection is that we are hardcoding the SQL query using string formatting. This allows attackers to manipulate the SQL statement via the URL.

For example:

    URL → http://127.0.0.1:5000/login?username=test&password=admin
    → Result: Login failed

    URL → http://127.0.0.1:5000/login?username=admin'--&password=admin
    → Result: Login successful

Why? Because the '-- comment symbol ignores the rest of the SQL condition, bypassing password verification



-**Secure Code :** 

```python 
import sqlite3
from flask import Flask, request

app = Flask(__name__)

def create_database():
    conn = sqlite3.connect('example.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute("INSERT INTO users (username, password) VALUES ('admin', 'adminpass')")
    conn.commit()
    conn.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    username = request.args.get('username')
    password = request.args.get('password')
    conn = sqlite3.connect('example.db')
    c = conn.cursor()
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    print("Executing query with parameters:", query, (username, password))
    c.execute(query, (username, password))
    result = c.fetchone()
    conn.close()
    if result:
        return "Login successful"
    else:
        return "Login failed"

if __name__ == '__main__':
    create_database()
    app.run(debug=True)
```

**Bandit's Analysis :** 
 i used the same command as before 

**The Output :** 

```json 
{
  "errors": [],
  "generated_at": "2025-06-30T09:39:17Z",
  "metrics": {
    "./sqli_fixed.py": {
      "CONFIDENCE.HIGH": 0,
      "CONFIDENCE.LOW": 0,
      "CONFIDENCE.MEDIUM": 1,
      "CONFIDENCE.UNDEFINED": 0,
      "SEVERITY.HIGH": 1,
      "SEVERITY.LOW": 0,
      "SEVERITY.MEDIUM": 0,
      "SEVERITY.UNDEFINED": 0,
      "loc": 28,
      "nosec": 0,
      "skipped_tests": 0
    },
    "_totals": {
      "CONFIDENCE.HIGH": 0,
      "CONFIDENCE.LOW": 0,
      "CONFIDENCE.MEDIUM": 1,
      "CONFIDENCE.UNDEFINED": 0,
      "SEVERITY.HIGH": 1,
      "SEVERITY.LOW": 0,
      "SEVERITY.MEDIUM": 0,
      "SEVERITY.UNDEFINED": 0,
      "loc": 28,
      "nosec": 0,
      "skipped_tests": 0
    }
  },
  "results": [
    {
      "code": "31     create_database()\n32     app.run(debug=True)\n",
      "col_offset": 4,
      "end_col_offset": 23,
      "filename": "./sqli_fixed.py",
      "issue_confidence": "MEDIUM",
      "issue_cwe": {
        "id": 94,
        "link": "https://cwe.mitre.org/data/definitions/94.html"
      },
      "issue_severity": "HIGH",
      "issue_text": "A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.",
      "line_number": 32,
      "line_range": [
        32
      ],
      "more_info": "https://bandit.readthedocs.io/en/1.7.10/plugins/b201_flask_debug_true.html",
      "test_id": "B201",
      "test_name": "flask_debug_true"
    }
  ]
}
```

we can see that the sql injection warning is'nt there anymore 

**the solution :**
Use parameterized queries to safely insert user input into SQL commands and prevent SQL injection vulnerabilities.


--- 
   -**Path Traversal :** 
   Path Traversal (also known as Directory Traversal) is a web security vulnerability that allows an attacker to access files and directories that are stored outside the intended folder of a web application. It exploits improper input validation of file paths by manipulating variables that reference files or directories on the server. 

   -**Unsecure code :** 
   This is a simple example of a Flask-based file download system written in Python that is vulnerable to path traversal


```python 
from flask import Flask, request, send_file
import os

app = Flask(__name__)

@app.route('/download', methods=['GET'])
def download_file():
    filename = request.args.get('filename')

    # Vulnerable path traversal
    filepath = os.path.join(os.getcwd(), filename)

    # Check if file exists and send it
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    else:
        return "File not found", 404

if __name__ == '__main__':
    app.run(debug=True)
```

  -**Bandit's analysis :** 
   The command used : ` bandit -r path_travel.py -f json -o report_path_travel.json`

  -**The Output :**

  ```json  
{
  "errors": [],
  "generated_at": "2025-06-30T14:45:51Z",
  "metrics": {
    "./path_travel.py": {
      "CONFIDENCE.HIGH": 0,
      "CONFIDENCE.LOW": 0,
      "CONFIDENCE.MEDIUM": 1,
      "CONFIDENCE.UNDEFINED": 0,
      "SEVERITY.HIGH": 1,
      "SEVERITY.LOW": 0,
      "SEVERITY.MEDIUM": 0,
      "SEVERITY.UNDEFINED": 0,
      "loc": 13,
      "nosec": 0,
      "skipped_tests": 0
    },
    "_totals": {
      "CONFIDENCE.HIGH": 0,
      "CONFIDENCE.LOW": 0,
      "CONFIDENCE.MEDIUM": 1,
      "CONFIDENCE.UNDEFINED": 0,
      "SEVERITY.HIGH": 1,
      "SEVERITY.LOW": 0,
      "SEVERITY.MEDIUM": 0,
      "SEVERITY.UNDEFINED": 0,
      "loc": 13,
      "nosec": 0,
      "skipped_tests": 0
    }
  },
  "results": [
    {
      "code": "19 if __name__ == '__main__':\n20     app.run(debug=True)\n",
      "col_offset": 4,
      "end_col_offset": 23,
      "filename": "./path_travel.py",
      "issue_confidence": "MEDIUM",
      "issue_cwe": {
        "id": 94,
        "link": "https://cwe.mitre.org/data/definitions/94.html"
      },
      "issue_severity": "HIGH",
      "issue_text": "A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.",
      "line_number": 20,
      "line_range": [
        20
      ],
      "more_info": "https://bandit.readthedocs.io/en/1.7.10/plugins/b201_flask_debug_true.html",
      "test_id": "B201",
      "test_name": "flask_debug_true"
    }
  ]
}   
```

  -**The issue :**
  As seen in the report, Bandit flags the use of debug=True, but it does not detect the path traversal vulnerability directly. Nevertheless, the vulnerability exists due to improper handling of user-supplied file paths

For example:

    URL → http://127.0.0.1:5000/download?filename=file.txt 
    → Result: File not found

    URL → http://127.0.0.1:5000/download?filename=/../../../../etc/passwd
    → Result: the passwd file is downloaded 



-**Secure Code :**
  ```python
  from flask import Flask, request, send_file, abort
import os

app = Flask(__name__)

UPLOAD_DIRECTORY = 'uploads'

@app.route('/download', methods=['GET'])
def download_file():
    filename = request.args.get('filename')

    # Securely sanitize and validate the filename
    safe_filename = os.path.basename(filename)
    filepath = os.path.join(UPLOAD_DIRECTORY, safe_filename)

    # Ensure the file is within the upload directory
    if os.path.commonprefix([UPLOAD_DIRECTORY, filepath]) == UPLOAD_DIRECTORY and os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    else:
        abort(404)

if __name__ == '__main__':
    app.run(debug=True)
```

-**Bandit's Analysis :** 
 the same command used before 


```json
{
  "errors": [],
  "generated_at": "2025-06-30T15:04:10Z",
  "metrics": {
    "./path_travel_fixed.py": {
      "CONFIDENCE.HIGH": 0,
      "CONFIDENCE.LOW": 0,
      "CONFIDENCE.MEDIUM": 1,
      "CONFIDENCE.UNDEFINED": 0,
      "SEVERITY.HIGH": 1,
      "SEVERITY.LOW": 0,
      "SEVERITY.MEDIUM": 0,
      "SEVERITY.UNDEFINED": 0,
      "loc": 15,
      "nosec": 0,
      "skipped_tests": 0
    },
    "_totals": {
      "CONFIDENCE.HIGH": 0,
      "CONFIDENCE.LOW": 0,
      "CONFIDENCE.MEDIUM": 1,
      "CONFIDENCE.UNDEFINED": 0,
      "SEVERITY.HIGH": 1,
      "SEVERITY.LOW": 0,
      "SEVERITY.MEDIUM": 0,
      "SEVERITY.UNDEFINED": 0,
      "loc": 15,
      "nosec": 0,
      "skipped_tests": 0
    }
  },
  "results": [
    {
      "code": "22 if __name__ == '__main__':\n23     app.run(debug=True)\n",
      "col_offset": 4,
      "end_col_offset": 23,
      "filename": "./path_travel_fixed.py",
      "issue_confidence": "MEDIUM",
      "issue_cwe": {
        "id": 94,
        "link": "https://cwe.mitre.org/data/definitions/94.html"
      },
      "issue_severity": "HIGH",
      "issue_text": "A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.",
      "line_number": 23,
      "line_range": [
        23
      ],
      "more_info": "https://bandit.readthedocs.io/en/1.7.10/plugins/b201_flask_debug_true.html",
      "test_id": "B201",
      "test_name": "flask_debug_true"
    }
  ]
}
```

-**The Solution :** 
  
  Use a safe directory restriction technique and validate user inputs strictly to prevent traversal outside the designated folder.





