from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import nmap  # Ensure you have python-nmap installed via `pip install python-nmap`
import subprocess
import requests

app = Flask(__name__)

# Set the secret key for session
app.secret_key = "your_super_secret_key"  # Replace with a strong key for production

# Route for Login Page
@app.route('/')
def login():
    return render_template('login.html')

# Route to handle login form submission
@app.route('/login', methods=['POST'])
def handle_login():
    email = request.form['email']
    password = request.form['password']

    # Simple Validation (Replace with DB/Authentication later)
    if email == "admin@example.com" and password == "password123":
        return redirect('/index')  # Redirect to your existing tool page
    else:
        return "Invalid credentials. Please try again!"
    
# Existing route (already defined in your code)
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/quiz')
def quiz():
    return render_template('quiz.html')

@app.route('/tips')
def tips():
    return render_template('tips.html')

# Route to serve Nmap form
@app.route('/nmap', methods=['GET'])
def nmap_page():
    return render_template('nmap.html')

# Route to handle Nmap scan and show results
@app.route('/nmap_scan', methods=['POST'])
def nmap_scan():
    target_ip = request.form.get('target')  # IP/domain from the form
    port_range = request.form.get('ports')  # Ports/range from the form

    try:
        # Initialize nmap scanner
        scanner = nmap.PortScanner(nmap_search_path=['C:\\Program Files (x86)\\Nmap\\nmap.exe'])

        # Perform scan (blocking method)
        scan_result = scanner.scan(hosts=target_ip, ports=port_range)
        
        # Extracting important data
        ports_info = scan_result['scan'][target_ip]['tcp'] if target_ip in scan_result['scan'] else "No data available"

        return render_template('nmap_result.html', target=target_ip, ports_info=ports_info)

    except Exception as e:
        # Handle exception (e.g., wrong input or nmap error)
        error_message = f"Scan failed: {str(e)}"
        return render_template('nmap_result.html', error=error_message)
    
@app.route('/password-checker')
def password_checker():
    return render_template('password-checker.html')


# Existing routes ke saath ye naya route
@app.route('/check_password_strength', methods=['POST'])
def check_password_strength():
    password = request.form['password']
    strength, result = evaluate_password_strength(password)
    return jsonify({'strength': strength, 'result': result})


def evaluate_password_strength(password):
    if len(password) < 8:
        return 'weak', 'The password is too short! Please use a minimum of 8 characters.'
    if password.isdigit() or password.isalpha():
        return 'weak', 'The password should not contain only letters or only numbers. Please mix them!'
    if len(set(password)) < 4:
        return 'weak', 'The password lacks variety. Do not use repetitive characters!'
    if any(char.isdigit() for char in password) and any(char.isalpha() for char in password):
        if len(password) >= 12:
            return 'strong', 'Wow! Strong password! You are safe now!'
        else:
            return 'moderate', 'The password is okay, but try to make it a bit stronger!'
    return 'weak', 'Weak password. Mix letters, numbers, and symbols!'

@app.route('/ping', methods=['GET', 'POST'])
def ping_tool():
    result = None
    if request.method == 'POST':
        ip_address = request.form['ip_address']
        try:
            # Run the ping command
            command = ['ping', '-n', '4', ip_address]  # Adjust '-n 4' to suit your platform (use '-n 4' on Windows)
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            if process.returncode == 0:
                result = stdout.decode('utf-8')
            else:
                result = stderr.decode('utf-8')
        except Exception as e:
            result = f"An error occurred: {e}"

    return render_template('ping.html', result=result)

@app.route('/traceroute', methods=['GET', 'POST'])
def traceroute():
    if request.method == 'POST':
        host = request.form['host']
        try:
            # Windows-specific tracert command
            result = subprocess.check_output(['tracert', host], stderr=subprocess.STDOUT)
            output = result.decode('utf-8')
        except subprocess.CalledProcessError as e:
            output = None
            error = f"Error: {e.output.decode('utf-8')}"
            return render_template('traceroute.html', error=error)
        except FileNotFoundError as fnf_error:
            error = f"FileNotFoundError: {fnf_error}"
            return render_template('traceroute.html', error=error)
        return render_template('traceroute.html', output=output)
    return render_template('traceroute.html', output=None)

@app.route('/dnslookup', methods=['GET', 'POST'])
def dns_lookup():
    if request.method == 'POST':  # Jab user form submit karega
        domain = request.form['domain']  # User se domain input milega
        try:
            result = subprocess.check_output(['nslookup', domain], stderr=subprocess.STDOUT)
            output = result.decode('utf-8')  # DNS lookup ka result yahan aa jayega
        except subprocess.CalledProcessError as e:
            output = None
            error = f"Error: {e.output.decode('utf-8')}"  # Agar koi error aaye toh
            return render_template('dns_lookup.html', error=error)
        except FileNotFoundError as fnf_error:
            error = f"FileNotFoundError: {fnf_error}"  # Agar 'nslookup' command nahi milti
            return render_template('dns_lookup.html', error=error)
        return render_template('dns_lookup_result.html', domain=domain, output=output)  # Result page dikhana
    return render_template('dns_lookup.html', output=None)  # Default page agar koi form submit na ho

@app.route("/phishing-url", methods=["GET", "POST"])
def phishing_url():
    if request.method == "POST":
        url = request.form["url"]
        # Example for checking phishing (you can integrate an actual phishing URL detection API)
        if "phishing" in url:  # Fake phishing check (replace with actual logic)
            result = "Phishing Attempt"
            message = "This URL is likely a phishing attempt. Please proceed with caution!"
        else:
            result = "Safe"
            message = "This URL seems safe. No phishing detected."
        return render_template("phishing_url_result.html", url=url, result=result, message=message)
    return render_template("phishing_url.html")

@app.route("/phishing-url-result", methods=["POST"])
def phishing_url_result():
    return phishing_url()

@app.route('/ip-geolocation')
def ip_geolocation():
    return render_template('ip_geolocation.html')

@app.route('/ip-geolocation-result', methods=['POST'])
def ip_geolocation_result():
    ip = request.form['ip']
    api_url = f"http://ip-api.com/json/{ip}"
    response = requests.get(api_url).json()
    
    if response['status'] == 'success':
        result = {
            'ip': ip,
            'country': response.get('country', 'N/A'),
            'region': response.get('regionName', 'N/A'),
            'city': response.get('city', 'N/A'),
            'latitude': response.get('lat', 'N/A'),
            'longitude': response.get('lon', 'N/A'),
        }
    else:
        result = {
            'ip': ip,
            'country': 'N/A',
            'region': 'N/A',
            'city': 'N/A',
            'latitude': 'N/A',
            'longitude': 'N/A',
        }

    return render_template('ip_geolocation_result.html', **result)

@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route('/http_header_analyzer', methods=['GET', 'POST'])
def http_header_analyzer():
    if request.method == 'POST':
        url = request.form['url']
        headers = requests.get(url).headers
        return render_template('http_header_analyzer.html', headers=headers)
    return render_template('http_header_analyzer.html')

if __name__ == '__main__':
    app.run(debug=True)
