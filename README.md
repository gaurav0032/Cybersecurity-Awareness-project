# Cybersecurity Awareness Tool

## Description
This project is a **Cybersecurity Awareness Tool** built using Flask. It provides users with various security tools to enhance their knowledge about cybersecurity and helps them test different aspects of their online security.

## Features
The project includes the following tools:

1. **Password Strength Checker** - Analyzes password strength and suggests improvements.
2. **Nmap Port Scanner** - Scans open ports on a given IP address or domain.
3. **DNS Lookup** - Retrieves DNS records for a domain.
4. **Ping Tool** - Checks the availability and latency of a server.
5. **Traceroute Tool** - Maps the route packets take to reach a host.
6. **Phishing URL Tool** - Detects if a URL is potentially a phishing link.
7. **IP Geolocation Tool** - Finds the geolocation of an IP address.
8. **HTTP Header Analyzer** - Analyzes HTTP headers of a website.

Additionally, the project includes **Security Tips** and **Quizzes** to educate users.

## Installation

1. **Clone the repository:**
   ```bash
   git clone <https://github.com/gaurav0032/Cybersecurity-Awareness-project.git>
   cd cybersecurity-awareness-tool
   ```

2. **Set up a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use 'venv\Scripts\activate'
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Flask app:**
   ```bash
   python app.py
   ```

5. **Access the app:**
   Open your browser and visit `http://127.0.0.1:5000`

## Usage
- **Home Page:** Displays an introduction and links to all the tools.
- **Tools Page:** Each tool has a dedicated page for user input and displaying results.
- **Security Tips:** Educates users on best cybersecurity practices.
- **Quizzes:** Interactive quizzes to test users' cybersecurity knowledge.

## Folder Structure
```
cybersecurity-awareness-tool/
│
├── static/               # CSS, JS, images
├── templates/            # HTML templates for Flask
├── tools/                # Python scripts for each tool
├── app.py                # Main Flask application
├── requirements.txt      # Project dependencies
└── README.md             # Project documentation
```

## Future Enhancements
- Adding more security-related tools.
- Enhancing the UI for better user experience.
- Implementing real-time threat alerts using external APIs.

## Contributing
Contributions are welcome! Feel free to submit a pull request or open an issue.

## License
This project is licensed under the MIT License.

