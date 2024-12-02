
# Cloud Configuration Scanner

## Description
**Cloud Configuration Scanner** is a pentesting tool designed to identify insecure configurations, sensitive files, and exposed data on web servers. The tool allows quick or deep scanning of a server's endpoints, detecting potential vulnerabilities like API keys, exposed credentials, and insecure configurations.

⚠️ **Note:** This tool should only be used for ethical purposes and on servers where you have explicit authorization. Malicious use is strictly prohibited.

## Features
- Quick ("basic") and deep ("full") scanning modes for identifying sensitive files and configurations.
- Detailed content analysis of discovered files, detecting:
  - API Keys
  - Passwords
  - Access Tokens
  - Email Addresses
  - IP Addresses
- Export results in **JSON** and **CSV** formats.
- HTTP Proxy support for advanced testing.

## Requirements
Make sure you have:
- Python 3 installed.
- Required libraries installed (specified in `requirements.txt`).

Install dependencies with:
```bash
pip install -r requirements.txt
```

## Installation
1. **Clone the repository**:
   ```bash
   git clone https://github.com/ccyl13/Cloud-Scanner.git
   cd Cloud-Scanner
   ```

2. **Make the script executable**:
   ```bash
   chmod +x cloud_scanner.py
   ```

## Usage
Run the tool from the terminal with the following parameters:

### Options
- `-u, --url`: Target URL or domain to scan (required).
- `-m, --mode`: Scan mode:
  - `basic`: Quick scan.
  - `full`: Deep scan.
- `--proxy`: Specify an HTTP proxy (optional).
- `-o, --output`: Prefix for output files (JSON and CSV).
- `-i, --info`: Show help menu.

### Usage Examples
1. **Basic Scan**:
   ```bash
   ./cloud_scanner.py -u http://localhost:8000 -m basic -o basic_scan
   ```
2. **Full Scan**:
   ```bash
   ./cloud_scanner.py -u http://localhost:8000 -m full -o full_scan
   ```
3. **Scan with Proxy**:
   ```bash
   ./cloud_scanner.py -u http://localhost:8000 -m full --proxy http://127.0.0.1:8080 -o proxied_scan
   ```

## Screenshots
### Help Menu
The tool provides a detailed menu of options and parameters:

![Help Menu](https://github.com/ccyl13/Cloud-Scanner/blob/main/Par%C3%A1metros%20y%20ayuda.png?raw=true)

### Basic Scan
A quick scan searches for sensitive files on the server and displays the results:

![Basic Scan](https://github.com/user-attachments/assets/e3c9aee6-b641-4e72-8e2c-91206ac935d8)

### Full Scan
The full scan includes detailed analysis of discovered file contents:

![Full Scan](https://github.com/ccyl13/Cloud-Scanner/blob/main/Escaneo%20completo.png?raw=true)

### Exported Results
Scan results are exported in **JSON** and **CSV** formats for detailed analysis:

- **JSON File**:
  ```json
  [
      {
          "url": "http://localhost:8000/.env",
          "sensitive_data": {
              "API Key": ["12345-ABCDE"],
              "Password": ["SuperSecretPassword!"]
          }
      }
  ]
  ```

- **CSV File**:
  ```csv
  URL,Sensitive Data
  http://localhost:8000/.env,"{""API Key"": [""12345-ABCDE""], ""Password"": [""SuperSecretPassword!""]}"
  ```

![Exported Results](https://github.com/ccyl13/Cloud-Scanner/blob/main/Archivos%20encontrados%20y%20exportados%20en%20CSV%20y%20JSON.png?raw=true)

## Limitations
- Only scans servers using HTTP/HTTPS protocols.
- Content analysis is based on predefined patterns and may not detect custom configurations.

## Warning
Using this tool for unauthorized activities is illegal. Ensure you have explicit permission from the server owner before running any scans.

## License
This project is licensed under the [MIT License](LICENSE).

## Quick Summary
1. **Clone the repository**:
   ```bash
   git clone https://github.com/ccyl13/Cloud-Scanner.git
   cd Cloud-Scanner
   ```

2. **Grant execution permissions and display help**:
   ```bash
   chmod +x cloud_scanner.py
   ./cloud_scanner.py -i
   ```

3. **Run a full scan**:
   ```bash
   ./cloud_scanner.py -u http://localhost:8000 -m full -o scan_results
   ```
