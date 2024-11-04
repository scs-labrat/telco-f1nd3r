# TELCO F1ND3R

![Hoody Image](hoody.png)

Telco F1ND3R is a comprehensive toolkit designed to discover, analyze, and visualize telecom infrastructure targets. Originally designed to facilitate research on telecommunications protocols and their related systems, Telco F1ND3R features a range of functionalities to assist researchers, hackers, and cybersecurity professionals in identifying and assessing vulnerabilities in telco networks. With a focus on ports related to telco protocols such as Diameter, SCTP, and GTP, this tool uses `ip4scout` and `l9filter` to discover targets and enriches findings with Shodan data.

## Features
- **Target Discovery** using `ip4scout` and `l9filter`.
- **Unique Parsing and Highlighting** of found targets by protocol type.
- **Shodan Integration** for retrieving additional data on discovered targets.
- **SCTP Nmap Scanning** for in-depth protocol analysis.
- **Parallel Processing** for faster, efficient target assessments.

## Dependencies
The following dependencies are required for Telco F1ND3R to operate properly:

- **Python Libraries**:
  - `os`
  - `re`
  - `subprocess`
  - `shutil`
  - `termcolor`
  - `pyfiglet`
  - `sys`
  - `select`
  - `json`
  - `shodan`
  - `ThreadPoolExecutor`
  - `time`

  You can install the necessary Python packages by running:
  ```bash
  pip install termcolor pyfiglet shodan
  ```

- **Command Line Tools**:
  - **ip4scout**: Used for IP scanning and target discovery.
  - **l9filter**: Used for data transformation to create human-readable output.

  You can install these dependencies with:
  ```bash
  wget https://github.com/LeakIX/ip4scout/releases/download/v1.0.0-beta.2/ip4scout-linux-64
  chmod +x ip4scout-linux-64
  sudo mv ip4scout-linux-64 /usr/local/bin/ip4scout

  wget https://github.com/LeakIX/l9filter/releases/download/v1.1.0/l9filter-linux-64
  chmod +x l9filter-linux-64
  sudo mv l9filter-linux-64 /usr/local/bin/l9filter
  ```

## Usage
Telco F1ND3R features a menu-driven interface that allows users to select actions like finding targets, parsing data, querying Shodan, running SCTP scans, and saving results. Simply run the script and follow the prompts in the main menu.

To start Telco F1ND3R, run:
```bash
python telco_f1nd3r.py
```

### Main Menu Options
1. **Check and Install Dependencies**: Ensures required tools (`ip4scout`, `l9filter`) are installed.
2. **Find Telco Targets**: Starts the discovery process for open telco-related ports.
3. **Parse Telco Target Data with Highlighting**: Highlights specific ports and protocols in the output.
4. **Query Shodan for a Target**: Use the Shodan API to find more information about a target.
5. **Run SCTP Nmap Scan for a Target**: Performs an SCTP scan on a chosen target.
6. **Run SCTP Nmap Scan for All Targets**: Performs SCTP scans for all found targets in parallel.
7. **Save Parsed Data to CSV**: Save scan results for future reference.
8. **Exit**: Close the application.

## Environment Setup
You must export your **Shodan API key** for the Shodan queries to work:
```bash
export SHODAN_API_KEY='your_shodan_api_key_here'
```
Ensure you have `sudo` privileges if you plan on running SCTP Nmap scans.

## Contributing
Contributions are welcome! If you would like to enhance Telco F1ND3R or add new features, please fork the repository, create a new branch, and submit a pull request. Let’s make this tool even better together.

## License
Telco F1ND3R is licensed under the MIT License. See `LICENSE` for more information.

## Acknowledgments
- **d8rh8r** for the ASCII art inspiration and contributions to the community.
- **LeakIX** for `ip4scout` and `l9filter`, crucial components of the discovery workflow.

Happy hacking and stay secure!

