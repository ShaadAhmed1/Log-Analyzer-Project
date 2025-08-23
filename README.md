# Log File Analyzer for Intrusion Detection

Project Overview
This is a Python-based tool designed to analyze log files (specifically Apache web server logs) to detect potential security threats such as brute-force attacks, directory scanning, and Denial-of-Service (DoS) attacks. It provides a comprehensive analysis, identifies suspicious IPs, and generates visual reports to aid in security monitoring.

Features

 Log Parsing: Efficiently parses Apache log files using regular expressions.

 Threat Detection:

  Identifies scanning attempts by tracking the number of unique paths accessed by a single IP address.

  Detects brute-force login attempts by counting failed login attempts from specific IPs.

  Pinpoints potential DoS attacks by monitoring rapid, high-volume requests from a single IP within a specified time window.

 IP Blacklist Cross-Referencing: Cross-references detected suspicious IP addresses with a public blacklist to identify known malicious actors.

 Data Visualization: Generates insightful plots to visualize key metrics:

  Top 10 IP Addresses by Request Count: A bar chart showing the most active IPs.

  Requests Over Time: A line graph illustrating traffic patterns over a period.

 Incident Reporting: Exports a text-based report detailing all detected threats and their associated IPs.

Visualizations

The tool generates the following data visualizations to provide a clear overview of the detected activity.


Top 10 IP Addresses by Request Count

This chart helps to quickly identify the IPs that are generating the most traffic, which can often be an indicator of malicious activity or heavy usage.


Requests Over Time

This line graph shows the volume of requests over a given time period, making it easy to spot unusual spikes in traffic that could indicate a DoS attack.


Getting Started

Prerequisites
Python 3.x

The following Python libraries: pandas, re, requests, matplotlib

You can install the required libraries using pip:

pip install pandas matplotlib requests

Usage
Place your Apache log file (e.g., sample-Apache-log.txt) in the same directory as the Python script.

Run the script from your terminal:

python your_script_name.py

The script will:

Print the parsed log data to the console.

Print the detected suspicious IPs.

Generate and display the data visualizations.

Create a text file named incident_report.txt with a summary of the findings.

Code Structure
parse_apache_log_file(file_path): Parses the log file and returns a pandas DataFrame.

detect_scanning(apache_df): Identifies potential scanning IPs.

detect_brute_force_login(apache_df): Detects brute-force attempts on a specified login path.

detect_dos(apache_df): Identifies potential DoS attack IPs.

get_blacklist(): Fetches a public IP blacklist.

generate_report(...): Creates and exports the incident report.

visualize_top_ips(apache_df): Generates the bar chart for top IPs.

visualize_requests_over_time(apache_df): Generates the line graph for requests over time.
