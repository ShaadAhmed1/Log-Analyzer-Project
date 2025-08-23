Project Progress Log

August 19, 2025
Accomplished:
    * Set up the development environment (installed Python, pandas, and other libraries).
    * Wrote the initial script to parse the Apache log file using `re` and `pandas`.
    * Successfully read and structured the sample log data into a DataFrame.

August 21, 2025
Accomplished:
*Brute-Force Detection: Implemented regex patterns to identify multiple failed login attempts from a single IP address within a short time frame on SSH logs. The tool now flags these IPs as potential threats.

*Scanning Patterns: Developed logic to detect web server scanning by identifying repeated requests for non-existent pages or directories, often a precursor to attacks.

*Denial-of-Service (DoS) Patterns: Created a mechanism to count rapid, high-volume requests from a single IP on Apache logs, indicating a potential DoS attack. The tool now sets a threshold to alert on such activity

August 23, 2025
Accomplished:

IP Blacklist Cross-Referencing:
The tool now has the functionality to download and parse a public IP blacklist.

Incident Reporting:

The report for each incident now includes the Scanning Detectionsn, Brute-Force Login Detections, DoS Detections. With Ip Blacklist Cross-Referencing.

Data Visualization:

Using matplotlib, I created scripts to generate and save visualizations of access patterns.

Access by IP: The tool now generates a bar chart showing the top 10 most active IP addresses, providing a clear visual representation of traffic sources.

Access by Time: A line graph is now generated showing the number of requests over time, which helps in identifying traffic spikes and unusual activity patterns.
