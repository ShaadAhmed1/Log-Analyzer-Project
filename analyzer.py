import pandas as pd
import re
import requests
import matplotlib.pyplot as plt

APACHE_LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<timestamp>.*?)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<size>\d+|-)'
)

def parse_apache_log_file(file_path):
    
    log_data = []
    with open(file_path, 'r') as file:
        for line in file:
            match = APACHE_LOG_PATTERN.match(line)
            if match:
                log_data.append(match.groupdict())
    
    return pd.DataFrame(log_data)

def detect_scanning(apache_df, threshold=20):
    
    unique_paths_per_ip = apache_df.groupby('ip')['path'].nunique()
    return unique_paths_per_ip[unique_paths_per_ip > threshold].index.tolist()

def detect_brute_force_login(apache_df, login_path='/login.php', threshold=5):
    
    login_attempts = apache_df[apache_df['path'] == login_path]
    failed_logins = login_attempts[login_attempts['status'].astype(int) >= 400]
    brute_force_ips = failed_logins['ip'].value_counts()
    return brute_force_ips[brute_force_ips > threshold].index.tolist()

def detect_dos(apache_df, time_window='1min', threshold=100):
    
    apache_df['timestamp'] = pd.to_datetime(apache_df['timestamp'], format='%d/%b/%Y:%H:%M:%S +0000', errors='coerce')
    apache_df = apache_df.dropna(subset=['timestamp'])

    requests_by_ip_time = apache_df.groupby(['ip', pd.Grouper(key='timestamp', freq=time_window)]).size()
    
    requests_by_ip_time = requests_by_ip_time.unstack(level='ip', fill_value=0)
    
    dos_ips = requests_by_ip_time[requests_by_ip_time > threshold].any(axis=0).index.tolist()
    
    return dos_ips

def get_blacklist():
    
    url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return set(response.text.strip().split('\n'))
        return set()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching blacklist: {e}")
        return set()

def generate_report(scanning_ips, brute_force_ips, dos_ips, report_path='incident_report.txt'):
    
    blacklist = get_blacklist()

    with open(report_path, 'w') as f:
        f.write("--- Log File Analysis Report ---\n\n")
        f.write("Time of Report: " + pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S") + "\n\n")

        f.write("Scanning Detections:\n")
        if scanning_ips:
            for ip in scanning_ips:
                is_blacklisted = ' (Blacklisted)' if ip in blacklist else ''
                f.write(f"- IP: {ip}{is_blacklisted}\n")
        else:
            f.write("No scanning attempts detected.\n")

        f.write("\nBrute-Force Login Detections:\n")
        if brute_force_ips:
            for ip in brute_force_ips:
                is_blacklisted = ' (Blacklisted)' if ip in blacklist else ''
                f.write(f"- IP: {ip}{is_blacklisted}\n")
        else:
            f.write("No brute-force attempts detected.\n")

        f.write("\nDoS Detections:\n")
        if dos_ips:
            for ip in dos_ips:
                is_blacklisted = ' (Blacklisted)' if ip in blacklist else ''
                f.write(f"- IP: {ip}{is_blacklisted}\n")
        else:
            f.write("No DoS attempts detected.\n")

def visualize_top_ips(apache_df, num_ips=10):
    
    top_ips = apache_df['ip'].value_counts().head(num_ips)
    
    plt.figure(figsize=(10, 6))
    top_ips.plot(kind='bar')
    plt.title(f'Top {num_ips} IP Addresses by Request Count')
    plt.xlabel('IP Address')
    plt.ylabel('Number of Requests')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

def visualize_requests_over_time(apache_df, time_window='1min'):
    
    apache_df['timestamp'] = pd.to_datetime(apache_df['timestamp'], format='%d/%b/%Y:%H:%M:%S +0000', errors='coerce')
    apache_df = apache_df.dropna(subset=['timestamp'])

    requests_over_time = apache_df.resample(time_window, on='timestamp', group_keys=False).size()
    
    plt.figure(figsize=(12, 6))
    requests_over_time.plot()
    plt.title('Requests Over Time')
    plt.xlabel('Time')
    plt.ylabel('Number of Requests')
    plt.grid(True)
    plt.show()

if __name__ == "__main__":
    apache_log_path = 'sample-Apache-log.txt'
    apache_df = parse_apache_log_file(apache_log_path)
    print("Apache Log Data:")
    print(apache_df.head())

    scanning_detections = detect_scanning(apache_df)
    brute_force_detections = detect_brute_force_login(apache_df)
    dos_detections = detect_dos(apache_df)

    print("Potential scanning IPs:", scanning_detections)
    print("Potential brute-force IPs on /login.php:", brute_force_detections)
    print("Potential DoS IPs:", dos_detections)

    generate_report(scanning_detections, brute_force_detections, dos_detections)
    print("\nReport generated successfully!")

    visualize_top_ips(apache_df)
    visualize_requests_over_time(apache_df)
