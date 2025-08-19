import pandas as pd
import re

APACHE_LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<timestamp>.*?)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<size>\d+|-)'
)

def parse_apache_log_file(file_path):
    """
    Parses an Apache log file and returns a pandas DataFrame.
    """
    log_data = []
    with open(file_path, 'r') as file:
        for line in file:
            match = APACHE_LOG_PATTERN.match(line)
            if match:
                log_data.append(match.groupdict())
    
    return pd.DataFrame(log_data)

# Example usage:
# If your Apache log file is named 'apache_access.log'
apache_df = parse_apache_log_file('sample-Apache-log.txt')
print("Apache Log Data:")
print(apache_df.head())