import re
import csv
from collections import Counter, defaultdict

# Configurable threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

# File paths
LOG_FILE = 'sample.log'
OUTPUT_FILE = 'log_analysis_results.csv'

# Patterns for log analysis
LOG_PATTERN = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*?\] "(?:GET|POST) (?P<endpoint>/\S*) HTTP/1\.\d" (?P<status>\d+) .*')

# Data storage
ip_requests = Counter()
endpoint_access = Counter()
failed_logins = defaultdict(int)

# Read and parse the log file
with open(LOG_FILE, 'r') as log_file:
    for line in log_file:
        match = LOG_PATTERN.match(line)
        if match:
            ip = match.group('ip')
            endpoint = match.group('endpoint')
            status = match.group('status')
            
            # Count IP requests
            ip_requests[ip] += 1
            
            # Count endpoint access
            endpoint_access[endpoint] += 1
            
            # Count failed logins
            if status == '401':
                failed_logins[ip] += 1

# Sort and prepare data for output
sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
most_accessed_endpoint = max(endpoint_access.items(), key=lambda x: x[1])
suspicious_ips = [(ip, count) for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD]

# Output results to terminal
print("\nIP Address Request Count:")
print(f"{'IP Address':<20}{'Request Count':<15}")
for ip, count in sorted_ip_requests:
    print(f"{ip:<20}{count:<15}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

print("\nSuspicious Activity Detected:")
if suspicious_ips:
    print(f"{'IP Address':<20}{'Failed Login Attempts':<20}")
    for ip, count in suspicious_ips:
        print(f"{ip:<20}{count:<20}")
else:
    print("No suspicious activity detected.")

# Save results to CSV
with open(OUTPUT_FILE, 'w', newline='') as csv_file:
    writer = csv.writer(csv_file)
    
    # Write IP requests
    writer.writerow(['IP Address', 'Request Count'])
    writer.writerows(sorted_ip_requests)
    
    # Write most accessed endpoint
    writer.writerow([])
    writer.writerow(['Most Accessed Endpoint', 'Access Count'])
    writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
    
    # Write suspicious activity
    writer.writerow([])
    writer.writerow(['IP Address', 'Failed Login Count'])
    writer.writerows(suspicious_ips)

print(f"\nResults saved to {OUTPUT_FILE}.")
