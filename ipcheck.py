import requests
import csv
import time
from tqdm import tqdm

VIRUSTOTAL_API_KEYS = ["x", "x", "x"]
ABUSEIPDB_API_KEY = "x"
INPUT_FILE = "ips-input.txt"
OUTPUT_FILE = "ips-output.csv"
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
RATELIMIT_DELAY = 8


def get_virus_total_report(ip_address, api_key):
    headers = {"x-apikey": api_key, "accept": "application/json"}
    url = VIRUSTOTAL_API_URL.format(ip_address)
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return None


def get_abuseipdb_report(ip_address):
    querystring = {"ipAddress": ip_address, "maxAgeInDays": "90", "verbose": True}
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    response = requests.get(ABUSEIPDB_API_URL, headers=headers, params=querystring)
    if response.status_code == 200:
        return response.json()
    return None


def main():
    with open(INPUT_FILE, "r") as infile:
        ip_addresses = infile.read().splitlines()

    results = []
    num_keys = len(VIRUSTOTAL_API_KEYS)

    for index, ip_address in enumerate(
        tqdm(ip_addresses, desc="Processing IP addresses")
    ):
        # Rotate API keys using modulo
        api_key = VIRUSTOTAL_API_KEYS[index % num_keys]
        vt_result = get_virus_total_report(ip_address, api_key)
        abuseipdb_result = get_abuseipdb_report(ip_address)

        if vt_result and "data" in vt_result and "attributes" in vt_result["data"]:
            attributes = vt_result["data"]["attributes"]
            hits = attributes.get("last_analysis_stats", {}).get("malicious", "N/A")
            asn = attributes.get("asn", "N/A")
        else:
            hits = "N/A"
            asn = "N/A"

        if abuseipdb_result and "data" in abuseipdb_result:
            usage_type = abuseipdb_result["data"].get("usageType", "N/A")
            isp = abuseipdb_result["data"].get("isp", "N/A")
            country = abuseipdb_result["data"].get("countryName", "N/A")
            domain = abuseipdb_result["data"].get("domain", "N/A")
        else:
            usage_type = "N/A"
            isp = "N/A"
            country = "N/A"
            domain = "N/A"

        results.append([ip_address, asn, hits, usage_type, isp, country, domain])

        # Sleep to ensure we stay within rate limits
        time.sleep(RATELIMIT_DELAY)

    with open(OUTPUT_FILE, "w", newline="") as outfile:
        writer = csv.writer(outfile)
        writer.writerow(
            ["IP Address", "ASN", "Hits", "Usage Type", "ISP", "Country", "Domain"]
        )
        writer.writerows(results)


if __name__ == "__main__":
    main()
