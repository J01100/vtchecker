import argparse
import hashlib
import csv
import time
import requests
from tqdm import tqdm

API_KEYS = ['x', 'x', 'x']
API_URL = 'https://www.virustotal.com/api/v3/files/{}'
DELAY_BETWEEN_REQUESTS = 6 # you can change me to 6 when you have 3 api keys

def get_sha256_from_string(hash_str):
    try:
        # Check if the string is already a valid hex digest (SHA256 format)
        int(hash_str, 16)  # Try converting to integer (base 16)
        return hash_str  # If no exception, it's likely a valid SHA256 hash
    except ValueError:
        # If conversion fails, assume it's MD5 or another format
        return hashlib.sha256(hash_str.encode()).hexdigest()

def get_virus_total_report(file_id, api_key):
    headers = {'x-apikey': api_key, 'accept': 'application/json'}
    url = API_URL.format(file_id)
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

def main(input_file, output_file):
    with open(input_file, 'r') as infile, open(output_file, 'w', newline='') as outfile:
        file_ids = [get_sha256_from_string(line.strip()) for line in infile.readlines()]
        writer = csv.writer(outfile)
        writer.writerow(['MD5', 'SHA1', 'SHA256', 'Hits', 'MeaningfulName', 'Filenames', 'Sandbox Results'])

        num_keys = len(API_KEYS)

        for index, file_id in enumerate(tqdm(file_ids, desc="Processing hash/es")):
            api_key = API_KEYS[index % num_keys]  # Rotate API keys using modulo
            result = get_virus_total_report(file_id, api_key)
            if result and 'data' in result and 'attributes' in result['data']:
                attributes = result['data']['attributes']
                last_analysis_results = attributes.get('last_analysis_results', {})

                filename_str = ' | '.join([name for name in attributes.get('names', 'N/A')])
                md5 = attributes.get('md5', 'N/A')
                sha1 = attributes.get('sha1', 'N/A')
                sha256 = attributes.get('sha256', 'N/A')
                meaningful_name = attributes.get('meaningful_name', 'N/A')
                hits = attributes.get('last_analysis_stats', {}).get('malicious', 'N/A')
                analysis_results_str = ' | '.join([
                        analysis['result']
                        for vendor, analysis in last_analysis_results.items()
                        if analysis['result'] is not None
                ])
                writer.writerow([md5, sha1, sha256, hits, meaningful_name, filename_str, analysis_results_str])
            else:
                continue

            time.sleep(DELAY_BETWEEN_REQUESTS)  # Adjust delay to respect rate limits

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process hash values and retrieve VirusTotal reports.')
    parser.add_argument('-in', '--input', required=True, help='Path to the input file containing hash values.')
    parser.add_argument('-out', '--output', required=True, help='Path to the output CSV file.')

    args = parser.parse_args()
    main(args.input, args.output)
