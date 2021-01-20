import requests
import sys
import argparse
import json
import os
from pyzipper import AESZipFile

URL = "https://mb-api.abuse.ch/api/v1/"
LIMIT = 2
ZIP_PASSWD = b"infected"
sample_dir = "samples/"
extracted_dir = "extracted/"

def load_conf(config_file):
    config = dict()
    try:
        with open(config_file, "r") as conf:
            config = json.loads(conf.read())
        return config
    except:
        raise("Error opening config file %s" % config_file)

def extract_field(results, field="sha256_hash"):
    json_results = json.loads(results)
    try:
        return [item[field] for item in json_results["data"]]
    except:
        raise

def query_tag(tag, api_key):
    data = {
        "query": "get_taginfo",
        "tag": tag,
        "limit": LIMIT
    }

    response = requests.post(URL, data=data, timeout=15, headers=api_key)
    return response.content.decode("utf-8", "ignore")

def download_sample(sha256_hash, api_key):
    data = {
        "query": "get_file",
        "sha256_hash": sha256_hash
    }

    response = requests.post(URL, data=data, timeout=15, headers=api_key, allow_redirects=True)

    with open(sample_dir+sha256_hash+'.zip', 'wb') as zip:
        zip.write(response.content)

def unzip_files(sample_dir):
    for zip_file in os.listdir(sample_dir):
        with AESZipFile(sample_dir+zip_file) as zf:
                zf.pwd = ZIP_PASSWD
                my_secrets = zf.extractall(extracted_dir)  
                print("Extracted %s to %s" % (zip_file, extracted_dir))

def main():
    parser = argparse.ArgumentParser(description='Scripts for Malware Bazaar')
    parser.add_argument('-t', '--tag', help='Tag of malware to be dowloaded', required=True)
    args = parser.parse_args()

    conf = load_conf("config.json")
    api_key = { "API_KEY": conf["api_key"]}

    results = query_tag(args.tag, api_key)

    sha256_list = extract_field(results)

    for sha256 in sha256_list:
        download_sample(sha256, api_key)
        print("Downloaded %s" % sha256)

    unzip_files(sample_dir)
    

if __name__ == "__main__":
    main()