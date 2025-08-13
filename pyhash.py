#!/usr/bin/env python3

import re
import urllib3
import os
import requests
import argparse
import concurrent.futures
import websocket

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
parser = argparse.ArgumentParser(description="PyHash - Automatic hash identifier and cracker")
parser.add_argument('-s', help='Single hash to crack', dest='hash')
parser.add_argument('-f', help='File containing hashes', dest='file')
parser.add_argument('-d', help='Directory containing hashes', dest='dir')
parser.add_argument('-t', help='Number of threads', dest='threads', type=int)
args = parser.parse_args()

# Flags
found = 0
hashv = ''

# Colors
end = '\033[0m'
red = '\033[91m'
green = '\033[92m'
white = '\033[97m'
yellow = '\033[93m'
info = '\033[93m[!]\033[0m'
bad = '\033[91m[-]\033[0m'
good = '\033[92m[+]\033[0m'

cwd = os.getcwd()
directory = args.dir
file = args.file
thread_count = args.threads or 4

if directory and directory.endswith('/'):
    directory = directory[:-1]

# API functions
def alpha(hashvalue, hashtype):
    cookies = {'ASP.NET_SessionId': 'be2jpjuviqbaa2mmq1w4h5ci'}
    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    data = {
        '__EVENTTARGET': 'Button1',
        '__VIEWSTATE': '6fEUcEEj0b0eN1Obqeu4TSsOBdS0APqz...',
        'ctl00$ContentPlaceHolder1$TextBoxInput': hashvalue,
        'ctl00$ContentPlaceHolder1$InputHashType': hashtype,
        'ctl00$ContentPlaceHolder1$Button1': 'decrypt',
    }
    response = requests.post('https://www.cmd5.org/', cookies=cookies, headers=headers, data=data)
    match = re.search(r'<span id="LabelAnswer"[^>]+?>(.+)</span>', response.text)
    return match.group(1) if match else False

def send_message(ws, message):
    global found, hashv
    pattern = r'"value\\":\\([^,]+)'
    ws.send(message)
    response = ws.recv()
    ws.recv()  # skip second recv
    match1 = re.search(pattern, response)
    if match1:
        x = match1.end() - 2
        found = 1
        hashv = response[148:x]
        return hashv

def beta(hashvalue, hashtype):
    ws = websocket.create_connection("wss://md5hashing.net/sockjs/697/etstxji0/websocket")
    connect_message = r'["{\"msg\":\"connect\",\"version\":\"1\",\"support\":[\"1\",\"pre2\",\"pre1\"]}"]'
    send_message(ws, connect_message)
    method_message = r'["{\"msg\":\"method\",\"method\":\"hash.get\",\"params\":[\"HASH_TYPE\",\"HASH_VALUE\"],\"id\":\"1\"}"]'
    method_message = method_message.replace("HASH_TYPE", hashtype).replace("HASH_VALUE", hashvalue)
    send_message(ws, method_message)
    sub_message = r'["{\"msg\":\"sub\",\"id\":\"AZnxL9tsZpE6XMTDB\",\"name\":\"meteor_autoupdate_clientVersions\",\"params\":[]}"]'
    send_message(ws, sub_message)
    return hashv if found else False

def gamma(hashvalue, hashtype):
    response = requests.get('https://www.nitrxgen.net/md5db/' + hashvalue, verify=False).text
    return response if response else False

def theta(hashvalue, hashtype):
    url = f'https://md5decrypt.net/Api/api.php?hash={hashvalue}&hash_type={hashtype}&email=noyile6983@lofiey.com&code=fa9e66f3c9e245d6'
    response = requests.get(url).text
    return response if len(response) != 0 else False

print(f"""{white}_  _ ____ _ _   _    _  _ ____ ____ 
                |__/ \_/  |__| |__| [__  |__|    
                |     |   |  | |  | ___] |  |     {red}PyHash v1{end}\n""")

md5 = [alpha, beta, gamma, theta]
sha1 = [alpha, beta, theta]
sha256 = [alpha, beta, theta]
sha384 = [alpha, beta, theta]
sha512 = [alpha, beta, theta]

def crack(hashvalue):
    if len(hashvalue) == 32:
        print(f'{info} Hash function: MD5')
        for api in md5:
            r = api(hashvalue, 'md5')
            if r: return r
    elif len(hashvalue) == 40:
        print(f'{info} Hash function: SHA1')
        for api in sha1:
            r = api(hashvalue, 'sha1')
            if r: return r
    elif len(hashvalue) == 64:
        print(f'{info} Hash function: SHA-256')
        for api in sha256:
            r = api(hashvalue, 'sha256')
            if r: return r
    elif len(hashvalue) == 96:
        print(f'{info} Hash function: SHA-384')
        for api in sha384:
            r = api(hashvalue, 'sha384')
            if r: return r
    elif len(hashvalue) == 128:
        print(f'{info} Hash function: SHA-512')
        for api in sha512:
            r = api(hashvalue, 'sha512')
            if r: return r
    else:
        print(f'{bad} This hash type is not supported.')
        return False

result = {}

def threaded(hashvalue):
    resp = crack(hashvalue)
    if resp:
        print(f'{hashvalue} : {resp}')
        result[hashvalue] = resp

def grepper(directory):
    os.system(f'''grep -Pr "[a-f0-9]{{128}}|[a-f0-9]{{96}}|[a-f0-9]{{64}}|[a-f0-9]{{40}}|[a-f0-9]{{32}}" {directory} --exclude=*.{{png,jpg,jpeg,mp3,mp4,zip,gz}} |
        grep -Po "[a-f0-9]{{128}}|[a-f0-9]{{96}}|[a-f0-9]{{64}}|[a-f0-9]{{40}}|[a-f0-9]{{32}}" >> {cwd}/{directory.split('/')[-1]}.txt''')
    print(f'{info} Results saved in {directory.split("/")[-1]}.txt')

def miner(file):
    found = set()
    with open(file, 'r') as f:
        for line in f:
            matches = re.findall(r'[a-f0-9]{128}|[a-f0-9]{96}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32}', line)
            found.update(matches)
    print(f'{info} Hashes found: {len(found)}')
    threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=thread_count)
    futures = (threadpool.submit(threaded, hv) for hv in found)
    for i, _ in enumerate(concurrent.futures.as_completed(futures)):
        if i + 1 == len(found) or (i + 1) % thread_count == 0:
            print(f'{info} Progress: {i+1}/{len(found)}', end='\r')

def single(args):
    result = crack(args.hash)
    if result:
        print(f'{good} {result}')
    else:
        print(f'{bad} Hash was not found in any database.')

if directory:
    try:
        grepper(directory)
    except KeyboardInterrupt:
        pass
elif file:
    try:
        miner(file)
    except KeyboardInterrupt:
        pass
    with open(f'cracked-{file.split("/")[-1]}', 'w+') as f:
        for hv, cracked in result.items():
            f.write(f'{hv}:{cracked}\n')
    print(f'{info} Results saved in cracked-{file.split("/")[-1]}')
elif args.hash:
    single(args)
