import analysisbuddy
import requests
import json
import time
import webbrowser
from config import fontcolors, loadconfig
from modules import osint
from emailrep import EmailRep
from bs4 import BeautifulSoup

bcolors = fontcolors.bcolors()
configvars = loadconfig.load_buddy_config()


# Menu
def menu():
    analysisbuddy.title_bar("Phishing & URL Tools")
    analysisbuddy.menu_item(0, "Return to main menu", "goback")
    analysisbuddy.menu_item(1, "URLScan.io", "tool")
    analysisbuddy.menu_item(2, "Useragent Lookup", "tool")
    analysisbuddy.menu_item(3, "Check email against EmailRep.io", "tool")
    analysisbuddy.menu_item(4, "Report phishing email to EmailRep.io", "tool")
    analysisbuddy.menu_item(5, "PhishStats URL", "tool")
    analysisbuddy.menu_item(6, "PhishStats IP", "tool")
    analysisbuddy.menu_item(7, "Tweetfeed IOC Lookup", "tool")
    analysisbuddy.menu_item(8, "Chrome Extension Lookup", "tool")
    menu_switch(input(f"{bcolors.INPUT} ~> {bcolors.ENDC}"))


def menu_switch(choice):
    if choice == "1":
        urlscanio()
    if choice == "2":
        useragent_lookup()
    if choice == "3":
        analyze_email()
    if choice == "4":
        report_phishing()
    if choice == "5":
        phish_stats_url()
    if choice == "6":
        phish_stats_ip()
    if choice == "7":
        osint.tweetfeed_live()
        osint.tweetfeed_live() if analysisbuddy.ask_to_run_again() else menu()
    if choice == "8":
        chrome_extension_lookup()
    else:
        analysisbuddy.main_menu()


# Tools
def analyze_email():
    """
    This function will query EmailRep.io for information about an email address
    """
    try:
        if loadconfig.check_buddy_config("EMAILREP_API_KEY"):
            analysisbuddy.title_bar("EmailRep.io Analyze Email")
            email = analysisbuddy.ask_for_user_input("Enter email address")
            analysisbuddy.info_message(osint.update_historical_osint_data(email), True)
            emailrep = EmailRep(f"{configvars.data['EMAILREP_API_KEY']}")
            analysisbuddy.print_json(emailrep.query(email))
            osint.run_osint_no_menu(email)
    except Exception as e:
        analysisbuddy.error_message("Error querying EmailRep.io", str(e))
    analyze_email() if analysisbuddy.ask_to_run_again() else menu()


def report_phishing():
    """
    This function will report an email address to EmailRep.io
    """
    try:
        if loadconfig.check_buddy_config("EMAILREP_API_KEY"):
            analysisbuddy.title_bar("EmailRep.io Report Email")
            email = analysisbuddy.ask_for_user_input("Enter email address")
            tags = str(
                input(
                    f"{bcolors.INPUT}Input comma delaminated tags. For example 'bec,maldoc': {bcolors.ENDC}"
                )
            ).strip()
            description = str(
                input(
                    f"{bcolors.INPUT}Enter a reason why youre reporting this email. Example 'Phishing targeting CEO': {bcolors.ENDC}"
                )
            ).strip()

            if "," in tags:
                tags = tags.split(",")

            yn = input(
                f"{bcolors.ORANGE}You're about to report the email: {email}\nTags: {tags}\nDescription {description}\n\nAre you sure you want to do this?? (Y/N): {bcolors.ENDC}"
            )

            if yn.upper() == "Y":
                emailrep = EmailRep(f"{configvars.data['EMAILREP_API_KEY']}")
                data = emailrep.report(email, tags, description)
                analysisbuddy.print_json(data)
            else:
                analysisbuddy.error_message("You decided to not send the report.")
    except Exception as e:
        analysisbuddy.error_message("Error querying EmailRep.io", str(e))
    report_phishing() if analysisbuddy.ask_to_run_again() else menu()


def phish_stats_url():
    """
    This function will query PhishStats.info for information about a URL
    """
    try:
        analysisbuddy.title_bar("PhishStats URL")
        url = analysisbuddy.ask_for_user_input()
        analysisbuddy.info_message(osint.update_historical_osint_data(url), True)
        endpoint = "https://phishstats.info:2096/api/phishing"
        params = {"_size": "100", "url": f"like,~{url}~"}
        response = requests.get(endpoint, params=params)
        if response.status_code == 200:
            print("")
            for x in response.json():
                output = {
                    "IP": str(x["ip"]),
                    "Title": str(x["title"]),
                    "URL": str(x["url"]),
                    "Score": str(x["score"]),
                    "Tags": str(x["tags"]),
                }
                analysisbuddy.print_json(output)
        else:
            analysisbuddy.error_message(
                f"Error {response.status_code}: {response.text}"
            )
        osint.run_osint_no_menu(url)
    except Exception as e:
        analysisbuddy.error_message("Failed to query PhishStats API", str(e))
    phish_stats_url() if analysisbuddy.ask_to_run_again() else menu()


def phish_stats_ip():
    """
    This function will query PhishStats.info for information about an IP
    """
    try:
        analysisbuddy.title_bar("PhishStats IPs")
        ip = analysisbuddy.ask_for_user_input()
        analysisbuddy.info_message(osint.update_historical_osint_data(ip), True)
        endpoint = "https://phishstats.info:2096/api/phishing"
        params = {"_size": "100", "url": f"eq,{ip}"}
        response = requests.get(endpoint, params=params)
        if response.status_code == 200:
            print("")
            c = 0
            for x in response.json():
                if str(x["ip"]) == ip:
                    c += 1
                    output = {
                        "IP": str(x["ip"]),
                        "Title": str(x["title"]),
                        "URL": str(x["url"]),
                        "Score": str(x["score"]),
                        "Tags": str(x["tags"]),
                    }
                    analysisbuddy.print_json(output)
            if c == 0:
                analysisbuddy.error_message("No results found")
        else:
            analysisbuddy.error_message(
                f"Error {response.status_code}: {response.text}"
            )
        osint.run_osint_no_menu(ip)
    except Exception as e:
        analysisbuddy.error_message("Failed to query PhishStats API", str(e))
    phish_stats_ip() if analysisbuddy.ask_to_run_again() else menu()


def urlscanio():
    """
    This function will query URLScan.io for information about a URL or domain
    """
    try:
        if loadconfig.check_buddy_config("URLSCAN_IO_KEY"):
            analysisbuddy.title_bar("Urlscan.io")
            url_to_scan = analysisbuddy.ask_for_user_input("Enter URL")
            analysisbuddy.info_message(
                osint.update_historical_osint_data(url_to_scan), True
            )
            type_prompt = str(
                input(
                    f"{bcolors.INPUT}\nSet scan visibility to Public? \nType '1' for Public or '2' for Private: {bcolors.ENDC}"
                )
            )

            visibility = "public" if type_prompt == "1" else "private"

            response = requests.post(
                "https://urlscan.io/api/v1/scan/",
                headers={
                    "API-Key": str(configvars.data["URLSCAN_IO_KEY"]),
                    "Content-Type": "application/json",
                },
                data=json.dumps({"url": url_to_scan, "visibility": visibility}),
            )

            if response.status_code == 200:
                analysisbuddy.info_message(
                    f"Now {visibility} scanning {url_to_scan}\nCheck back in 1 minute.",
                    True,
                )

                uuid_variable = str(response.json()["uuid"])
                time.sleep(60)
                scan_results = requests.get(
                    f"https://urlscan.io/api/v1/result/{uuid_variable}/"
                ).json()

                # fmt: off
                output = {
                    "Task URL": scan_results.get("task", {}).get("url"),
                    "Report URL": scan_results.get("task", {}).get("reportURL"),
                    "Screenshot": scan_results.get("task", {}).get("screenshotURL"),
                    "Overall Verdict": scan_results.get("verdicts", {}).get("overall", {}).get("score"),
                    "Malicious": scan_results.get("verdicts", {}, {}).get("overall", {}).get("malicious"),
                    "IPs": scan_results.get("lists", {}).get("ips"),
                    "Countries": scan_results.get("lists", {}).get("countries"),
                    "Domains": scan_results.get("lists", {}).get("domains"),
                    "Servers": scan_results.get("lists", {}).get("servers"),
                }
                # fmt: on
                analysisbuddy.print_json(output)
            else:
                analysisbuddy.error_message("URLScan run failed", response["message"])
    except Exception as e:
        analysisbuddy.error_message("Failed to query URLScan.io", str(e))
    urlscanio() if analysisbuddy.ask_to_run_again() else menu()


def useragent_lookup():
    """
    This function will open a browser to useragent.net to lookup a useragent
    """

    def user_agent_fix(agent):
        # replaces most characters with - so that the site can parse it
        fix = agent.lower()
        fix = fix.replace("/", "-")
        fix = fix.replace(".", "-")
        fix = fix.replace(";", "-")
        fix = fix.replace(" ", "-")
        fix = fix.replace("(", "-")
        fix = fix.replace(")", "-")
        fix = fix.replace("_", "-")
        fix = fix.replace(",", "-")
        fix = fix.replace("--", "-")
        return fix

    try:
        analysisbuddy.title_bar("Urlscan.io")
        useragent = analysisbuddy.ask_for_user_input("Enter useragent")
        url = f"https://user-agents.net/string/{user_agent_fix(useragent)}"
        analysisbuddy.print_json({"Useragent Lookup": url})
        webbrowser.open(url, new=2)
    except Exception as e:
        analysisbuddy.error_message("Failed to query useragent.net", str(e))
    urlscanio() if analysisbuddy.ask_to_run_again() else menu()


def chrome_extension_lookup():
    """
    This function will lookup a Chrome Extension ID in the Chrome Web Store
    """
    try:
        analysisbuddy.title_bar("Chrome Extension Details")
        extension_id = analysisbuddy.ask_for_user_input("Enter the Chrome Extension ID")
        url = f"https://chrome.google.com/webstore/detail/{extension_id}"
        response = requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")

        output = {
            "Extension name": soup.find("h1", {"class": "e-f-w"}).text.strip(),
            "Version": soup.find("span", {"class": "C-b-p-D-Xe h-C-b-p-D-md"}).text,
            "Size": soup.find("span", {"class": "C-b-p-D-Xe h-C-b-p-D-za"}).text,
            "Updated": soup.find("span", {"class": "C-b-p-D-Xe h-C-b-p-D-xh-hh"}).text,
            "Number of users": soup.find("span", {"class": "e-f-ih"}).text,
            "Developer": soup.find("a", {"class": "e-f-y"}).text,
            "url": url,
        }
        analysisbuddy.print_json(output)
    except AttributeError as e:
        analysisbuddy.error_message("Failed to parse HTML", str(e))
    chrome_extension_lookup() if analysisbuddy.ask_to_run_again() else menu()
