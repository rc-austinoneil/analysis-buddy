import socbuddy
import requests
import json
import time
import webbrowser
from config import fontcolors, loadconfig
from modules import osint
from emailrep import EmailRep


bcolors = fontcolors.bcolors()
configvars = loadconfig.load_buddy_config()
linksFoundList = []
linksDict = {}


# Menu
def menu():
    socbuddy.title_bar("Phishing & URLs")
    socbuddy.menu_item(0, "Return to main menu", "goback")
    socbuddy.menu_item(1, "URLScan.io", "tool")
    socbuddy.menu_item(2, "Useragent Lookup", "tool")
    socbuddy.menu_item(3, "Check email against EmailRep.io", "tool")
    socbuddy.menu_item(4, "Report phishing email to EmailRep.io", "tool")
    socbuddy.menu_item(5, "PhishStats URL", "tool")
    socbuddy.menu_item(6, "PhishStats IP", "tool")
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
    else:
        socbuddy.main_menu()


# Tools
def analyze_email():
    try:
        if loadconfig.check_buddy_config("EMAILREP_API_KEY"):
            socbuddy.title_bar("EmailRep.io Analyze Email")
            email = socbuddy.ask_for_user_input("Enter email address")
            socbuddy.info_message(osint.count_occurrences(email), True)
            emailrep = EmailRep(f"{configvars.data['EMAILREP_API_KEY']}")
            socbuddy.print_json(emailrep.query(email))
            osint.osint_enrichment(email, True)
    except Exception as e:
        socbuddy.error_message("Error querying EmailRep.io", str(e))
    analyze_email() if socbuddy.ask_to_run_again() else menu()


def report_phishing():
    try:
        if loadconfig.check_buddy_config("EMAILREP_API_KEY"):
            socbuddy.title_bar("EmailRep.io Report Email")
            email = socbuddy.ask_for_user_input("Enter email address")
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
                socbuddy.print_json(data)
            else:
                socbuddy.error_message("You decided to not send the report.")
    except Exception as e:
        socbuddy.error_message("Error querying EmailRep.io", str(e))
    report_phishing() if socbuddy.ask_to_run_again() else menu()


def phish_stats_url():
    try:
        socbuddy.title_bar("PhishStats URL")
        url = socbuddy.ask_for_user_input()
        socbuddy.info_message(osint.count_occurrences(url), True)
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
                socbuddy.print_json(output)
        else:
            socbuddy.error_message(f"Error {response.status_code}: {response.text}")
        osint.osint_enrichment(url, True)
    except Exception:
        socbuddy.error_message("Failed to query PhishStats API")
    phish_stats_url() if socbuddy.ask_to_run_again() else menu()


def phish_stats_ip():
    try:
        socbuddy.title_bar("PhishStats IPs")
        ip = socbuddy.ask_for_user_input()
        socbuddy.info_message(osint.count_occurrences(ip), True)
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
                    socbuddy.print_json(output)
            if c == 0:
                socbuddy.error_message("No results found")
        else:
            socbuddy.error_message(f"Error {response.status_code}: {response.text}")
        osint.osint_enrichment(ip, True)
    except Exception:
        socbuddy.error_message("Failed to query PhishStats API")
    phish_stats_ip() if socbuddy.ask_to_run_again() else menu()


def urlscanio():
    try:
        if loadconfig.check_buddy_config("URLSCAN_IO_KEY"):
            socbuddy.title_bar("Urlscan.io")
            url_to_scan = socbuddy.ask_for_user_input("Enter URL")
            type_prompt = str(
                input(
                    f"{bcolors.INPUT}\nSet scan visibility to Public? \nType '1' for Public or '2' for Private: {bcolors.ENDC}"
                )
            )

            visibility = "public" if type_prompt == "1" else "private"
            data = {"url": url_to_scan, "visibility": visibility}
            headers = {
                "API-Key": str(configvars.data["URLSCAN_IO_KEY"]),
                "Content-Type": "application/json",
            }

            response = requests.post(
                "https://urlscan.io/api/v1/scan/",
                headers=headers,
                data=json.dumps(data),
            )

            if response.status_code == 200:
                socbuddy.info_message(
                    f"Now {visibility} scanning {url_to_scan}\nCheck back in 1 minute.",
                    True,
                )

                uuid_variable = str(response.json()["uuid"])
                time.sleep(60)
                scan_results = requests.get(
                    f"https://urlscan.io/api/v1/result/{uuid_variable}/"
                ).json()

                output = {
                    "Task URL": scan_results.get("task").get("url"),
                    "Report URL": scan_results.get("task").get("reportURL"),
                    "Screenshot": scan_results.get("task").get("screenshotURL"),
                    "Overall Verdict": scan_results.get("verdicts")
                    .get("overall")
                    .get("score"),
                    "Malicious": scan_results.get("verdicts")
                    .get("overall")
                    .get("malicious"),
                    "IPs": scan_results.get("lists").get("ips"),
                    "Countries": scan_results.get("lists").get("countries"),
                    "Domains": scan_results.get("lists").get("domains"),
                    "Servers": scan_results.get("lists").get("servers"),
                }
                socbuddy.print_json(output)
            else:
                socbuddy.error_message("URLScan run failed", response["message"])
    except Exception as e:
        socbuddy.error_message("Failed to query URLScan.io", str(e))
    urlscanio() if socbuddy.ask_to_run_again() else menu()


def useragent_lookup():
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
        socbuddy.title_bar("Urlscan.io")
        useragent = socbuddy.ask_for_user_input("Enter useragent")
        url = f"https://user-agents.net/string/{user_agent_fix(useragent)}"
        socbuddy.print_json({"Useragent Lookup": url})
        webbrowser.open(url, new=2)
    except Exception:
        socbuddy.error_message("Failed to query useragent.net")
    urlscanio() if socbuddy.ask_to_run_again() else menu()
