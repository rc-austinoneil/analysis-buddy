import socbuddy
import requests
from config import fontcolors, loadconfig
from modules import osint
from emailrep import EmailRep


bcolors = fontcolors.bcolors()
configvars = loadconfig.load_buddy_config()
linksFoundList = []
linksDict = {}


# Menu
def menu():
    socbuddy.title_bar("Phishing")
    socbuddy.menu_item(0, "Return to main menu", "goback")
    socbuddy.menu_item(1, "Check email against EmailRep.io", "tool")
    socbuddy.menu_item(2, "PhishStats URL", "tool")
    socbuddy.menu_item(3, "PhishStats IP", "tool")
    socbuddy.menu_item(4, "Report phishing email to EmailRep.io", "tool")
    menu_switch(input(bcolors.INPUT + " ~> " + bcolors.ENDC))


def menu_switch(choice):
    if choice == "1":
        analyze_email()
    if choice == "2":
        phish_stats_url()
    if choice == "3":
        phish_stats_ip()
    if choice == "4":
        report_phishing()
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
                    bcolors.INPUT
                    + 'Input comma delaminated tags. For example "bec,maldoc": '
                    + bcolors.ENDC
                )
            ).strip()
            description = str(
                input(
                    bcolors.INPUT
                    + 'Enter a reason why youre reporting this email. Example "Phishing email targeting CEO": '
                    + bcolors.ENDC
                )
            ).strip()

            if "," in tags:
                tags = tags.split(",")

            yn = input(
                bcolors.ORANGE
                + f"You're about to report the email: {email}\nTags: {tags}\nDescription: {description}\n\nAre you sure you want to do this?? (Y/N): "
                + bcolors.ENDC
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
                print(bcolors.OKGREEN + f"IP    : {str(x['ip'])}" + bcolors.ENDC)
                print(bcolors.OKGREEN + f"Title : {str(x['title'])}" + bcolors.ENDC)
                print(bcolors.OKGREEN + f"URL   : {str(x['url'])}" + bcolors.ENDC)
                print(bcolors.OKGREEN + f"Score : {str(x['score'])}" + bcolors.ENDC)
                print(bcolors.OKGREEN + f"Tags  : {str(x['tags'])}" + bcolors.ENDC)
                print("")
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
                    print(bcolors.OKGREEN + f"IP    : {str(x['ip'])}" + bcolors.ENDC)
                    print(bcolors.OKGREEN + f"Title : {str(x['title'])}" + bcolors.ENDC)
                    print(bcolors.OKGREEN + f"URL   : {str(x['url'])}" + bcolors.ENDC)
                    print(bcolors.OKGREEN + f"Score : {str(x['score'])}" + bcolors.ENDC)
                    print(bcolors.OKGREEN + f"Tags  : {str(x['tags'])}" + bcolors.ENDC)
                    print("")
            if c == 0:
                socbuddy.error_message("No results found")
        else:
            socbuddy.error_message(f"Error {response.status_code}: {response.text}")
        osint.osint_enrichment(ip, True)
    except Exception:
        socbuddy.error_message("Failed to query PhishStats API")
    phish_stats_ip() if socbuddy.ask_to_run_again() else menu()
