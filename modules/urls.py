import socbuddy
import time
import requests
from config import fontcolors, loadconfig

bcolors = fontcolors.bcolors()
configvars = loadconfig.load_buddy_config()


# Menu
def menu():
    socbuddy.title_bar("URL Tools")
    socbuddy.menu_item(0, "Return to main menu", "goback")
    socbuddy.menu_item(1, "URLScan.io", "tool")
    menu_switch(input(bcolors.INPUT + " ~> " + bcolors.ENDC))


def menu_switch(choice):
    if choice == "1":
        urlscanio()
    if choice == "0":
        socbuddy.main_menu()
    else:
        menu()


# Tools
def urlscanio():
    try:
        if loadconfig.check_buddy_config("URLSCAN_IO_KEY"):
            socbuddy.title_bar("Urlscan.io")
            url_to_scan = socbuddy.ask_for_user_input("Enter URL")
            type_prompt = str(
                input(
                    bcolors.INPUT
                    + '\nSet scan visibility to Public? \nType "1" for Public or "2" for Private: '
                    + bcolors.ENDC
                )
            )
            if type_prompt == "1":
                scan_type = "public"
            else:
                scan_type = "private"

            headers = {
                "Content-Type": "application/json",
                "API-Key": configvars.data["URLSCAN_IO_KEY"],
            }
            response = requests.post(
                "https://urlscan.io/api/v1/scan/",
                headers=headers,
                data='{"url": "%s", "%s": "on"}' % (url_to_scan, scan_type),
            ).json()

            if "successful" in response["message"]:
                socbuddy.info_message(
                    f"Now scanning {url_to_scan}. Check back in around 1 minute."
                )

                uuid_variable = str(response["uuid"])
                time.sleep(60)
                scan_results = requests.get(
                    f"https://urlscan.io/api/v1/result/{uuid_variable}/"
                ).json()

                task_url = scan_results["task"]["url"]
                verdicts_overall_score = scan_results["verdicts"]["overall"]["score"]
                verdicts_overall_malicious = scan_results["verdicts"]["overall"][
                    "malicious"
                ]
                task_report_URL = scan_results["task"]["reportURL"]

                print("urlscan.io Report:")
                print("URL: " + task_url)
                print("Overall Verdict: " + str(verdicts_overall_score))
                print("Malicious: " + str(verdicts_overall_malicious))
                print(
                    "urlscan.io: " + str(scan_results["verdicts"]["urlscan"]["score"])
                )
                if scan_results["verdicts"]["urlscan"]["malicious"]:
                    print(
                        "Malicious: "
                        + str(scan_results["verdicts"]["urlscan"]["malicious"])
                    )  # True
                if scan_results["verdicts"]["urlscan"]["categories"]:
                    print("Categories: ")
                for line in scan_results["verdicts"]["urlscan"]["categories"]:
                    print("\t" + str(line))  # phishing
                for line in scan_results["verdicts"]["engines"]["verdicts"]:
                    print(
                        str(line["engine"]) + " score: " + str(line["score"])
                    )  # googlesafebrowsing
                    print("Categories: ")
                    for item in line["categories"]:
                        print("\t" + item)  # social_engineering
                print("See full report for more details: " + str(task_report_URL))
            else:
                socbuddy.error_message("URLScan run failed", response["message"])
    except Exception as e:
        socbuddy.error_message("Failed to query URLScan.io", str(e))
    urlscanio() if socbuddy.ask_to_run_again() else menu()
