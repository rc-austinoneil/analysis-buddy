import socbuddy
import time
import requests
import json
from config import fontcolors, loadconfig

bcolors = fontcolors.bcolors()
configvars = loadconfig.load_buddy_config()


# Menu
def menu():
    socbuddy.title_bar("URL Tools")
    socbuddy.menu_item(0, "Return to main menu", "goback")
    socbuddy.menu_item(1, "URLScan.io", "tool")
    menu_switch(input(f"{bcolors.INPUT} ~> {bcolors.ENDC}"))


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
                    f"Now {visibility} scanning {url_to_scan}\nCheck back in 1 minute."
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
