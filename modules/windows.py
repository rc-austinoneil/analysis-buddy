import socbuddy
import requests
import json
from config import fontcolors, loadconfig

bcolors = fontcolors.bcolors()
configvars = loadconfig.load_buddy_config()


# Menu
def menu():
    socbuddy.title_bar("Windows Tools")
    socbuddy.menu_item(0, "Return to main menu", "goback")
    socbuddy.menu_item(1, "EventID Lookup", "tool")
    socbuddy.menu_item(2, "LOLBin Lookup", "tool")
    socbuddy.menu_item(3, "LOLdriver Lookup", "tool")
    socbuddy.menu_item(4, "CLISD Lookup", "tool")
    socbuddy.menu_item(5, "EchoTrail Lookup - WIP", "tool")
    menu_switch(str(input(bcolors.INPUT + " ~> " + bcolors.ENDC)))


def menu_switch(choice):
    if choice == "1":
        event_id_lookup()
    if choice == "2":
        lolbin_lookup()
    if choice == "3":
        loldriver_lookup()
    if choice == "4":
        clsid_lookup()
    if choice == "5":
        echotrail_lookup()
    if choice == "0":
        socbuddy.main_menu()
    else:
        menu()


# Tools
def clsid_lookup():
    try:
        socbuddy.title_bar("CLSID Lookup")
        target = socbuddy.ask_for_user_input("Enter a CLSID string to lookup")
        req = requests.get(
            "https://raw.githubusercontent.com/jkerai1/CLSID-Lookup/main/List.md"
        )
        if req.status_code == 200:
            lines = req.text.splitlines()
            for line in lines:
                if target in line:
                    line = line.split(" ")
                    socbuddy.print_json(
                        {"CLSID": line[0], "Description": " ".join(line[1:])}
                    )
        else:
            raise Exception
    except Exception:
        socbuddy.error_message(f"Failed to run the CLSID lookup.")
    clsid_lookup() if socbuddy.ask_to_run_again() else menu()


def event_id_lookup():
    try:
        socbuddy.title_bar("Windows Event ID Lookup")
        socbuddy.download_file_from_internet(
            url="https://raw.githubusercontent.com/qbrusa/Windows-Security-Event-ID-Helper/main/AdvancedSecurityEventIDs.json",
            file_path="./config/json_lookups/windows_lookups/windowseventids.json",
        )
        socbuddy.json_lookup(
            "./config/json_lookups/windows_lookups/windowseventids.json", "UTF-8"
        )
    except Exception:
        socbuddy.error_message("Failed to run the event id lookup")
    event_id_lookup() if socbuddy.ask_to_run_again() else menu()


def lolbin_lookup():
    try:
        socbuddy.title_bar("LOLBin Lookup")
        socbuddy.download_file_from_internet(
            url="https://lolbas-project.github.io/api/lolbas.json",
            file_path="./config/json_lookups/windows_lookups/lolbins.json",
        )
        socbuddy.json_lookup(
            "./config/json_lookups/windows_lookups/lolbins.json", "UTF-8"
        )
    except Exception:
        socbuddy.error_message("Failed to run the LOLBin lookup")
    lolbin_lookup() if socbuddy.ask_to_run_again() else menu()


def loldriver_lookup():
    try:
        socbuddy.title_bar("Loldriver Lookup")
        socbuddy.download_file_from_internet(
            url="https://www.loldrivers.io/api/drivers.json",
            file_path="./config/json_lookups/windows_lookups/loldrivers.json",
        )
        socbuddy.json_lookup(
            "./config/json_lookups/windows_lookups/loldrivers.json", "UTF-8"
        )
    except Exception:
        socbuddy.error_message("Failed to run the Loldriver lookup")
    loldriver_lookup() if socbuddy.ask_to_run_again() else menu()


def echotrail_lookup():
    try:
        if loadconfig.check_buddy_config("ECHOTRAIL_API_KEY"):
            socbuddy.title_bar("Echo Trail Windows Binary Lookup")
            search = socbuddy.ask_for_user_input("Enter a Windows Binary to lookup")

            url = f"https://api.echotrail.io/v1/insights/{search}"
            echotrail_session = requests.session()
            echotrail_session.verify = True
            echotrail_session.headers = {
                "X-Api-Key": str(configvars["ECHOTRAIL_API_KEY"]),
                "Content-Type": "application/json",
            }

            echotrail_api_response = echotrail_session.get(
                url, headers=echotrail_session.headers
            )

            if echotrail_api_response.status_code == 200:
                print(json.dumps(echotrail_api_response.json()))
            else:
                raise Exception
    except Exception as e:
        socbuddy.error_message("Failed to run the EchoTrail lookup", str(e))
    echotrail_lookup() if socbuddy.ask_to_run_again() else menu()
