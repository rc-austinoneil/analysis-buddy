import analysisbuddy
import requests
import json
from config import fontcolors, loadconfig

bcolors = fontcolors.bcolors()
configvars = loadconfig.load_buddy_config()


# Menu
def menu():
    analysisbuddy.title_bar("Windows Tools")
    analysisbuddy.menu_item(0, "Return to main menu", "goback")
    analysisbuddy.menu_item(1, "EventID Lookup", "tool")
    analysisbuddy.menu_item(2, "LOLBin Lookup", "tool")
    analysisbuddy.menu_item(3, "LOLdriver Lookup", "tool")
    analysisbuddy.menu_item(4, "CLISD Lookup", "tool")
    analysisbuddy.menu_item(5, "EchoTrail Lookup", "tool")
    menu_switch(str(input(f"{bcolors.INPUT} ~> {bcolors.ENDC}")))


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
        analysisbuddy.main_menu()
    else:
        menu()


# Tools
def clsid_lookup():
    """
    This function will lookup a CLSID string in the CLSID-Lookup github repo
    """
    try:
        analysisbuddy.title_bar("CLSID Lookup")
        target = analysisbuddy.ask_for_user_input("Enter a CLSID string to lookup")
        req = requests.get(
            "https://raw.githubusercontent.com/jkerai1/CLSID-Lookup/main/List.md"
        )
        if req.status_code == 200:
            lines = req.text.splitlines()
            for line in lines:
                if target in line:
                    line = line.split(" ")
                    analysisbuddy.print_json(
                        {"CLSID": line[0], "Description": " ".join(line[1:])}
                    )
        else:
            raise Exception
    except Exception as e:
        analysisbuddy.error_message(f"Failed to run the CLSID lookup.", str(e))
    clsid_lookup() if analysisbuddy.ask_to_run_again() else menu()


def event_id_lookup():
    """
    This function will lookup a Windows Event ID in ./config/json_lookups/windows_lookups/windowseventids.json
    """
    try:
        analysisbuddy.title_bar("Windows Event ID Lookup")
        analysisbuddy.download_file_from_internet(
            url="https://raw.githubusercontent.com/qbrusa/Windows-Security-Event-ID-Helper/main/AdvancedSecurityEventIDs.json",
            file_path="./config/json_lookups/windows_lookups/windowseventids.json",
        )
        analysisbuddy.json_lookup(
            "./config/json_lookups/windows_lookups/windowseventids.json", "UTF-8"
        )
    except Exception as e:
        analysisbuddy.error_message("Failed to run the event id lookup", str(e))
    event_id_lookup() if analysisbuddy.ask_to_run_again() else menu()


def lolbin_lookup():
    """
    This function will lookup a LOLBin in ./config/json_lookups/windows_lookups/lolbins.json
    """
    try:
        analysisbuddy.title_bar("LOLBin Lookup")
        analysisbuddy.download_file_from_internet(
            url="https://lolbas-project.github.io/api/lolbas.json",
            file_path="./config/json_lookups/windows_lookups/lolbins.json",
        )
        analysisbuddy.json_lookup(
            "./config/json_lookups/windows_lookups/lolbins.json", "UTF-8"
        )
    except Exception as e:
        analysisbuddy.error_message("Failed to run the LOLBin lookup", str(e))
    lolbin_lookup() if analysisbuddy.ask_to_run_again() else menu()


def loldriver_lookup():
    """
    This function will lookup a LOLDriver in ./config/json_lookups/windows_lookups/loldrivers.json
    """
    try:
        analysisbuddy.title_bar("Loldriver Lookup")
        analysisbuddy.download_file_from_internet(
            url="https://www.loldrivers.io/api/drivers.json",
            file_path="./config/json_lookups/windows_lookups/loldrivers.json",
        )
        analysisbuddy.json_lookup(
            "./config/json_lookups/windows_lookups/loldrivers.json", "UTF-8"
        )
    except Exception as e:
        analysisbuddy.error_message("Failed to run the Loldriver lookup", str(e))
    loldriver_lookup() if analysisbuddy.ask_to_run_again() else menu()


def echotrail_lookup():
    """
    This function will lookup a Windows Binary using the EchoTrail API
    """
    try:
        if loadconfig.check_buddy_config("ECHOTRAIL_API_KEY"):
            analysisbuddy.title_bar("Echo Trail Windows Binary Lookup")
            search = analysisbuddy.ask_for_user_input(
                "Enter a Windows Binary to lookup"
            )

            response = requests.get(
                f"https://api.echotrail.io/v1/insights/{search}",
                headers={
                    "X-Api-Key": str(configvars["ECHOTRAIL_API_KEY"]),
                    "Content-Type": "application/json",
                },
            )
            if response.status_code == 200:
                analysisbuddy.print_json(response.json())
            else:
                raise Exception
    except Exception as e:
        analysisbuddy.error_message("Failed to run the EchoTrail lookup", str(e))
    echotrail_lookup() if analysisbuddy.ask_to_run_again() else menu()
