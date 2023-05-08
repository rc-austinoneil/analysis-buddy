#!./venv/bin/python3
import sys
import os
import pyperclip
import webbrowser
import urllib.parse
import json
import requests
from modules import urls, dns_ip, decoders, phishing, osint, mitre, windows, cloud
from config import fontcolors, loadconfig
from team import teammenu
from datetime import datetime

bcolors = fontcolors.bcolors()
configvars = loadconfig.load_buddy_config()


# Menu
def main_menu():
    os.system("clear")
    title_bar("Main Menu", True)
    title_bar_time()
    menu_item(0, "Exit Tool", "exit")
    menu_item(1, teammenu.team_name(), "menu")
    menu_item(2, "Decoders (PP, URL, SafeLinks)", "menu")
    menu_item(3, "DNS and IP Tools", "menu")
    menu_item(4, "Phishing Analysis", "menu")
    menu_item(5, "URLs", "menu")
    menu_item(6, "Windows Tools", "menu")
    menu_item(7, "Cloud Tools", "menu")
    menu_item(8, "Run data through OSINT tooling", "tool")
    menu_item(9, "MITRE ATT&CK Lookup", "tool")
    menu_item(10, "JSON Pretty Print", "tool")
    menu_switch(input(f"{bcolors.INPUT} ~> {bcolors.ENDC}"))


def menu_switch(choice):
    if choice == "0":
        sys.exit()
    if choice == "1":
        teammenu.main_menu()
    if choice == "2":
        decoders.menu()
    if choice == "3":
        dns_ip.menu()
    if choice == "4":
        phishing.menu()
    if choice == "5":
        urls.menu()
    if choice == "6":
        windows.menu()
    if choice == "7":
        cloud.menu()
    if choice == "8":
        osint.run_osint()
    if choice == "9":
        mitre.mitre_lookup()
    if choice == "10":
        decoders.json_pprint()
    else:
        main_menu()


# Project Wide Functions
def title_bar(title, include_clipboard=False):
    print("")
    print(
        f"{bcolors.HEADER}{bcolors.UNDERLINE}{title[:50].upper().center(50)}{bcolors.ENDC}"
    )
    if include_clipboard and not clipboard_paste() == "Clipboard init failed.":
        print("")
        print(f"{bcolors.HEADER}On Clipboard:{bcolors.ENDC} {clipboard_paste()[:75]}")
    print("")


def title_bar_time():
    print(f" Local : {datetime.now().strftime('%H:%M:%S %m/%d/%Y')}")
    print(f" UTC   : {datetime.utcnow().strftime('%H:%M:%S %m/%d/%Y')}")
    print("")


def menu_item(option_number, option_name, option_type):
    prefix = ""
    if option_type == "menu":
        prefix = f"{bcolors.MENU}[MENU]"
    elif option_type == "tool":
        prefix = f"{bcolors.TOOL}[TOOL]"
    elif option_type == "copy":
        prefix = "[CLIPBOARD]"
    elif option_type == "link":
        prefix = "[LINK]"
    elif option_type == "goback":
        prefix = f"{bcolors.GOBACK}[RETURN]"
    elif option_type == "exit":
        prefix = f"{bcolors.GOBACK}[EXIT]"

    if option_number <= 9:
        prefix = f"  {prefix}"
    else:
        prefix = f" {prefix}"
    print(f" {option_number}:{prefix} {option_name}{bcolors.ENDC}")


def error_message(message, error=False):
    print("")
    print(bcolors.ERROR + message + bcolors.ENDC)
    if error:
        print(bcolors.ERROR + error + bcolors.ENDC)


def success_message(message):
    print("")
    print(bcolors.OKGREEN + message + bcolors.ENDC)
    print("")


def info_message(message, newline=False):
    if newline:
        print("")
    print(bcolors.WARNING + message + bcolors.ENDC)


def next_result_message(message="Next Result"):
    print("")
    print(
        bcolors.NEXTRESULT
        + bcolors.UNDERLINE
        + message[:50].upper().center(50)
        + bcolors.ENDC
    )
    print("")


def clipboard_paste():
    try:
        return pyperclip.paste()
    except Exception:
        return "Clipboard init failed."


def clipboard_copy(item_to_copy):
    try:
        pyperclip.copy(item_to_copy)
        success_message("Output copied to clipboard.")
    except Exception:
        error_message("Clipboard init failed, copy output manually.")


def ask_for_user_input(input_message="Enter a search string"):
    print("")
    if clipboard_paste() == "Clipboard init failed.":
        output = str(input(f"{bcolors.INPUT}{input_message}: {bcolors.ENDC}")).strip()
    else:
        paste_from_clipboard = str(
            input(
                f"{bcolors.INPUT}{input_message}, Paste from clipboard? (Y/N): {bcolors.ENDC}"
            )
        ).strip()
        if paste_from_clipboard.upper() == "Y":
            output = str(clipboard_paste()).strip()
        elif paste_from_clipboard.upper() == "N":
            output = str(
                input(f"{bcolors.INPUT}{input_message}: {bcolors.ENDC}")
            ).strip()
        else:
            output = str(paste_from_clipboard).strip()
    return output


def ask_to_run_again():
    print("")
    run_again = input(f"{bcolors.INPUT}Run again? (Y/N): {bcolors.ENDC}")
    if run_again.upper() == "Y":
        return True
    else:
        return False


def open_in_jsoncrack(inputdata):
    open_jsoncrack = input(
        f"{bcolors.INPUT}Open in jsoncrack? See (Y/N) {bcolors.ENDC}"
    )
    if open_jsoncrack.upper() == "Y":
        info_message(
            "This requires JSONCrack running in a local docker container. See the following link to download and install.\nhttps://github.com/AykutSarac/jsoncrack.com"
        )
        try:
            url = f"http://127.0.0.1:8888/editor?json={urllib.parse.quote_plus(json.dumps(inputdata))}"
            success_message(url)
            webbrowser.open(url)
        except Exception:
            error_message("Error opening jsoncrack.")


# fmt: off
def print_json(json_data, level=0, newline=True):
    try:
        if newline:
            print("")

        if isinstance(json_data, list):
            for item in json_data:
                print_json(item, level, False)

        if isinstance(json_data, dict):
            for k, v in json_data.items():
                if isinstance(v, dict):
                    print(" "*level + f"{bcolors.OKBLUE}{k.capitalize()}:{bcolors.ENDC}")
                    print_json(v, level+1, False)

                elif isinstance(v, list):
                    print(" "*level + f"{bcolors.WARNING}{k.capitalize()}:{bcolors.ENDC}")
                    for item in v:
                        if isinstance(item, dict):
                            print_json(item, level+1, False)
                        if isinstance(item, list):
                                print(" "*level + f" - {str(item)}") 
                        else:
                            print(" "*level + f" - {str(item)}")
                else:
                    print(" "*level + f"{bcolors.OKGREEN}{k.capitalize()}: {bcolors.ENDC}{str(v)}")
    except Exception:
        error_message("Error printing results.")
# fmt: on


def json_lookup(file, encoding=None):
    def search(values, searchFor):
        try:
            output = []
            for k in values:
                if searchFor in str(k):
                    output.append(k)
                else:
                    for v in k.values():
                        if searchFor in str(v):
                            output.append(k)
            return output
        except Exception:
            error_message(f"Error searching for {searchFor} in {file}.")

    try:
        searchFor = ask_for_user_input("Enter a search string")
        with open(file, "r", encoding=encoding) as f:
            data = json.load(f)
        search_results = search(data, searchFor)

        if search_results:
            print("")
            printed_result = 0
            for result in search_results:
                print_json(result)
                printed_result += 1
                if printed_result < len(search_results):
                    next_result_message()
            info_message(f"Found {len(search_results)} results for {searchFor}.", True)
        else:
            error_message(f"No results found for {searchFor}.")
    except FileNotFoundError:
        error_message(f"Error loading file: {file}")
    except Exception:
        raise Exception


def download_file_from_internet(url, file_path):
    try:
        if not os.path.isfile(file_path):
            response = requests.get(url)
            if response.status_code == 200:
                with open(file_path, "wb") as f:
                    f.write(response.content)
                info_message(f"File downloaded and saved to {file_path}")
    except Exception:
        error_message(f"Failed to download {url} to {file_path}")


if __name__ == "__main__":
    main_menu()
