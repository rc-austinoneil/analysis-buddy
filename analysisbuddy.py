#!./venv/bin/python3
import sys
import os
import pyperclip
import webbrowser
import urllib.parse
import json
import csv
import requests
from config import fontcolors, loadconfig
from team import teammenu
from datetime import datetime
from modules import (
    decoders_hashes,
    dns_ip,
    osint,
    mitre,
    phishing_urls,
    windows,
    cloud,
    linux,
    mac,
)

bcolors = fontcolors.bcolors()
configvars = loadconfig.load_buddy_config()


# Menu
def main_menu():
    """
    This function will clear the console and print the Analysis Buddy main menu.
    """
    os.system("clear")
    title_bar("Analysis Buddy Main Menu", True)
    title_bar_time()
    menu_item(0, "Exit Tool", "exit")
    menu_item(1, "Search All OSINT Tools", "tool")
    menu_item(2, teammenu.team_name(), "menu")
    menu_item(3, "Decoders & Hash Tools", "menu")
    menu_item(4, "DNS & IP Tools", "menu")
    menu_item(5, "Phishing & URL Tools", "menu")
    menu_item(6, "Windows Tools", "menu")
    menu_item(7, "Linux Tools", "menu")
    menu_item(8, "MacOS Tools", "menu")
    menu_item(9, "Cloud Tools", "menu")
    menu_item(10, "MITRE ATT&CK Lookup", "tool")
    menu_item(11, "JSON Pretty Print", "tool")
    menu_item(12, "Convert CSV to JSON", "tool")
    menu_item(13, "Convert JSON to CSV", "tool")
    menu_switch(input(f"{bcolors.INPUT} ~> {bcolors.ENDC}"))


def menu_switch(choice):
    """
    This function will take the user input and run the appropriate function.
    """
    if choice == "0":
        sys.exit()
    if choice == "1":
        osint.run_osint()
    if choice == "2":
        teammenu.main_menu()
    if choice == "3":
        decoders_hashes.menu()
    if choice == "4":
        dns_ip.menu()
    if choice == "5":
        phishing_urls.menu()
    if choice == "6":
        windows.menu()
    if choice == "7":
        linux.menu()
    if choice == "8":
        mac.menu()
    if choice == "9":
        cloud.menu()
    if choice == "10":
        mitre.mitre_lookup()
    if choice == "11":
        decoders_hashes.json_pprint()
    if choice == "12":
        csv_to_json()
        csv_to_json() if ask_to_run_again() else main_menu()
    if choice == "13":
        json_to_csv()
        json_to_csv() if ask_to_run_again() else main_menu()

    else:
        main_menu()


# Project Wide Functions
def title_bar(title, include_clipboard=False):
    """
    This function will print a title bar with the title passed to it.
    The optional include_clipboard parameter will print the contents of the clipboard if it is not empty.
    """
    try:
        print("")
        print(
            f"{bcolors.HEADER}{bcolors.UNDERLINE}{title[:50].upper().center(50)}{bcolors.ENDC}"
        )
        if include_clipboard and not clipboard_paste() == "Clipboard init failed.":
            print("")
            print(
                f"{bcolors.HEADER}On Clipboard:{bcolors.ENDC} {clipboard_paste()[:75]}"
            )
        print("")
    except Exception:
        print("")
        print(
            f"{bcolors.HEADER}{bcolors.UNDERLINE}{title[:50].upper().center(50)}{bcolors.ENDC}"
        )
        print("")


def title_bar_time():
    """
    This function will print the current time in UTC and Local time.
    """
    print(
        f"{bcolors.HEADER}Local :{bcolors.ENDC} {datetime.now().strftime('%H:%M:%S %m/%d/%Y')}"
    )
    print(
        f"{bcolors.HEADER}UTC   :{bcolors.ENDC} {datetime.utcnow().strftime('%H:%M:%S %m/%d/%Y')}"
    )
    print("")


def menu_item(option_number, option_name, option_type):
    """
    This function will print a menu item with the option number, option name, and option type.
    """
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
    """
    This function will print an error message in red.
    """
    print("")
    print(bcolors.ERROR + message + bcolors.ENDC)
    if error:
        print(bcolors.ERROR + error + bcolors.ENDC)


def success_message(message):
    """
    This function will print a success message in green.
    """
    print("")
    print(bcolors.OKGREEN + message + bcolors.ENDC)
    print("")


def info_message(message, newline=False):
    """
    This function will print an info message in yellow. Optional newline parameter
    to give spacing if needed.
    """
    if newline:
        print("")
    print(bcolors.WARNING + message + bcolors.ENDC)


def next_result_message(message="Next Result"):
    """
    This function will print a message in purple to indicate the next result.
    """
    print("")
    print(
        bcolors.NEXTRESULT
        + bcolors.UNDERLINE
        + message[:50].upper().center(50)
        + bcolors.ENDC
    )
    print("")


def clipboard_paste():
    """
    This function will attempt to paste the contents of the clipboard.
    If it fails, it will return "Clipboard init failed."
    """
    try:
        return pyperclip.paste()
    except Exception:
        return "Clipboard init failed."


def clipboard_copy(item_to_copy):
    """
    This function will attempt to copy the item passed to it to the clipboard.
    """
    try:
        pyperclip.copy(item_to_copy)
        success_message("Output copied to clipboard.")
    except Exception:
        error_message("Clipboard init failed, copy output manually.")


def ask_for_user_input(input_message="Enter a search string"):
    """
    This function will ask the user for input. If the clipboard is not empty,
    it will ask if the user wants to paste from the clipboard.
    """
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
    """
    This function will ask the user if they want to run the tool again and return True or False.
    """
    print("")
    run_again = input(f"{bcolors.INPUT}Run again? (Y/N): {bcolors.ENDC}")
    if run_again.upper() == "Y":
        return True
    else:
        return False


def open_in_jsoncrack(inputdata):
    """
    This function will ask the user if they want to open the input data in jsoncrack.
    """
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
        except Exception as e:
            error_message("Error opening jsoncrack.", str(e))


# fmt: off
def print_json(json_data, level=0, newline=True):
    """
    This function will print json data in a readable format to the console.
    """
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
                        elif isinstance(item, list):
                            print(" "*level + f" - {str(item)}")
                        else:
                            print(" "*level + f" - {str(item)}")
                else:
                    print(" "*level + f"{bcolors.OKGREEN}{k.capitalize()}: {bcolors.ENDC}{str(v)}")
    except Exception as e:
        error_message("Error printing results.", str(e))
# fmt: on


def json_lookup(file, encoding=None):
    """
    This function will load a json file then search the json file for a string and return the results.
    """

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
        except Exception as e:
            error_message(f"Error searching for {searchFor} in {file}.", str(e))

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
    """
    This function will download a file from the internet and save it to the file_path.
    """
    try:
        if not os.path.isfile(file_path):
            response = requests.get(url)
            if response.status_code == 200:
                with open(file_path, "wb") as f:
                    f.write(response.content)
                info_message(f"File downloaded and saved to {file_path}")
    except Exception as e:
        error_message(f"Failed to download {url} to {file_path}", str(e))


def json_to_csv(input_file_path=None):
    """
    This function will convert a JSON file to a CSV file.
    """
    try:
        title_bar("JSON to CSV Converter")
        if not input_file_path:
            input_file_path = ask_for_user_input("Enter the path to the JSON file")
        output_file_path = ask_for_user_input("Enter the path to output CSV file")

        with open(input_file_path, "r") as input_file:
            json_data = json.load(input_file)

        headers = list(json_data[0].keys())

        with open(output_file_path, "w+", newline="") as output_file:
            writer = csv.DictWriter(output_file, fieldnames=headers)
            writer.writeheader()
            writer.writerows(json_data)

        success_message(
            f"Conversion successful\nJSON file '{input_file_path}' converted to CSV file '{output_file_path}'"
        )
    except Exception as e:
        error_message("Failed to convert JSON to CSV", str(e))


def csv_to_json(input_file_path=None):
    """
    This function will convert a CSV file to a JSON file.
    """
    try:
        title_bar("CSV to JSON Converter")
        if not input_file_path:
            input_file_path = ask_for_user_input("Enter the path to the CSV file")
        output_file_path = ask_for_user_input("Enter the path to output JSON file")

        with open(input_file_path, "r") as input_file:
            reader = csv.DictReader(input_file)
            rows = list(reader)

        with open(output_file_path, "w+") as output_file:
            json.dump(rows, output_file, indent=4)

        success_message(
            f"Conversion successful\nCSV file '{input_file_path}' converted to JSON file '{output_file_path}'"
        )
    except Exception as e:
        error_message("Failed to convert CSV to JSON", str(e))


if __name__ == "__main__":
    main_menu()
