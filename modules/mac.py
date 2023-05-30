import analysisbuddy
from config import fontcolors, loadconfig

bcolors = fontcolors.bcolors()
configvars = loadconfig.load_buddy_config()


# Menu
def menu():
    analysisbuddy.title_bar("MacOS Tools")
    analysisbuddy.menu_item(0, "Return to main menu", "goback")
    analysisbuddy.menu_item(1, "Living off the orchard Bin lookup", "tool")
    menu_switch(input(f"{bcolors.INPUT} ~> {bcolors.ENDC}"))


def menu_switch(choice):
    if choice == "1":
        loobin()
    if choice == "0":
        analysisbuddy.main_menu()
    else:
        menu()


# Tools
def loobin():
    """
    This function will lookup a Loo Bin in ./config/json_lookups/macos_lookups/loobins.json
    """
    try:
        analysisbuddy.title_bar("Loo bin Lookup")
        analysisbuddy.download_file_from_internet(
            url="https://www.loobins.io/loobins.json",
            file_path="./config/json_lookups/macos_lookups/loobins.json",
        )
        analysisbuddy.json_lookup(
            "./config/json_lookups/macos_lookups/loobins.json", "UTF-8"
        )
    except Exception as e:
        analysisbuddy.error_message("Failed to run the Loo Bin lookup", str(e))
    loobin() if analysisbuddy.ask_to_run_again() else menu()
