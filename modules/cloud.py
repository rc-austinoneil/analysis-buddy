import socbuddy
from config import fontcolors

bcolors = fontcolors.bcolors()


# Menu
def menu():
    socbuddy.title_bar("Cloud")
    socbuddy.menu_item(0, "Return to main menu", "goback")
    socbuddy.menu_item(1, "AWS serviceName Lookup", "tool")
    socbuddy.menu_item(2, "AWS eventName Lookup", "tool")
    socbuddy.menu_item(3, "GCP serviceName Lookup", "tool")
    socbuddy.menu_item(4, "Azure Service Actions Lookup", "tool")
    menu_switch(input(f"{bcolors.INPUT} ~> {bcolors.ENDC}"))


def menu_switch(choice):
    if choice == "1":
        aws_service_actions()
    if choice == "2":
        aws_event_names()
    if choice == "3":
        gcp_service_names()
    if choice == "4":
        azure_service_actions()
    else:
        socbuddy.main_menu()


# Tools
def aws_service_actions():
    socbuddy.title_bar("AWS serviceName Lookup")
    socbuddy.json_lookup("./config/json_lookups/cloud_lookups/awsservicenames.json")
    aws_service_actions() if socbuddy.ask_to_run_again() else menu()


def aws_event_names():
    socbuddy.title_bar("AWS eventName Lookup")
    socbuddy.json_lookup(
        "./config/json_lookups/cloud_lookups/awseventnames.json", "utf-8-sig"
    )
    aws_event_names() if socbuddy.ask_to_run_again() else menu()


def gcp_service_names():
    socbuddy.title_bar("GCP serviceName Lookup")
    socbuddy.json_lookup("./config/json_lookups/cloud_lookups/gcpservices.json")
    gcp_service_names() if socbuddy.ask_to_run_again() else menu()


def azure_service_actions():
    socbuddy.title_bar("Azure Service Actions Lookup")
    socbuddy.json_lookup("./config/json_lookups/cloud_lookups/azureserviceactions.json")
    azure_service_actions() if socbuddy.ask_to_run_again() else menu()
