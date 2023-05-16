import analysisbuddy
from config import fontcolors

bcolors = fontcolors.bcolors()


# Menu
def menu():
    analysisbuddy.title_bar("Cloud Tools")
    analysisbuddy.menu_item(0, "Return to main menu", "goback")
    analysisbuddy.menu_item(1, "AWS serviceName Lookup", "tool")
    analysisbuddy.menu_item(2, "AWS eventName Lookup", "tool")
    analysisbuddy.menu_item(3, "GCP serviceName Lookup", "tool")
    analysisbuddy.menu_item(4, "Azure Service Actions Lookup", "tool")
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
        analysisbuddy.main_menu()


# Tools
def aws_service_actions():
    """
    This function will lookup an AWS service name in the awsservicenames.json file
    """
    analysisbuddy.title_bar("AWS serviceName Lookup")
    analysisbuddy.json_lookup(
        "./config/json_lookups/cloud_lookups/awsservicenames.json"
    )
    aws_service_actions() if analysisbuddy.ask_to_run_again() else menu()


def aws_event_names():
    """
    This function will lookup an AWS event name in the awseventnames.json file
    """
    analysisbuddy.title_bar("AWS eventName Lookup")
    analysisbuddy.json_lookup(
        "./config/json_lookups/cloud_lookups/awseventnames.json", "utf-8-sig"
    )
    aws_event_names() if analysisbuddy.ask_to_run_again() else menu()


def gcp_service_names():
    """
    This function will lookup a GCP service name in the gcpservices.json file
    """
    analysisbuddy.title_bar("GCP serviceName Lookup")
    analysisbuddy.json_lookup("./config/json_lookups/cloud_lookups/gcpservices.json")
    gcp_service_names() if analysisbuddy.ask_to_run_again() else menu()


def azure_service_actions():
    """
    This function will lookup an Azure service action in the azureserviceactions.json file
    """
    analysisbuddy.title_bar("Azure Service Actions Lookup")
    analysisbuddy.json_lookup(
        "./config/json_lookups/cloud_lookups/azureserviceactions.json"
    )
    azure_service_actions() if analysisbuddy.ask_to_run_again() else menu()
