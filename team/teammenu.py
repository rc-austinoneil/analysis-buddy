import socbuddy
import os
from config import fontcolors, loadconfig
from team import *

bcolors = fontcolors.bcolors()
# teamconfigvars = loadconfig.load_team_config()


def team_name():
    return "Internal Tooling"


# Menu
def main_menu():
    os.system("clear")
    socbuddy.title_bar(team_name() + " Main Menu", True)
    socbuddy.title_bar_time()
    socbuddy.error_message(
        "This module allows you to use SocBuddy as a framework for your own internal tooling. To configure, please see the readme.\n"
    )
    socbuddy.menu_item(0, "Return to main menu", "goback")
    menu_switch(input(bcolors.INPUT + " ~> " + bcolors.ENDC))


def menu_switch(choice):
    if choice == "0":
        socbuddy.main_menu()
    else:
        main_menu()


def function1():
    pass
