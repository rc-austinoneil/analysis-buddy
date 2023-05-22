import analysisbuddy
import os
from config import fontcolors, loadconfig
from custom import *

bcolors = fontcolors.bcolors()
# customconfigvars = loadconfig.load_custom_config()


def custom_name():
    return "Internal Tooling"


# Menu
def main_menu():
    os.system("clear")
    analysisbuddy.title_bar(custom_name() + " Main Menu", True)
    analysisbuddy.title_bar_time()
    analysisbuddy.error_message(
        "This module allows you to use Analysis Buddy as a framework for your own internal tooling. To configure, please see the readme.\n"
    )
    analysisbuddy.menu_item(0, "Return to main menu", "goback")
    menu_switch(input(bcolors.INPUT + " ~> " + bcolors.ENDC))


def menu_switch(choice):
    if choice == "0":
        analysisbuddy.main_menu()
    else:
        main_menu()


def function1():
    pass
