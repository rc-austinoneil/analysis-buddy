import analysisbuddy
from config import fontcolors, loadconfig

bcolors = fontcolors.bcolors()
configvars = loadconfig.load_buddy_config()


# Menu
def menu():
    analysisbuddy.title_bar("Linux Tools")
    analysisbuddy.menu_item(0, "Return to main menu", "goback")
    analysisbuddy.menu_item(1, "Placeholder", "tool")
    menu_switch(input(f"{bcolors.INPUT} ~> {bcolors.ENDC}"))


def menu_switch(choice):
    if choice == "1":
        function1()
    if choice == "0":
        analysisbuddy.main_menu()
    else:
        menu()


# Tools
def function1():
    pass


def function2():
    pass


def function3():
    pass
