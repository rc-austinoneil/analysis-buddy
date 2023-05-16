import socbuddy
from config import fontcolors, loadconfig

bcolors = fontcolors.bcolors()
configvars = loadconfig.load_buddy_config()


# Menu
def menu():
    socbuddy.title_bar("Linux Tools")
    socbuddy.menu_item(0, "Return to main menu", "goback")
    socbuddy.menu_item(1, "Placeholder", "tool")
    menu_switch(input(f"{bcolors.INPUT} ~> {bcolors.ENDC}"))


def menu_switch(choice):
    if choice == "1":
        function1()
    if choice == "0":
        socbuddy.main_menu()
    else:
        menu()


# Tools
def function1():
    pass


def function2():
    pass


def function3():
    pass
