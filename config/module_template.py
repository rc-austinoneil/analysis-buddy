import analysisbuddy
from config import fontcolors, loadconfig

bcolors = fontcolors.bcolors()
configvars = loadconfig.load_buddy_config()


# Menu
def menu():
    analysisbuddy.title_bar("Example Menu")
    analysisbuddy.menu_item(0, "Return to main menu", "goback")
    analysisbuddy.menu_item(1, "Tool function", "tool")
    analysisbuddy.menu_item(2, "Menu function", "menu")
    menu_switch(input(f"{bcolors.INPUT} ~> {bcolors.ENDC}"))


def menu_switch(choice):
    if choice == "1":
        function1()
    if choice == "2":
        function2()
    if choice == "3":
        function3()
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
