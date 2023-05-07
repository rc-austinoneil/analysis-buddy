import strictyaml, sys
from config import fontcolors

bcolors = fontcolors.bcolors()


def load_buddy_config():
    try:
        f = open("./config/config.yaml", "r")
        configvars = strictyaml.load(f.read())
        f.close()
        return configvars
    except FileNotFoundError:
        print(
            bcolors.ERROR
            + "Error: ./config/config.yaml not found.\nPlease configure the config file before launching Soc Buddy. See readme for documentation."
            + bcolors.ENDC
        )
        sys.exit()


def check_buddy_config(key):
    configvars = load_buddy_config()
    if configvars[key] != "Enter API Key Here":
        return True
    else:
        raise Exception(f"{key} not set in ./config/config.yaml")


def check_team_config(key):
    configvars = load_team_config()
    if configvars[key] != "Enter API Key Here":
        return True
    else:
        raise Exception(f"{key} not set in ./team/config/config.yaml")


def load_team_config():
    try:
        f = open("./team/config/config.yaml", "r")
        configvars = strictyaml.load(f.read())
        f.close()
        return configvars
    except FileNotFoundError:
        print(
            bcolors.ERROR
            + "Error: ./team/config/config.yaml not found.\nPlease configure your team config file before launching Soc Buddy. See readme for documentation."
            + bcolors.ENDC
        )
        sys.exit()


def load_machinae_config():
    try:
        with open("./config/machinae.yaml", "r") as file:
            return "./config/machinae.yaml"
    except FileNotFoundError:
        print(
            bcolors.ERROR
            + "Error: ./config/machinae.yaml not found.\nPlease setup the machinae config file before launching Soc Buddy. See readme for documentation."
            + bcolors.ENDC
        )
        sys.exit()
