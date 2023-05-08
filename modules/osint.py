import socbuddy
import subprocess
import requests
import ipaddress
import re
import json
import datetime
import os
from config import fontcolors, loadconfig

bcolors = fontcolors.bcolors()
configvars = loadconfig.load_buddy_config()
machinaeconfig = loadconfig.load_machinae_config()


# Tools
def get_target_type(target):
    try:
        getVer = ipaddress.ip_address(target)
        if getVer.version == 4:
            return "ipv4"
        elif getVer.version == 6:
            return "ipv6"
    except ValueError:
        pass

    # Hashes
    if re.match("^[a-f0-9]{32}$", target, re.I):
        # MD5
        return "hash"
    elif re.match("^[a-f0-9]{40}$", target, re.I):
        # SHA-1
        return "hash.sha1"
    elif re.match("^[a-f0-9]{64}$", target, re.I):
        # SHA-256
        return "hash.sha256"
    elif re.match("^[a-f0-9]{128}$", target, re.I):
        # SHA-512
        return "hash.sha512"

    # URL
    elif re.match("^https?://", target, re.I):
        return "url"

    # Email Addresses
    elif re.match("^.*?@.*?$", target, re.I):
        return "email"

    # SSL fingerprints
    elif re.match("^(?:[a-f0-9]{2}:){19}[a-f0-9]{2}$", target, flags=re.I):
        return "sslfp"

    # Mac Addresses
    elif re.match(
        "^([0-9a-fA-F][0-9a-fA-F][-:\.]){5}([0-9a-fA-F][0-9a-fA-F])$", target, re.I
    ):
        return "mac"

    return "fqdn"


def count_occurrences(target):
    historical_osint_data = "./config/output/osint_data.json"

    def append_to_file(target):
        date = datetime.datetime.now().strftime("%m-%d-%Y %H:%M:%S")
        data = {"target": target, "date": date}
        try:
            with open(historical_osint_data, "r") as f:
                existing_data = json.load(f)
        except Exception:
            existing_data = []
        existing_data.append(data)
        with open(historical_osint_data, "w") as f:
            json.dump(existing_data, f)

    try:
        if not os.path.exists(historical_osint_data):
            os.system(f"touch {historical_osint_data}")

        with open(historical_osint_data, "r") as f:
            data = json.load(f)
    except Exception:
        data = []

    last_date = None
    for d in reversed(data):
        if d.get("target") == target:
            last_date = d.get("date")
            break

    count = sum(1 for d in data if d.get("target") == target)
    append_to_file(target)

    if count == 0:
        return f"{target} has not been scanned before."
    else:
        return (
            f"{target} has been scanned {count} times, the last scan was: {last_date}"
        )


def run_osint():
    try:
        socbuddy.title_bar("Machinae OSINT")
        target = str(socbuddy.ask_for_user_input("Enter a target"))
        if "[.]" in target:
            target = target.replace("[.]", ".")
        socbuddy.info_message(f"Running OSINT search for {target}", True)
        socbuddy.info_message(count_occurrences(target), False)
        subprocess.call(["machinae", "-c", machinaeconfig, "-s", "default", target])
        additional_osint(target)
        run_osint() if socbuddy.ask_to_run_again() else socbuddy.main_menu()
    except KeyboardInterrupt:
        socbuddy.error_message("OSINT search canceled.")
    except Exception:
        socbuddy.error_message("Failed to run OSINT search.")
        input(bcolors.INPUT + "Press enter to return to the main menu" + bcolors.ENDC)
        socbuddy.main_menu()


def osint_enrichment(target, newline=False):
    try:
        if newline:
            print("")

        if (
            input(
                f"{bcolors.INPUT}Run {target} against additional OSINT enrichment? (Y/N): {bcolors.ENDC}"
            ).upper()
            == "Y"
        ):
            count_occurrences(target)
            subprocess.call(["machinae", "-c", machinaeconfig, "-s", "default", target])
            additional_osint(target)
        else:
            return
    except KeyboardInterrupt:
        socbuddy.error_message("OSINT search canceled.")
    except Exception:
        socbuddy.error_message("Failed to run OSINT search.")


def additional_osint(target):
    links = []
    if get_target_type(target) == "ipv4":
        tor_list(target)
        abuse_ipdb(target)
        ip_threat_lists(target)
        links.append(f"https://www.virustotal.com/gui/ip-address/{target}")
        links.append(f"https://www.abuseipdb.com/check/{target}")
        links.append(f"https://viz.greynoise.io/ip/{target}")

    elif get_target_type(target) in ["hash", "hash.sha1", "hash.sha256", "hash.sha512"]:
        hash_threat_lists(target)
        links.append(f"https://www.virustotal.com/gui/file/{target}")
        links.append(f"https://www.hybrid-analysis.com/search?query={target}")
        links.append(f"https://www.joesandbox.com/search?q={target}")

    elif get_target_type(target) == "fqdn":
        domain_threat_lists(target)
        links.append(f"https://www.virustotal.com/gui/domain/{target}")
        links.append(
            f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{target}&run=toolpage"
        )

    if links:
        print(f"{bcolors.OKGREEN}[+] OSINT Links{bcolors.ENDC}")
        for link in links:
            print(f"    [-] {link}")


def tor_list(target):
    try:
        TOR_URL = "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"
        req = requests.get(TOR_URL)
        if req.status_code == 200:
            print(f"{bcolors.OKGREEN}[+] TOR Exit Node Report{bcolors.ENDC}")
            tl = req.text.split("\n")
            c = 0
            for i in tl:
                if target == i:
                    print(f"    [-] {i} is a TOR Exit Node")
                    c = c + 1
            if c == 0:
                print(f"    [-] {target} is NOT a TOR Exit Node")
        else:
            raise Exception
    except Exception:
        print(f"{bcolors.ERROR}[!] Unable to check against TOR list{bcolors.ENDC}")


def abuse_ipdb(target):
    try:
        if loadconfig.check_buddy_config("AB_API_KEY"):
            AB_URL = "https://api.abuseipdb.com/api/v2/check"
            days = "180"
            querystring = {"ipAddress": target, "maxAgeInDays": days}
            headers = {
                "Accept": "application/json",
                "Key": configvars.data["AB_API_KEY"],
            }
            response = requests.request(
                method="GET", url=AB_URL, headers=headers, params=querystring
            )

            if response.status_code == 200:
                req = response.json()
                print(f"{bcolors.OKGREEN}[+] ABUSEIPDB Report{bcolors.ENDC}")
                print("    [-] IP:          " + str(req["data"]["ipAddress"]))
                print("    [-] Reports:     " + str(req["data"]["totalReports"]))
                print(
                    "    [-] Abuse Score: "
                    + str(req["data"]["abuseConfidenceScore"])
                    + "%"
                )
                print("    [-] Last Report: " + str(req["data"]["lastReportedAt"]))
            else:
                raise Exception
    except Exception:
        print(f"{bcolors.ERROR}[!] Unable to run ABUSE IPDB{bcolors.ENDC}")


def ip_threat_lists(target):
    class lookupLists:
        def __init__(self, name, desc, category, listURL, period):
            self.name = name
            self.desc = desc
            self.category = category
            self.listURL = listURL
            self.period = period

        def ip_threat_lists(self, target):
            self.hitlist = set()
            req = requests.get(self.listURL)
            if req.status_code == 200:
                lines = req.text.splitlines()
                for line in lines:
                    if target == line:
                        self.hitlist.add(target)

    try:
        with open("./config/json_lookups/threat_lists/iplists.json") as settings:
            blacklists = json.load(settings)

        blacklistObjs = [
            lookupLists(
                blacklist["name"],
                blacklist["desc"],
                blacklist["category"],
                blacklist["listURL"],
                blacklist["period"],
            )
            for blacklist in blacklists
        ]

        for listObj in blacklistObjs:
            listObj.ip_threat_lists(target)

        for listObj in blacklistObjs:
            if len(listObj.hitlist) != 0:
                print(
                    f"{bcolors.OKGREEN}[+] IP found in {listObj.name} threat list{bcolors.ENDC}"
                )
                print(f"    [-] Category: {listObj.category}")
                print(f"    [-] List Age: {listObj.period}")
                print(f"    [-] List Description: {listObj.desc}")
                print(f"    [-] List URL: {listObj.listURL}")
            else:
                print(
                    f"{bcolors.WARNING}[-] IP not found in {listObj.name} threat list{bcolors.ENDC}"
                )
    except Exception:
        print(f"{bcolors.ERROR}[!] Unable to run IP threat lists{bcolors.ENDC}")


def domain_threat_lists(target):
    class lookupLists:
        def __init__(self, name, category, listURL):
            self.name = name
            self.category = category
            self.listURL = listURL

        def remove_ip_address(self, line):
            ip_address_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3} \b"
            if re.search(ip_address_pattern, line):
                line = line.split(" ")[1]
                line = line.strip()
            return line

        def domain_threat_lists(self, target):
            self.hitlist = set()
            req = requests.get(self.listURL)
            if req.status_code == 200:
                lines = req.text.splitlines()
                for line in lines:
                    line = self.remove_ip_address(line)
                    if target == line:
                        self.hitlist.add(target)

    try:
        with open("./config/json_lookups/threat_lists/domainlists.json") as settings:
            blacklists = json.load(settings)

        blacklistObjs = [
            lookupLists(blacklist["name"], blacklist["category"], blacklist["listURL"])
            for blacklist in blacklists
        ]

        for listObj in blacklistObjs:
            listObj.domain_threat_lists(target)

        for listObj in blacklistObjs:
            if len(listObj.hitlist) != 0:
                print(
                    f"{bcolors.OKGREEN}[+] Domain found in {listObj.name} threat list{bcolors.ENDC}"
                )
                print(f"    [-] Category: {listObj.category}")
                print(f"    [-] List URL: {listObj.listURL}")
            else:
                print(
                    f"{bcolors.WARNING}[-] Domain not found in {listObj.name} threat list{bcolors.ENDC}"
                )
    except Exception:
        print(f"{bcolors.ERROR}[!] Unable to run domain threat lists{bcolors.ENDC}")


def hash_threat_lists(target):
    class lookupLists:
        def __init__(self, name, category, listURL):
            self.name = name
            self.category = category
            self.listURL = listURL

        def hash_threat_lists(self, target):
            self.hitlist = set()
            req = requests.get(self.listURL)
            if req.status_code == 200:
                lines = req.text.splitlines()
                for line in lines:
                    if target == line:
                        self.hitlist.add(target)

    try:
        with open("./config/json_lookups/threat_lists/hashlists.json") as settings:
            blacklists = json.load(settings)

        blacklistObjs = [
            lookupLists(blacklist["name"], blacklist["category"], blacklist["listURL"])
            for blacklist in blacklists
        ]

        for listObj in blacklistObjs:
            listObj.hash_threat_lists(target)

        for listObj in blacklistObjs:
            if len(listObj.hitlist) != 0:
                print(
                    f"{bcolors.OKGREEN}[+] Hash found in {listObj.name} threat list{bcolors.ENDC}"
                )
                print(f"    [-] Category: {listObj.category}")
                print(f"    [-] List URL: {listObj.listURL}")
            else:
                print(
                    f"{bcolors.WARNING}[-] Hash not found in {listObj.name} threat list{bcolors.ENDC}"
                )
    except Exception:
        print(f"{bcolors.ERROR}[!] Unable to run hash threat lists{bcolors.ENDC}")
