import analysisbuddy
import subprocess
import requests
import ipaddress
import re
import json
import datetime
from config import fontcolors, loadconfig

bcolors = fontcolors.bcolors()
configvars = loadconfig.load_buddy_config()
machinaeconfig = loadconfig.load_machinae_config()


# Tools
def get_target_type(target):
    """
    This function checks the target to see if it is an IP address, hash, URL,
    email address, SSL fingerprint, or MAC address. If it is none of those,
    it assumes it is a domain name.
    """
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
        return "hash"
    elif re.match("^[a-f0-9]{64}$", target, re.I):
        # SHA-256
        return "hash"
    elif re.match("^[a-f0-9]{128}$", target, re.I):
        # SHA-512
        return "hash"

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

    # FQDN
    elif re.match(
        "(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)",
        target,
        re.I,
    ):
        return "fqdn"

    return None


def update_historical_osint_data(target):
    """
    This function creates a file for storing the historical OSINT data. It then
    reads the data into a variable, checks to see if the target has been
    scanned before, and if it has, it appends the date to the file. Finally,
    it outputs the number of times the target has been scanned and the date
    of the last scan.
    """
    historical_osint_data_file = "./config/output/osint_data.json"

    try:
        with open(historical_osint_data_file, "r") as f:
            historical_osint_data = json.load(f)
    except Exception:
        historical_osint_data = []

    last_scan_date = None
    for entry in reversed(historical_osint_data):
        if entry.get("target") == target:
            last_scan_date = entry.get("date")
            break

    count = sum(1 for entry in historical_osint_data if entry.get("target") == target)

    try:
        data = {
            "target": target,
            "date": datetime.datetime.now().strftime("%m-%d-%Y %H:%M:%S"),
        }
        with open(historical_osint_data_file, "w+") as f:
            historical_osint_data.append(data)
            json.dump(historical_osint_data, f)
    except Exception as e:
        analysisbuddy.error_message("Failed to update historical OSINT data", str(e))

    if count == 0:
        return f"{target} has not been scanned before."
    else:
        return f"{target} has been scanned {count} times, the last scan was: {last_scan_date}"


def run_osint():
    """
    This function will give a titlebar, ask the user for a target, and then
    run the Machinae against the target, with secondary osint tools.
    """
    try:
        analysisbuddy.title_bar("Machinae OSINT")
        target = analysisbuddy.ask_for_user_input("Enter a target")
        target = target.replace("[.]", ".")
        target_type = get_target_type(target)
        analysisbuddy.info_message(
            f"Running OSINT search for {target_type}: {target}", True
        )
        if target_type:
            analysisbuddy.info_message(update_historical_osint_data(target), False)
            subprocess.call(
                [
                    "machinae",
                    "-c",
                    machinaeconfig,
                    "-s",
                    "default",
                    "-O",
                    target_type,
                    target,
                ]
            )
            run_secondary_osint(target)
        else:
            analysisbuddy.error_message("Invalid target. Please try again.")
        run_osint() if analysisbuddy.ask_to_run_again() else analysisbuddy.main_menu()
    except KeyboardInterrupt:
        analysisbuddy.error_message("OSINT search canceled.")
    except Exception as e:
        analysisbuddy.error_message("Failed to run OSINT search.", str(e))
        input(bcolors.INPUT + "Press enter to return to the main menu" + bcolors.ENDC)
        analysisbuddy.main_menu()


def run_osint_no_menu(target):
    """
    This function asks the user if they want to run additional OSINT and then
    run the Machinae against the target, with secondary osint tools.
    """
    try:
        print("")
        if (
            input(
                f"{bcolors.INPUT}Run {target} against additional OSINT enrichment? (Y/N): {bcolors.ENDC}"
            ).upper()
            == "Y"
        ):
            target = target.replace("[.]", ".")
            target_type = get_target_type(target)
            if target_type:
                update_historical_osint_data(target)
                subprocess.call(
                    [
                        "machinae",
                        "-c",
                        machinaeconfig,
                        "-s",
                        "default",
                        "-O",
                        target_type,
                        target,
                    ]
                )
                run_secondary_osint(target)
            else:
                analysisbuddy.error_message("Invalid target. Please try again.")
        else:
            return
    except KeyboardInterrupt:
        analysisbuddy.error_message("OSINT search canceled.")
    except Exception as e:
        analysisbuddy.error_message("Failed to run OSINT search.", str(e))


def run_secondary_osint(target):
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

    tweetfeed_live(target)

    if links:
        print(f"{bcolors.OKGREEN}[+] OSINT Links{bcolors.ENDC}")
        for link in links:
            print(f"    [-] {link}")


def tor_list(target):
    """
    This function checks the target against the TOR exit node list and outputs
    whether or not the target is a TOR exit node.
    """
    try:
        tor_url = "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"
        response = requests.get(tor_url)
        if response.status_code == 200:
            print(f"{bcolors.OKGREEN}[+] TOR Exit Node Report{bcolors.ENDC}")
            tor_endpoint_list = response.text.split("\n")
            count = 0
            for ip_address in tor_endpoint_list:
                if target == ip_address:
                    print(f"    [-] {ip_address} is a TOR Exit Node")
                    count = count + 1
            if count == 0:
                print(f"    [-] {target} is NOT a TOR Exit Node")
        else:
            raise Exception(f"Invalid response {response.status_code}")
    except Exception:
        print(f"{bcolors.ERROR}[!] Unable to check against TOR list{bcolors.ENDC}")


def abuse_ipdb(target):
    """
    This function checks the target against the AbuseIPDB and outputs the
    Abuse Confidence Score, the number of reports, and the last report date.
    """
    try:
        if loadconfig.check_buddy_config("AB_API_KEY"):
            response = requests.request(
                method="GET",
                url="https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Accept": "application/json",
                    "Key": configvars.data["AB_API_KEY"],
                },
                params={"ipAddress": target, "maxAgeInDays": "180"},
            )

            if response.status_code == 200:
                req = response.json()
                # fmt: off
                print(f"{bcolors.OKGREEN}[+] ABUSEIPDB Report{bcolors.ENDC}")
                print(f"    [-] IP:          {req.get('data', {}).get('ipAddress')}")
                print(f"    [-] Reports:     {req.get('data', {}).get('totalReports')}")
                print(f"    [-] Abuse Score: {req.get('data', {}).get('abuseConfidenceScore')}%")
                print(f"    [-] Last Report: {req.get('data', {}).get('lastReportedAt')}")
                # fmt: on
            else:
                raise Exception(f"Invalid response {response.status_code}")
        else:
            raise Exception("Invalid API Key")
    except Exception:
        print(f"{bcolors.ERROR}[!] Unable to run ABUSE IPDB{bcolors.ENDC}")


def ip_threat_lists(target):
    """
    This function check the target against the IP threat lists
    located at ./config/json_lookups/threat_lists/iplists.json
    and outputs the threat list name, category, age, description,
    and URL.
    """

    class lookupLists:
        def __init__(self, name, desc, category, listURL, period):
            self.name = name
            self.desc = desc
            self.category = category
            self.listURL = listURL
            self.period = period

        def search_threat_lists(self, target):
            self.hitlist = set()
            req = requests.get(self.listURL)
            if req.status_code == 200:
                lines = req.text.splitlines()
                for line in lines:
                    if target == line:
                        self.hitlist.add(target)

        def print_output(self):
            print(
                f"{bcolors.OKGREEN}[+] IP found in {listObj.name} threat list{bcolors.ENDC}"
            )
            print(f"    [-] Category: {listObj.category}")
            print(f"    [-] List Age: {listObj.period}")
            print(f"    [-] List Description: {listObj.desc}")
            print(f"    [-] List URL: {listObj.listURL}")

    try:
        with open("./config/json_lookups/threat_lists/iplists.json") as threat_list:
            threat_list = json.load(threat_list)

        threatlistObjs = []
        for ip_address in threat_list:
            threatlistObjs.append(
                lookupLists(
                    ip_address["name"],
                    ip_address["desc"],
                    ip_address["category"],
                    ip_address["listURL"],
                    ip_address["period"],
                )
            )

        for listObj in threatlistObjs:
            listObj.search_threat_lists(target)

        for listObj in threatlistObjs:
            if len(listObj.hitlist) != 0:
                listObj.print_output()
            else:
                print(
                    f"{bcolors.WARNING}[-] IP not found in {listObj.name} threat list{bcolors.ENDC}"
                )

    except Exception:
        print(f"{bcolors.ERROR}[!] Unable to run IP threat lists{bcolors.ENDC}")


def domain_threat_lists(target):
    """
    This function check the target against the Domain threat lists
    located at ./config/json_lookups/threat_lists/domainlists.json
    and outputs the threat list name, category, and URL.
    """

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

        def search_threat_lists(self, target):
            self.hitlist = set()
            req = requests.get(self.listURL)
            if req.status_code == 200:
                lines = req.text.splitlines()
                for line in lines:
                    line = self.remove_ip_address(line)
                    if target == line:
                        self.hitlist.add(target)

        def print_output(self):
            print(
                f"{bcolors.OKGREEN}[+] Domain found in {listObj.name} threat list{bcolors.ENDC}"
            )
            print(f"    [-] Category: {listObj.category}")
            print(f"    [-] List URL: {listObj.listURL}")

    try:
        with open("./config/json_lookups/threat_lists/domainlists.json") as threat_list:
            threat_list = json.load(threat_list)

        threatlistObjs = []
        for domain in threat_list:
            threatlistObjs.append(
                lookupLists(domain["name"], domain["category"], domain["listURL"])
            )

        for listObj in threatlistObjs:
            listObj.search_threat_lists(target)

        for listObj in threatlistObjs:
            if len(listObj.hitlist) != 0:
                listObj.print_output()
            else:
                print(
                    f"{bcolors.WARNING}[-] Domain not found in {listObj.name} threat list{bcolors.ENDC}"
                )
    except Exception:
        print(f"{bcolors.ERROR}[!] Unable to run domain threat lists{bcolors.ENDC}")


def hash_threat_lists(target):
    """
    This function check the target against the hash threat lists
    located at ./config/json_lookups/threat_lists/hashlists.json
    and outputs the threat list name, category, and URL.
    """

    class lookupLists:
        def __init__(self, name, category, listURL):
            self.name = name
            self.category = category
            self.listURL = listURL

        def search_threat_lists(self, target):
            self.hitlist = set()
            req = requests.get(self.listURL)
            if req.status_code == 200:
                lines = req.text.splitlines()
                for line in lines:
                    if target == line:
                        self.hitlist.add(target)

        def print_output(self):
            print(
                f"{bcolors.OKGREEN}[+] Hash found in {listObj.name} threat list{bcolors.ENDC}"
            )
            print(f"    [-] Category: {listObj.category}")
            print(f"    [-] List URL: {listObj.listURL}")

    try:
        with open("./config/json_lookups/threat_lists/hashlists.json") as threat_list:
            threat_list = json.load(threat_list)

        threatlistObjs = []
        for hash_item in threat_list:
            threatlistObjs.append(
                lookupLists(
                    hash_item["name"], hash_item["category"], hash_item["listURL"]
                )
            )

        for listObj in threatlistObjs:
            listObj.search_threat_lists(target)

        for listObj in threatlistObjs:
            if len(listObj.hitlist) != 0:
                listObj.print_output()
            else:
                print(
                    f"{bcolors.WARNING}[-] Hash not found in {listObj.name} threat list{bcolors.ENDC}"
                )
    except Exception:
        print(f"{bcolors.ERROR}[!] Unable to run hash threat lists{bcolors.ENDC}")


def tweetfeed_live(target=None):
    """
    This function checks the target against the Tweetfeed.live API
    and outputs the date, user, value, tweet, and tags.
    """
    running_as_secondary_osint = True
    time = "month"

    def query_api(url):
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return response.json()
        except Exception:
            analysisbuddy.error_message("Failed to query the Tweetfeed.live API")

    def print_secondary_osint(api_type, results, domain_or_url):
        count = 0
        if domain_or_url:
            for dic in results:
                for key in dic:
                    if target in key.get("value"):
                        count += 1
                        # fmt: off
                        print(f"{bcolors.OKGREEN}[+] {api_type} found in Tweetfeed.live data{bcolors.ENDC}")
                        print(f"    [-] Date:  {key.get('date')}")
                        print(f"    [-] User:  {key.get('user')}")
                        print(f"    [-] Value: {key.get('value')}")
                        print(f"    [-] Tweet: {key.get('tweet')}")
                        print(f"    [-] Tags:  {key.get('tags')}")
                        # fmt: on
        else:
            for item in results:
                if target in item.get("value"):
                    count += 1
                    # fmt: off
                    print(f"{bcolors.OKGREEN}[+] {api_type} found in Tweetfeed.live data{bcolors.ENDC}")
                    print(f"    [-] Date:  {item.get('date')}")
                    print(f"    [-] User:  {item.get('user')}")
                    print(f"    [-] Value: {item.get('value')}")
                    print(f"    [-] Tweet: {item.get('tweet')}")
                    print(f"    [-] Tags:  {item.get('tags')}")
                    # fmt: on
        if count == 0:
            print(
                f"{bcolors.WARNING}[-] {api_type} not found in Tweetfeed.live data{bcolors.ENDC}"
            )

    def print_results(results, domain_or_url):
        analysisbuddy.info_message(update_historical_osint_data(target), True)
        count = 0
        if domain_or_url:
            for dic in results:
                for key in dic:
                    if target in key.get("value"):
                        count += 1
                        analysisbuddy.print_json(key)
        else:
            for item in results:
                if target in item.get("value"):
                    count += 1
                    analysisbuddy.print_json(item)
        if count == 0:
            analysisbuddy.error_message(f"{target} not found in Tweetfeed.live data")

    if not target:
        analysisbuddy.title_bar("TweetFeed.live")
        target = analysisbuddy.ask_for_user_input("Enter an IP, domain, or hash")
        time = analysisbuddy.ask_for_user_input(
            "How long would you like to search back? (today, week, month, year)"
        )
        running_as_secondary_osint = False

    api_type = get_target_type(target)
    domain_or_url = False

    if api_type == "ipv4":
        api_type = "IP"
        results = query_api(f"https://api.tweetfeed.live/v1/{time}/ip")
    elif api_type == "fqdn" or api_type == "url":
        api_type = "Domain"
        results = []
        results.append(query_api(f"https://api.tweetfeed.live/v1/{time}/domain"))
        results.append(query_api(f"https://api.tweetfeed.live/v1/{time}/url"))
        domain_or_url = True
    elif api_type == "hash":
        api_type = "MD5"
        results = query_api(f"https://api.tweetfeed.live/v1/{time}/md5")
    elif api_type == "hash.sha256":
        api_type = "Sha256"
        results = query_api(f"https://api.tweetfeed.live/v1/{time}/sha256")
    else:
        results = None

    if results:
        if running_as_secondary_osint:
            print_secondary_osint(api_type, results, domain_or_url)
        else:
            print_results(results, domain_or_url)
