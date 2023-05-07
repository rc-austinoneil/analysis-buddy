import socbuddy
import re
import webbrowser
import socket
import requests
import haversine
from modules import osint
from ipwhois import IPWhois
from config import fontcolors, loadconfig
from shodan import Shodan

bcolors = fontcolors.bcolors()
configvars = loadconfig.load_buddy_config()


# Menu
def menu():
    socbuddy.title_bar("DNS and IP Tools")
    socbuddy.menu_item(0, "Return to main menu", "goback")
    socbuddy.menu_item(1, "Reverse DNS Lookup", "tool")
    socbuddy.menu_item(2, "DNS Lookup", "tool")
    socbuddy.menu_item(3, "WHOIS Lookup", "tool")
    socbuddy.menu_item(4, "IP Quality Score", "tool")
    socbuddy.menu_item(5, "GreyNoise.io", "tool")
    socbuddy.menu_item(6, "Shodan", "tool")
    socbuddy.menu_item(7, "Geo Compare IPs", "tool")
    socbuddy.menu_item(8, "TCP/UDP Port Lookup", "tool")
    socbuddy.menu_item(9, "Defang URLs & IPs", "tool")
    menu_switch(input(bcolors.INPUT + " ~> " + bcolors.ENDC))


def menu_switch(choice):
    if choice == "1":
        reverse_dns_lookup()
    if choice == "2":
        dns_lookup()
    if choice == "3":
        who_is()
    if choice == "4":
        ip_quality_score()
    if choice == "5":
        grey_noise()
    if choice == "6":
        run_shodan()
    if choice == "7":
        ip_quality_score_geo_compare()
    if choice == "8":
        tcp_udp_port_lookup()
    if choice == "9":
        defang()
    if choice == "0":
        socbuddy.main_menu()
    else:
        menu()


# Tools
def reverse_dns_lookup():
    try:
        socbuddy.title_bar("Reverse DNS Lookup")
        d = socbuddy.ask_for_user_input("Enter IP to check")
        s = socket.gethostbyaddr(d)
        output = {"Hostname": s[0], "Aliases": s[1], "IPs": s[2]}
        socbuddy.print_json(output)
        osint.osint_enrichment(output.get("Hostname"), True)
    except Exception:
        socbuddy.error_message("Hostname not found")
    reverse_dns_lookup() if socbuddy.ask_to_run_again() else menu()


def dns_lookup():
    try:
        socbuddy.title_bar("DNS Lookup")
        d = socbuddy.ask_for_user_input("Enter a FQDN to check")
        d = re.sub("http://", "", d)
        d = re.sub("https://", "", d)
        s = socket.gethostbyname(d)
        output = {"IP": s, "Domain": d}
        socbuddy.print_json(output)
        socbuddy.clipboard_copy(output.get("IP"))
        osint.osint_enrichment(output.get("IP"), True)
    except Exception:
        socbuddy.error_message("Domain not found")
    dns_lookup() if socbuddy.ask_to_run_again() else menu()


def who_is():
    try:
        socbuddy.title_bar("Whois")
        search = socbuddy.ask_for_user_input("Enter IP / Domain")

        if osint.get_target_type(search) == "fqdn":
            search = re.sub("http://", "", search)
            search = re.sub("https://", "", search)
            search = socket.gethostbyname(search)

        w = IPWhois(search)
        w = w.lookup()
        output = {
            "CIDR": str(w.get("nets")[0].get("cidr")),
            "Name": str(w.get("nets")[0].get("name")),
            "Handle": str(w.get("nets")[0].get("handle")),
            "Range": str(w.get("nets")[0].get("range")),
            "Registry": str(w.get("asn_registry")),
            "ASN": str(w.get("asn")),
            "ASN CIDR": str(w.get("asn_cidr")),
            "ASN Country": str(w.get("asn_country_code")),
            "ASN Date": str(w.get("asn_date")),
            "Descr": str(w.get("nets")[0].get("description")),
            "Country": str(w.get("nets")[0].get("country")),
            "State": str(w.get("nets")[0].get("state")),
            "City": str(w.get("nets")[0].get("city")),
            "Address": str(w.get("nets")[0].get("address")).replace("\n", ", "),
            "Post Code": str(w.get("nets")[0].get("postal_code")),
            "Abuse Emails": w.get("nets")[0].get("abuse_emails").split("\n"),
            "Tech Emails": w.get("nets")[0].get("tech_emails").split("\n"),
            "Created": str(w.get("nets")[0].get("created")),
            "Updated": str(w.get("nets")[0].get("updated")),
        }

        socbuddy.print_json(output)
        osint.osint_enrichment(w.get("query"), True)
    except Exception:
        socbuddy.error_message("Failed to run WHOIS lookup")
    who_is() if socbuddy.ask_to_run_again() else menu()


def ip_quality_score():
    try:
        if loadconfig.check_buddy_config("IPQS_API_KEY"):
            socbuddy.title_bar("IP Quality")
            ipqs_url = f"https://us.ipqualityscore.com/api/json/ip/{configvars.data['IPQS_API_KEY']}/"
            ip_address = socbuddy.ask_for_user_input("Enter an IP Address")
            socbuddy.info_message(osint.count_occurrences(ip_address), True)
            ipqs_params = {"strictness": 1, "ip": ip_address}
            response = requests.get(ipqs_url, params=ipqs_params)
            if response.status_code == 200:
                data = response.json()
                print("")
                check_if_residential(ip_address, data)
                check_if_mobile(ip_address, data)
                check_if_zscalar(ip_address, data)
                socbuddy.print_json(data)
                socbuddy.info_message(
                    f"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip_address}",
                    True,
                )
            osint.osint_enrichment(ip_address, True)

    except Exception as e:
        socbuddy.error_message("Failed to query IP Quality Score", str(e))
    ip_quality_score() if socbuddy.ask_to_run_again() else menu()


def grey_noise():
    try:
        if loadconfig.check_buddy_config("GREYNOISE_API_KEY"):
            socbuddy.title_bar("Greynoise")
            ip_address = socbuddy.ask_for_user_input("Enter an IP Address")
            socbuddy.info_message(osint.count_occurrences(ip_address), True)
            url = f"https://api.greynoise.io/v3/community/{ip_address}"
            headers = {"key": configvars.data["GREYNOISE_API_KEY"]}
            response = requests.request("GET", url, headers=headers)
            socbuddy.print_json(response.json())
            osint.osint_enrichment(ip_address, True)
    except Exception as e:
        socbuddy.error_message("Failed to query Greynoise", str(e))
    grey_noise() if socbuddy.ask_to_run_again() else menu()


def run_shodan():
    try:
        if loadconfig.check_buddy_config("SHODAN_API_KEY"):
            socbuddy.title_bar("Shodan")
            search = socbuddy.ask_for_user_input("Enter shodan search")
            socbuddy.info_message(osint.count_occurrences(search), True)
            inputtype = osint.get_target_type(search)
            sdan = Shodan(configvars.data["SHODAN_API_KEY"])

            if inputtype == "ipv4":
                output = sdan.host(search)
                if output:
                    output = [
                        {
                            "last_update": output.get("last_update"),
                            "ip_str": output.get("ip_str"),
                            "city": output.get("city"),
                            "asn": output.get("asn"),
                            "isp": output.get("isp"),
                            "country_name": output.get("country_name"),
                            "region_code": output.get("region_code"),
                            "os": output.get("os"),
                            "tags": output.get("tags"),
                            "ports": output.get("ports"),
                            "vulns": output.get("vulns"),
                            "domains": output.get("domains"),
                            "url": f"https://www.shodan.io/host/{output.get('ip_str')}",
                        }
                    ]
                    socbuddy.print_json(output)
                else:
                    socbuddy.error_message("No results found")
            else:
                output = sdan.search(search)
                if output:
                    printed_result = 0
                    for x in output["matches"]:
                        output_item = [
                            {
                                "last_update": x.get("last_update"),
                                "ip_str": x.get("ip_str"),
                                "city": x.get("city"),
                                "asn": x.get("asn"),
                                "isp": x.get("isp"),
                                "country_name": x.get("country_name"),
                                "region_code": x.get("region_code"),
                                "os": x.get("os"),
                                "tags": x.get("tags"),
                                "ports": x.get("ports"),
                                "domains": x.get("domains"),
                                "url": f"https://www.shodan.io/host/{x.get('ip_str')}",
                            }
                        ]
                        socbuddy.print_json(output_item)
                        printed_result += 1
                        if printed_result < len(output["matches"]):
                            socbuddy.next_result_message()
                else:
                    socbuddy.info_message("No results found")
    except Exception as e:
        socbuddy.error_message("Failed to query shodan", str(e))
    run_shodan() if socbuddy.ask_to_run_again() else menu()


def get_ip_quality_score_geo(ip_address):
    try:
        if loadconfig.check_buddy_config("IPQS_API_KEY"):
            ipqs_url = f"https://us.ipqualityscore.com/api/json/ip/{configvars.data['IPQS_API_KEY']}/"
            ipqs_params = {"strictness": 1, "ip": ip_address}
            response = requests.get(ipqs_url, params=ipqs_params)
            if response.status_code == 200:
                data = response.json()
                loc = (data["latitude"], data["longitude"])
            return loc, data
    except Exception as e:
        socbuddy.error_message("Failed to query IP Quality Score", str(e))
        return None


def check_if_mobile(ip_address, ipquality_data):
    if ipquality_data["mobile"] or ipquality_data["connection_type"] == "Mobile":
        print(bcolors.ERROR + f"{ip_address} a mobile IP address!" + bcolors.ENDC)
    else:
        print(bcolors.OKGREEN + f"{ip_address} not a mobile IP address." + bcolors.ENDC)


def check_if_zscalar(ip_address, ipquality_data):
    if ipquality_data["ISP"] == "Zscaler":
        print(bcolors.ERROR + f"{ip_address} is a Zscalar IP address!" + bcolors.ENDC)
    else:
        print(
            bcolors.OKGREEN
            + f"{ip_address} is not a Zscalar IP address."
            + bcolors.ENDC
        )


def check_if_residential(ip_address, ipquality_data):
    if ipquality_data["connection_type"] == "Residential":
        print(
            bcolors.OKGREEN
            + f"{ip_address} is a residential IP address."
            + bcolors.ENDC
        )
    else:
        print(
            bcolors.ERROR
            + f"{ip_address} is a {ipquality_data['connection_type']} IP address!"
            + bcolors.ENDC
        )


def ip_quality_score_geo_compare():
    try:
        if loadconfig.check_buddy_config("IPQS_API_KEY"):
            socbuddy.title_bar("Geo Compare IPs")
            # Input and processing
            ip_address1 = socbuddy.ask_for_user_input("Enter the first IP Address")
            ip_address2 = socbuddy.ask_for_user_input("Enter the second IP Address")
            loc1, data1 = get_ip_quality_score_geo(ip_address1)
            loc2, data2 = get_ip_quality_score_geo(ip_address2)
            distance = haversine.haversine(loc1, loc2, unit=haversine.Unit.MILES)

            # Output
            socbuddy.next_result_message(ip_address1)
            socbuddy.print_json(data1, False)
            socbuddy.next_result_message(ip_address2)
            socbuddy.print_json(data2, False)

            # Summary
            socbuddy.next_result_message("Geo IP Summary")
            socbuddy.info_message(
                f"Distance between the two IPs is {str(round(distance,2))} miles."
            )
            print("")
            print(
                f'{ip_address1} is located in {data1.get("country_code")}, {data1.get("region")}, {data1.get("city")} and the ISP is {data1.get("ISP")}'
            )
            socbuddy.info_message(osint.count_occurrences(ip_address1), False)
            check_if_residential(ip_address1, data1)
            check_if_mobile(ip_address1, data1)
            check_if_zscalar(ip_address1, data1)
            print("")
            print(
                f'{ip_address2} is located in {data2.get("country_code")}, {data2.get("region")}, {data2.get("city")} and the ISP is {data2.get("ISP")}'
            )
            socbuddy.info_message(osint.count_occurrences(ip_address2), False)
            check_if_residential(ip_address2, data2)
            check_if_mobile(ip_address2, data2)
            check_if_zscalar(ip_address2, data2)
            osint.osint_enrichment(ip_address1, True)
            osint.osint_enrichment(ip_address2, False)
    except Exception as e:
        socbuddy.error_message("Failed to run geo compare", str(e))
    ip_quality_score_geo_compare() if socbuddy.ask_to_run_again() else menu()


def tcp_udp_port_lookup():
    try:
        socbuddy.title_bar("TCP/UDP Port Lookup")
        port = socbuddy.ask_for_user_input("Enter a port number")
        url = f"https://www.speedguide.net/port.php?port={port}"
        socbuddy.info_message(f"Opening {url}")
        webbrowser.open(url)
    except Exception:
        socbuddy.error_message(f"Failed to open {url}")
    tcp_udp_port_lookup() if socbuddy.ask_to_run_again() else menu()


def defang():
    try:
        socbuddy.title_bar("Defang URLs & IPs")
        x = socbuddy.ask_for_user_input("Enter URL or IP")
        x = re.sub(r"\.", "[.]", x)
        x = re.sub("http://", "hxxp://", x)
        x = re.sub("https://", "hxxps://", x)
        output = {"defanged": x}
        socbuddy.print_json(output)
        socbuddy.clipboard_copy(output.get("defanged"))
    except Exception:
        socbuddy.error_message("Unable to defang URL or IP")
    defang() if socbuddy.ask_to_run_again() else menu()
