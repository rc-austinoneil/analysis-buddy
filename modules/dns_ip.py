import analysisbuddy
import re
import webbrowser
import socket
import requests
import haversine
import ipaddress
from modules import osint
from ipwhois import IPWhois
from config import fontcolors, loadconfig
from shodan import Shodan

bcolors = fontcolors.bcolors()
configvars = loadconfig.load_buddy_config()


# Menu
def menu():
    analysisbuddy.title_bar("DNS & IP Tools")
    analysisbuddy.menu_item(0, "Return to main menu", "goback")
    analysisbuddy.menu_item(1, "Reverse DNS Lookup", "tool")
    analysisbuddy.menu_item(2, "DNS Lookup", "tool")
    analysisbuddy.menu_item(3, "WHOIS Lookup", "tool")
    analysisbuddy.menu_item(4, "IP Quality Score", "tool")
    analysisbuddy.menu_item(5, "GreyNoise.io", "tool")
    analysisbuddy.menu_item(6, "Shodan", "tool")
    analysisbuddy.menu_item(7, "Geo Compare IPs", "tool")
    analysisbuddy.menu_item(8, "TCP/UDP Port Lookup", "tool")
    analysisbuddy.menu_item(9, "Defang URLs & IPs", "tool")
    analysisbuddy.menu_item(10, "Tweetfeed IOC Lookup", "tool")
    analysisbuddy.menu_item(11, "Subnet Calculator", "tool")
    menu_switch(input(f"{bcolors.INPUT} ~> {bcolors.ENDC}"))


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
    if choice == "10":
        osint.tweetfeed_live()
        osint.tweetfeed_live() if analysisbuddy.ask_to_run_again() else menu()
    if choice == "11":
        subnet_calc()
    if choice == "0":
        analysisbuddy.main_menu()
    else:
        menu()


# Tools
def reverse_dns_lookup():
    """
    This function will query DNS for information about an IP address
    """
    try:
        analysisbuddy.title_bar("Reverse DNS Lookup")
        domain = analysisbuddy.ask_for_user_input("Enter IP to check")
        analysisbuddy.info_message(osint.update_historical_osint_data(domain), True)
        results = socket.gethostbyaddr(domain)
        output = {"Hostname": results[0], "Aliases": results[1], "IPs": results[2]}
        analysisbuddy.print_json(output)
        osint.run_osint_no_menu(output.get("Hostname"))
    except Exception as e:
        analysisbuddy.error_message("Hostname not found", str(e))
    reverse_dns_lookup() if analysisbuddy.ask_to_run_again() else menu()


def dns_lookup():
    """
    This function will query DNS for information about a domain
    """
    try:
        analysisbuddy.title_bar("DNS Lookup")
        domain = analysisbuddy.ask_for_user_input("Enter a FQDN to check")
        analysisbuddy.info_message(osint.update_historical_osint_data(domain), True)
        domain = re.sub("http://", "", domain)
        domain = re.sub("https://", "", domain)
        output = {"IP": socket.gethostbyname(domain), "Domain": domain}
        analysisbuddy.print_json(output)
        analysisbuddy.clipboard_copy(output.get("IP"))
        osint.run_osint_no_menu(output.get("IP"))
    except Exception as e:
        analysisbuddy.error_message("Domain not found", str(e))
    dns_lookup() if analysisbuddy.ask_to_run_again() else menu()


def who_is():
    """
    This function will query IPWhois for information about an IP address
    """
    try:
        analysisbuddy.title_bar("Whois")
        search = analysisbuddy.ask_for_user_input("Enter IP / Domain")
        analysisbuddy.info_message(osint.update_historical_osint_data(search), True)
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

        analysisbuddy.print_json(output)
        osint.run_osint_no_menu(w.get("query"))
    except Exception as e:
        analysisbuddy.error_message("Failed to run WHOIS lookup", str(e))
    who_is() if analysisbuddy.ask_to_run_again() else menu()


def ip_quality_score():
    """
    This function will query IP Quality Score for information about an IP address
    """
    try:
        if loadconfig.check_buddy_config("IPQS_API_KEY"):
            analysisbuddy.title_bar("IP Quality")
            ip_address = analysisbuddy.ask_for_user_input("Enter an IP Address")
            analysisbuddy.info_message(
                osint.update_historical_osint_data(ip_address), True
            )
            response = requests.get(
                f"https://us.ipqualityscore.com/api/json/ip/{configvars.data['IPQS_API_KEY']}/",
                params={"strictness": 1, "ip": ip_address},
            )
            if response.status_code == 200:
                data = response.json()
                print("")
                check_if_residential(ip_address, data)
                check_if_mobile(ip_address, data)
                check_if_zscalar(ip_address, data)
                analysisbuddy.print_json(data)
                analysisbuddy.info_message(
                    f"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip_address}",
                    True,
                )
            osint.run_osint_no_menu(ip_address)

    except Exception as e:
        analysisbuddy.error_message("Failed to query IP Quality Score", str(e))
    ip_quality_score() if analysisbuddy.ask_to_run_again() else menu()


def grey_noise():
    """
    This function will query Greynoise for information about an IP address
    """
    try:
        if loadconfig.check_buddy_config("GREYNOISE_API_KEY"):
            analysisbuddy.title_bar("Greynoise")
            ip_address = analysisbuddy.ask_for_user_input("Enter an IP Address")
            analysisbuddy.info_message(
                osint.update_historical_osint_data(ip_address), True
            )
            response = requests.get(
                f"https://api.greynoise.io/v3/community/{ip_address}",
                headers={"key": configvars.data["GREYNOISE_API_KEY"]},
            )
            analysisbuddy.print_json(response.json())
            osint.run_osint_no_menu(ip_address)
    except Exception as e:
        analysisbuddy.error_message("Failed to query Greynoise", str(e))
    grey_noise() if analysisbuddy.ask_to_run_again() else menu()


def run_shodan():
    """
    This function will query Shodan for information about an IP address or domain
    """
    try:
        if loadconfig.check_buddy_config("SHODAN_API_KEY"):
            analysisbuddy.title_bar("Shodan")
            search = analysisbuddy.ask_for_user_input("Enter shodan search")
            analysisbuddy.info_message(osint.update_historical_osint_data(search), True)
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
                    analysisbuddy.print_json(output)
                else:
                    analysisbuddy.error_message("No results found")
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
                        analysisbuddy.print_json(output_item)
                        printed_result += 1
                        if printed_result < len(output["matches"]):
                            analysisbuddy.next_result_message()
                else:
                    analysisbuddy.info_message("No results found")
    except Exception as e:
        analysisbuddy.error_message("Failed to query shodan", str(e))
    run_shodan() if analysisbuddy.ask_to_run_again() else menu()


def get_ip_quality_score_geo(ip_address):
    """
    This function will use IP Quality Score to get the geo location of an IP address
    """
    try:
        if loadconfig.check_buddy_config("IPQS_API_KEY"):
            response = requests.get(
                f"https://us.ipqualityscore.com/api/json/ip/{configvars.data['IPQS_API_KEY']}/",
                params={"strictness": 1, "ip": ip_address},
            )
            if response.status_code == 200:
                data = response.json()
                loc = (data["latitude"], data["longitude"])
            return loc, data
    except Exception as e:
        analysisbuddy.error_message("Failed to query IP Quality Score", str(e))
        return None


def check_if_mobile(ip_address, ipquality_data):
    """
    This function will take the IP Quality Score data and determine if the IP address is a mobile IP address
    """
    if ipquality_data["mobile"] or ipquality_data["connection_type"] == "Mobile":
        print(f"{bcolors.ERROR}{ip_address} a mobile IP address!{bcolors.ENDC}")
    else:
        print(f"{bcolors.OKGREEN}{ip_address} not a mobile IP address.{bcolors.ENDC}")


def check_if_zscalar(ip_address, ipquality_data):
    """
    This function will take the IP Quality Score data and determine if the IP address is a Zscalar IP address
    """
    if ipquality_data["ISP"] == "Zscaler":
        print(f"{bcolors.ERROR}{ip_address} is a Zscalar IP address!{bcolors.ENDC}")
    else:
        print(
            f"{bcolors.OKGREEN}{ip_address} is not a Zscalar IP address.{bcolors.ENDC}"
        )


def check_if_residential(ip_address, ipquality_data):
    """
    This function will take the IP Quality Score data and determine if the IP address is residential
    """
    if ipquality_data["connection_type"] == "Residential":
        print(
            f"{bcolors.OKGREEN}{ip_address} is a residential IP address.{bcolors.ENDC}"
        )
    else:
        print(
            f"{bcolors.ERROR}{ip_address} is a {ipquality_data['connection_type']} IP address!{bcolors.ENDC}"
        )


def ip_quality_score_geo_compare():
    """
    This function will use IP Quality Score to compare two IP addresses and determine the distance between them
    """
    try:
        if loadconfig.check_buddy_config("IPQS_API_KEY"):
            analysisbuddy.title_bar("Geo Compare IPs")
            # Input and processing
            ip_address1 = analysisbuddy.ask_for_user_input("Enter the first IP Address")
            ip_address2 = analysisbuddy.ask_for_user_input(
                "Enter the second IP Address"
            )
            loc1, data1 = get_ip_quality_score_geo(ip_address1)
            loc2, data2 = get_ip_quality_score_geo(ip_address2)
            distance = haversine.haversine(loc1, loc2, unit=haversine.Unit.MILES)

            # Output
            analysisbuddy.next_result_message(ip_address1)
            analysisbuddy.print_json(data1, False)
            analysisbuddy.next_result_message(ip_address2)
            analysisbuddy.print_json(data2, False)

            # Summary
            analysisbuddy.next_result_message("Geo IP Summary")
            analysisbuddy.info_message(
                f"Distance between the two IPs is {str(round(distance,2))} miles."
            )
            print("")
            print(
                f'{ip_address1} is located in {data1.get("country_code")}, {data1.get("region")}, {data1.get("city")} and the ISP is {data1.get("ISP")}'
            )
            analysisbuddy.info_message(
                osint.update_historical_osint_data(ip_address1), False
            )
            check_if_residential(ip_address1, data1)
            check_if_mobile(ip_address1, data1)
            check_if_zscalar(ip_address1, data1)
            print("")
            print(
                f'{ip_address2} is located in {data2.get("country_code")}, {data2.get("region")}, {data2.get("city")} and the ISP is {data2.get("ISP")}'
            )
            analysisbuddy.info_message(
                osint.update_historical_osint_data(ip_address2), False
            )
            check_if_residential(ip_address2, data2)
            check_if_mobile(ip_address2, data2)
            check_if_zscalar(ip_address2, data2)
            print("")
            osint.run_osint_no_menu(ip_address1)
            osint.run_osint_no_menu(ip_address2)
    except Exception as e:
        analysisbuddy.error_message("Failed to run geo compare", str(e))
    ip_quality_score_geo_compare() if analysisbuddy.ask_to_run_again() else menu()


def tcp_udp_port_lookup():
    """
    This function will open a web browser to speedguide.net to lookup a TCP or UDP port
    """
    try:
        analysisbuddy.title_bar("TCP/UDP Port Lookup")
        port = analysisbuddy.ask_for_user_input("Enter a port number")
        url = f"https://www.speedguide.net/port.php?port={port}"
        analysisbuddy.info_message(f"Opening {url}")
        webbrowser.open(url)
    except Exception as e:
        analysisbuddy.error_message(f"Failed to open {url}", str(e))
    tcp_udp_port_lookup() if analysisbuddy.ask_to_run_again() else menu()


def defang():
    """
    This function will defang a URL or IP address so you can safely copy and paste it into a browser or email
    """
    try:
        analysisbuddy.title_bar("Defang URLs & IPs")
        input_item = analysisbuddy.ask_for_user_input("Enter URL or IP")
        input_item = re.sub(r"\.", "[.]", input_item)
        input_item = re.sub("http://", "hxxp://", input_item)
        input_item = re.sub("https://", "hxxps://", input_item)
        output = {"defanged": input_item}
        analysisbuddy.print_json(output)
        analysisbuddy.clipboard_copy(output.get("defanged"))
    except Exception as e:
        analysisbuddy.error_message("Unable to defang URL or IP", str(e))
    defang() if analysisbuddy.ask_to_run_again() else menu()


def subnet_calc():
    try:
        analysisbuddy.title_bar("Subnet Calculator")
        IP_Addr = ipaddress.ip_interface(
            analysisbuddy.ask_for_user_input("Enter IP address in IP/Mask Format")
        )

        Net_Addr = IP_Addr.network
        pref_len = IP_Addr.with_prefixlen
        Mask = IP_Addr.with_netmask
        wildcard = IP_Addr.hostmask
        broadcast_address = Net_Addr.broadcast_address

        output = {
            "Network Address": str(Net_Addr).split("/")[0],
            "Broadcast Address": broadcast_address,
            "CIDR Notation": pref_len.split("/")[1],
            "Subnet Mask": Mask.split("/")[1],
            "Wildcard Mask": wildcard,
            "First IP": list(Net_Addr.hosts())[0],
            "Last IP": list(Net_Addr.hosts())[-1],
        }

        analysisbuddy.print_json(output)
    except Exception as e:
        analysisbuddy.error_message("Failed to run subnet calculator", str(e))
    subnet_calc() if analysisbuddy.ask_to_run_again() else menu()
