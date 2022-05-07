import requests
import time


head = '''[General]
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com
tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32
dns-server = 114.114.114.114, 223.5.5.5
ipv6 = false

[Rule]
'''

tail = '''GEOIP,CN,DIRECT
FINAL,PROXY

[Host]
localhost = 127.0.0.1

[URL Rewrite]
^http://(www.)?g.cn https://www.google.com 302
^http://(www.)?google.cn https://www.google.com 302
'''


def main():
    rule_names = ("direct-list",
                  "proxy-list",
                  "reject-list",
                  "apple-cn",
                  "google-cn",
                  "gfw",
                  "greatfire",
                  "win-spy",
                  "win-update",
                  "win-extra")
    # All data are domains NO IP is included

    reject_group = tuple(["reject-list"])
    proxy_group = ("proxy-list", "google-cn", "gfw", "greatfire")
    direct_group = ("direct-list", "apple-cn", "win-spy", "win-update", "win-extra")

    content_flawless = sorted(rule_names) == sorted(reject_group + proxy_group + direct_group)
    assert content_flawless

    rule_lists_dict = {}

    i = 0
    while i < len(rule_names):
        r = requests.get("https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/" + rule_names[i] + ".txt")
        # Currently, I have no idea how to deal with regexp rules.
        # Fortunately, there aren't many of them. So I just decided to skip them.
        # Update: URL-REGEX for regular expression
        items = [x.strip() for x in r.text.split("\n") if x != ""]
        rule_lists_dict[rule_names[i]] = items
        i += 1

    # Start constructing the actual file
    localtime = time.asctime(time.localtime(time.time()))

    content_to_write = ""
    content_to_write += "# Shadowrocket: " + str(localtime) + "\n"
    content_to_write += head

    REJECT = "REJECT"
    PROXY = "PROXY"
    DIRECT = "DIRECT"
    # Sequence: REJECT, DIRECT, PROXY, GEOIP CN, FINAL PROXY
    content_to_write += generate_rules(reject_group, REJECT, rule_lists_dict)
    content_to_write += generate_rules(direct_group, DIRECT, rule_lists_dict)
    content_to_write += generate_rules(proxy_group, PROXY, rule_lists_dict)
    content_to_write += tail

    with open("rocket_rules.conf", mode="w") as f:
        f.write(content_to_write)
        f.close()


def generate_rules(rule_group, rule_strategy, rule_lists_dict):
    DOMAIN = "DOMAIN"
    DOMAIN_SUFFIX = "DOMAIN-SUFFIX"
    URL_REGEX = "URL-REGEX"
    res = ""
    for rule_name in rule_group:
        for domain in rule_lists_dict[rule_name]:
            if domain.startswith("full:"):
                res += construct_single_line_rule(DOMAIN, domain[5:], rule_strategy)
            elif domain.startswith("regexp:"):
                res += construct_single_line_rule(URL_REGEX, domain[7:], rule_strategy)
            else:
                res += construct_single_line_rule(DOMAIN_SUFFIX, domain, rule_strategy)
    return res


def construct_single_line_rule(match_strategy, domain, rule_strategy):
    return match_strategy + "," + domain + "," + rule_strategy + "\n"


if __name__ == '__main__':
    main()
