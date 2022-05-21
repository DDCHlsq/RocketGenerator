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

tail_first_half = '''GEOIP,CN,DIRECT
FINAL,PROXY

[Host]
localhost = 127.0.0.1

[URL Rewrite]
^http://(www.)?g.cn https://www.google.com 302
^http://(www.)?google.cn https://www.google.com 302

[MITM]
hostname = '''

tail_second_half = '''
ca-passphrase = Shadowrocket
ca-p12 = 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
enable = false
'''

mitm_domains = []

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
    content_to_write += tail_first_half + ", ".join(mitm_domains) + tail_second_half

    with open("rocket_rules.conf", mode="w") as f:
        f.write(content_to_write)
        f.close()


def generate_rules(rule_group, rule_strategy, rule_lists_dict):
    DOMAIN = "DOMAIN"
    DOMAIN_SUFFIX = "DOMAIN-SUFFIX"
    URL_REGEX = "URL-REGEX"
    REG_HTTP = "(https?:\\/\\/)?"
    REG_START = "^"
    REG_END = "$"
    REG_PORT_SLASH = "(:[0-9]+)?(\\/.*)*\\/?"
    res = ""
    for rule_name in rule_group:
        for domain in rule_lists_dict[rule_name]:
            if domain.startswith("full:"):
                res += construct_single_line_rule(DOMAIN, domain[5:], rule_strategy)
            elif domain.startswith("regexp:"):
                regex = domain[7:]
                split_arr = regex.split("\\.")
                domain_wildcard = ["*"]
                if "[" not in split_arr[-2] and \
                        "apple" not in regex and \
                        "icloud" not in regex and \
                        "mzstatic" not in regex:
                    domain_wildcard = ["*"] + split_arr[-2:len(split_arr)]
                if domain_wildcard[-1][-1] == REG_END:
                    domain_wildcard[-1] = domain_wildcard[-1][:-1]
                if len(domain_wildcard) > 1:
                    new_comer = ".".join(domain_wildcard)
                    if new_comer not in mitm_domains:
                        mitm_domains.append(new_comer)
                if regex[0] == REG_START:
                    regex = regex[1:]
                if regex[-1] == REG_END:
                    regex = regex[:-1]
                regex = REG_START + REG_HTTP + regex + REG_PORT_SLASH + REG_END
                res += construct_single_line_rule(URL_REGEX, regex, rule_strategy)
            else:
                res += construct_single_line_rule(DOMAIN_SUFFIX, domain, rule_strategy)
    return res


def construct_single_line_rule(match_strategy, domain, rule_strategy):
    return match_strategy + "," + domain + "," + rule_strategy + "\n"


if __name__ == '__main__':
    main()
