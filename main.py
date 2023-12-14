import requests
import time

COMMA = ","
REJECT = "REJECT"
PROXY = "PROXY"
DIRECT = "DIRECT"


def main():
    private_lines = construct_rule_lines("private", DIRECT, None)
    reject_lines = construct_rule_lines("reject", REJECT, None)
    icloud_lines = construct_rule_lines("icloud", DIRECT, None)
    apple_lines = construct_rule_lines("apple", DIRECT, None)
    google_lines = construct_rule_lines("google", PROXY, None)
    proxy_lines = construct_rule_lines("proxy", PROXY, "force-remote-dns")
    direct_lines = construct_rule_lines("direct", DIRECT, None)
    telegramcidr_lines = construct_rule_lines("telegramcidr", PROXY, None)
    cncidr_lines = construct_rule_lines("cncidr", DIRECT, None)

    rocket_rules = f'''
# Generated at {str(time.asctime(time.localtime(time.time())))}
[General]
# 默认关闭 ipv6 支持，如果需要请手动开启
ipv6 = false
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, e.crashlytics.com, captive.apple.com, sequoia.apple.com, seed-sequoia.siri.apple.com
bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,255.255.255.255/32
dns-server = https://1.12.12.12/dns-query, https://223.5.5.5/dns-query

[Rule]
PROCESS-NAME,v2ray,DIRECT
PROCESS-NAME,xray,DIRECT
PROCESS-NAME,clash,DIRECT
PROCESS-NAME,naive,DIRECT
PROCESS-NAME,trojan,DIRECT
PROCESS-NAME,trojan-go,DIRECT
PROCESS-NAME,ss-local,DIRECT
PROCESS-NAME,privoxy,DIRECT
PROCESS-NAME,leaf,DIRECT
PROCESS-NAME,Thunder,DIRECT
PROCESS-NAME,DownloadService,DIRECT
PROCESS-NAME,qBittorrent,DIRECT
PROCESS-NAME,Transmission,DIRECT
PROCESS-NAME,fdm,DIRECT
PROCESS-NAME,aria2c,DIRECT
PROCESS-NAME,Folx,DIRECT
PROCESS-NAME,NetTransport,DIRECT
PROCESS-NAME,uTorrent,DIRECT
PROCESS-NAME,WebTorrent,DIRECT
{private_lines}
{reject_lines}
RULE-SET,SYSTEM,DIRECT
{icloud_lines}
{apple_lines}
{google_lines}
{proxy_lines}
{direct_lines}
{telegramcidr_lines}
{cncidr_lines}
RULE-SET,LAN,DIRECT
FINAL,PROXY,dns-failed

[URL Rewrite]
^https?://(www.)?(g|google)\.cn https://www.google.com 302

[MITM]
hostname = *.google.cn,*.googlevideo.com
    '''

    with open("rocket_rules.conf", mode="w") as f:
        f.write(rocket_rules)
        f.close()


def construct_rule_lines(rule_name, rule_route, ext_info):
    # proxies = {
    #     'http': 'http://127.0.0.1:7890',
    #     'https': 'http://127.0.0.1:7890',
    # }
    # r = requests.get(f"https://cdn.jsdelivr.net/gh/Loyalsoldier/surge-rules@release/ruleset/{rule_name}.txt", proxies=proxies)
    r = requests.get(f"https://cdn.jsdelivr.net/gh/Loyalsoldier/surge-rules@release/ruleset/{rule_name}.txt")
    lines = [x.strip() for x in r.text.split("\n") if x != ""]
    line_tail = ""
    if ext_info:
        line_tail = COMMA + ext_info
    for i in range(len(lines)):
        lines[i] = lines[i] + COMMA + rule_route + line_tail
    return "\n".join(lines)


if __name__ == '__main__':
    main()
