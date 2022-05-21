# RocketGenerator
一键生成小火箭分流策略文件。

本脚本基于 [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat)

由于 Loyalsoldier 没有现成的小火箭分流方案，所以本脚本通过其上述项目的分流策略转换为小火箭策略。

05-07-2022 Update: 现在已经可以正常处理正则表达式规则。（仅 HTTP 协议）

05-21-2022 Update: 现在已经可以正常处理所有正则规则，包括 HTTPS 协议的 URL 可以解密，只需要安装配置文件中附上的证书并信任即可。规则中对 Apple 相关的域名进行了屏蔽，不会对 Apple 官方域名进行 HTTPS MITM，并且 HTTPS MITM 默认关闭，需要用户手动打开。

为了在境内也能正常运行，本脚本没有使用 Github 链接作为原规则的获取链接，而是使用了 jsDelivr 的链接，其在时效性上稍稍滞后，但并无大碍。

使用方法：直接运行 `main.py` 即可。
