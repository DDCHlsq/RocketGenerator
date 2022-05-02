# RocketGenerator
一键生成小火箭分流策略文件。

本脚本基于 [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat)

由于 Loyalsoldier 没有现成的小火箭分流方案，所以本脚本通过其上述项目的分流策略转换为小火箭策略，由于我不清楚小火箭如何处理正则表达式类规则，所以碰到此种规则一律跳过，好在正则表达式规则非常少，影响很小。

为了在境内也能正常运行，本脚本没有使用 Github 链接作为原规则的获取链接，而是使用了 jsDelivr 的链接，其在时效性上稍稍滞后，但并无大碍。

使用方法：直接运行 `main.py` 即可。
