# Ninja

Ninja 使用加密 TCP 流；启用 `udp` 和 `udp-over-tcp` 后，可以通过该 TCP 流承载 UDP（UDP-over-TCP v2）。支持 `aes-128-gcm`、`aes-192-gcm`、
`aes-256-gcm` 与 `chacha20-ietf-poly1305`。

通过顶层 `providers` 引入 Ninja 订阅 YAML 时，仅导入其 `proxies` 中
`type: ninja` 的节点；这是 provider 的自定义扩展，不是标准 Mihomo 节点类型。
订阅中的规则、分组与 DNS 配置均会忽略。provider
在启动建图前加载，远程下载失败时可回退到 `path` 缓存；更新在配置重载后生效。
远程 provider 的 URL 必须包含 `tag=ninja`，以请求 Ninja 订阅格式；此时默认
使用 `clash-ninja/openwrt` 作为 `User-Agent`，可通过 `user_agent` 覆盖。
