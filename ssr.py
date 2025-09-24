#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSR订阅地址转Clash YAML配置文件转换器
支持从SSR订阅地址读取配置并转换为Clash格式
"""

import base64
import urllib.request
import urllib.parse
import yaml
import json
import re
import sys
import argparse
from typing import List, Dict, Any


class SSRToClashConverter:
    """SSR到Clash配置转换器"""

    def __init__(self):
        self.clash_config = {
            "port": 7890,
            "socks-port": 7891,
            "allow-lan": False,
            "mode": "Rule",
            "log-level": "info",
            "external-controller": "127.0.0.1:9090",
            "proxies": [],
            "proxy-groups": [
                {"name": "PROXY", "type": "select", "proxies": []},
                {
                    "name": "Auto",
                    "type": "url-test",
                    "proxies": [],
                    "url": "http://www.gstatic.com/generate_204",
                    "interval": 300,
                },
            ],
            "rules": [
                "DOMAIN-SUFFIX,local,DIRECT",
                "IP-CIDR,127.0.0.0/8,DIRECT",
                "IP-CIDR,172.16.0.0/12,DIRECT",
                "IP-CIDR,192.168.0.0/16,DIRECT",
                "IP-CIDR,10.0.0.0/8,DIRECT",
                "IP-CIDR,17.0.0.0/8,DIRECT",
                "IP-CIDR,100.64.0.0/10,DIRECT",
                "GEOIP,CN,DIRECT",
                "MATCH,Auto",
            ],
        }
        self.timeout = 30

    def _safe_b64decode(self, data: str) -> str:
        """对Base64内容做安全解码(自动补齐=)。"""
        try:
            # urlsafe兼容与标准兼容
            padding = 4 - (len(data) % 4)
            if padding and padding < 4:
                data = data + ("=" * padding)
            try:
                return base64.urlsafe_b64decode(data).decode("utf-8")
            except Exception:
                return base64.b64decode(data).decode("utf-8")
        except Exception:
            return ""

    def fetch_ssr_subscription(self, url: str) -> str:
        """从订阅地址获取SSR配置内容"""
        try:
            print(f"正在获取订阅内容: {url}")
            req = urllib.request.Request(url)
            req.add_header(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            )

            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                content = response.read()
                # 尝试解码base64
                try:
                    decoded_content = base64.b64decode(content).decode("utf-8")
                    print(
                        f"成功获取订阅内容，共 {len(decoded_content.splitlines())} 个节点"
                    )
                    return decoded_content
                except Exception as e:
                    print(f"Base64解码失败，尝试直接解码: {e}")
                    return content.decode("utf-8")

        except Exception as e:
            print(f"获取订阅内容失败: {e}")
            return ""

    def parse_vmess_url(self, vmess_url: str) -> Dict[str, Any]:
        """解析vmess链接并返回Clash vmess代理。"""
        try:
            if not vmess_url.startswith("vmess://"):
                return {}
            payload = vmess_url[len("vmess://") :]
            decoded = self._safe_b64decode(payload)
            if not decoded:
                return {}
            data = json.loads(decoded)

            name = data.get("ps") or f"{data.get('add','')}-{data.get('port','')}"
            server = data.get("add")
            port = int(data.get("port", 0))
            uuid = data.get("id")
            alter_id = int(data.get("aid", 0) or 0)
            cipher = data.get("scy") or "auto"
            tls_enabled = (data.get("tls") or "").lower() == "tls"
            network = data.get("net") or "tcp"
            host_header = data.get("host") or ""
            path = data.get("path") or ""

            proxy: Dict[str, Any] = {
                "name": name,
                "type": "vmess",
                "server": server,
                "port": port,
                "uuid": uuid,
                "alterId": alter_id,
                "cipher": cipher,
            }

            if tls_enabled:
                proxy["tls"] = True

            if network == "ws":
                proxy["network"] = "ws"
                ws_opts: Dict[str, Any] = {}
                if path:
                    ws_opts["path"] = path
                headers: Dict[str, str] = {}
                if host_header:
                    headers["Host"] = host_header
                if headers:
                    ws_opts["headers"] = headers
                if ws_opts:
                    proxy["ws-opts"] = ws_opts
            elif network:
                proxy["network"] = network

            return proxy
        except Exception as e:
            print(f"解析vmess链接失败: {e}")
            return {}

    def parse_ss_url(self, ss_url: str) -> Dict[str, Any]:
        """解析ss链接并返回Clash ss代理。"""
        try:
            if not ss_url.startswith("ss://"):
                return {}
            raw = ss_url[len("ss://") :]

            # 提取备注
            name = ""
            if "#" in raw:
                raw, name_part = raw.split("#", 1)
                name = urllib.parse.unquote(name_part)

            # 处理可能存在的插件与查询参数
            if "?" in raw:
                raw, _ = raw.split("?", 1)

            userinfo = raw
            server_part = ""

            if "@" in raw:
                userinfo, server_part = raw.split("@", 1)
            else:
                # 整段为base64编码的 method:password@server:port
                decoded_all = self._safe_b64decode(raw)
                if "@" in decoded_all:
                    userinfo, server_part = decoded_all.split("@", 1)
                else:
                    # 非标准，放弃
                    return {}

            # 解析加密与密码
            if ":" in userinfo:
                method, password = userinfo.split(":", 1)
            else:
                # 可能userinfo本身是base64的 method:password
                decoded_userinfo = self._safe_b64decode(userinfo)
                if ":" in decoded_userinfo:
                    method, password = decoded_userinfo.split(":", 1)
                else:
                    return {}

            # 解析server与port
            if ":" in server_part:
                server, port_str = server_part.rsplit(":", 1)
                port = int(port_str)
            else:
                return {}

            if not name:
                name = f"{server}:{port}"

            proxy: Dict[str, Any] = {
                "name": name,
                "type": "ss",
                "server": server,
                "port": port,
                "cipher": method,
                "password": password,
            }
            return proxy
        except Exception as e:
            print(f"解析ss链接失败: {e}")
            return {}

    def parse_ssr_url(self, ssr_url: str) -> Dict[str, Any]:
        """解析SSR链接"""
        try:
            # 移除ssr://前缀
            if ssr_url.startswith("ssr://"):
                ssr_url = ssr_url[6:]

            # Base64解码
            decoded = base64.b64decode(ssr_url + "==").decode("utf-8")

            # 解析参数
            parts = decoded.split("/?")
            if len(parts) != 2:
                return {}

            server_info = parts[0].split(":")
            if len(server_info) < 6:
                return {}

            # 解析服务器信息
            server = server_info[0]
            port = int(server_info[1])
            protocol = server_info[2]
            method = server_info[3]
            obfs = server_info[4]
            password = base64.b64decode(server_info[5] + "==").decode("utf-8")

            # 解析查询参数
            params = urllib.parse.parse_qs(parts[1])

            # 获取密码和混淆参数
            password_param = params.get("password", [None])[0]
            obfs_param = params.get("obfsparam", [None])[0]
            protocol_param = params.get("protoparam", [None])[0]
            remarks = params.get("remarks", [None])[0]

            if password_param:
                password = base64.b64decode(password_param + "==").decode("utf-8")
            if obfs_param:
                obfs_param = base64.b64decode(obfs_param + "==").decode("utf-8")
            if protocol_param:
                protocol_param = base64.b64decode(protocol_param + "==").decode("utf-8")
            if remarks:
                remarks = base64.b64decode(remarks + "==").decode("utf-8")

            return {
                "server": server,
                "port": port,
                "password": password,
                "method": method,
                "protocol": protocol,
                "obfs": obfs,
                "obfs_param": obfs_param or "",
                "protocol_param": protocol_param or "",
                "name": remarks or f"{server}:{port}",
            }

        except Exception as e:
            print(f"解析SSR链接失败: {e}")
            return {}

    def ssr_to_clash_proxy(self, ssr_config: Dict[str, Any]) -> Dict[str, Any]:
        """将SSR配置转换为Clash代理配置"""
        if not ssr_config:
            return {}

        # 生成唯一名称
        name = ssr_config["name"]
        if name in [p.get("name", "") for p in self.clash_config["proxies"]]:
            name = f"{name}_{ssr_config['port']}"

        # 构建SSR配置
        proxy = {
            "name": name,
            "type": "ssr",
            "server": ssr_config["server"],
            "port": ssr_config["port"],
            "cipher": ssr_config["method"],
            "password": ssr_config["password"],
            "protocol": ssr_config["protocol"],
            "obfs": ssr_config["obfs"],
        }

        # 添加可选参数
        if ssr_config.get("protocol_param"):
            proxy["protocol-param"] = ssr_config["protocol_param"]
        if ssr_config.get("obfs_param"):
            proxy["obfs-param"] = ssr_config["obfs_param"]

        return proxy

    def convert_subscription_to_clash(self, subscription_url: str) -> str:
        """转换订阅地址为Clash配置"""
        # 获取订阅内容
        subscription_content = self.fetch_ssr_subscription(subscription_url)
        if not subscription_content:
            return ""

        # 抓取所有可识别链接: vmess/ssr/ss
        content = subscription_content
        # 部分订阅是再次base64包裹，尝试再解一次
        if (
            content.strip().startswith("vmess://") is False
            and content.strip().startswith("ssr://") is False
            and content.strip().startswith("ss://") is False
        ):
            decoded_once_more = self._safe_b64decode(content.strip())
            if decoded_once_more:
                content = decoded_once_more

        urls = re.findall(r"(vmess://[^\s]+|ssr://[^\s]+|ss://[^\s]+)", content)

        if not urls:
            print("未找到可识别的节点链接(vmess/ssr/ss)")
            return ""

        print(f"找到 {len(urls)} 个节点，开始转换...")

        for i, link in enumerate(urls, 1):
            print(f"正在转换第 {i}/{len(urls)} 个节点...")
            proxy: Dict[str, Any] = {}
            if link.startswith("vmess://"):
                proxy = self.parse_vmess_url(link)
            elif link.startswith("ssr://"):
                ssr_config = self.parse_ssr_url(link)
                if ssr_config:
                    proxy = self.ssr_to_clash_proxy(ssr_config)
            elif link.startswith("ss://"):
                # 注意避免把ssr识别成ss
                proxy = self.parse_ss_url(link)

            if proxy:
                self.clash_config["proxies"].append(proxy)

        # 更新代理组
        proxy_names = [p["name"] for p in self.clash_config["proxies"]]
        self.clash_config["proxy-groups"][0]["proxies"] = ["DIRECT"] + proxy_names
        self.clash_config["proxy-groups"][1]["proxies"] = proxy_names

        print(f"成功转换 {len(self.clash_config['proxies'])} 个节点")
        return yaml.dump(
            self.clash_config, default_flow_style=False, allow_unicode=True
        )

    def save_clash_config(self, config_content: str, output_file: str):
        """保存Clash配置到文件"""
        try:
            with open(output_file, "w", encoding="utf-8", newline="\n") as f:
                f.write(config_content)
            print(f"配置已保存到: {output_file}")
        except Exception as e:
            print(f"保存配置文件失败: {e}")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="SSR订阅地址转Clash YAML配置文件转换器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python ssr.py "https://example.com/ssr-subscription"
  python ssr.py "https://example.com/ssr-subscription" -o my_config.yaml
  python ssr.py "https://example.com/ssr-subscription" -p 8080 -s 8081
  python ssr.py "https://example.com/ssr-subscription" --mode global
  python ssr.py "https://example.com/ssr-subscription" --no-rules
        """,
    )

    # 必需参数
    parser.add_argument("subscription_url", help="SSR订阅地址URL")

    # 输出选项
    parser.add_argument(
        "-o",
        "--output",
        default="clash_config.yaml",
        help="输出文件名 (默认: clash_config.yaml)",
    )
    parser.add_argument(
        "--stdout", action="store_true", help="直接输出到标准输出，不保存文件"
    )

    # 端口配置
    parser.add_argument(
        "-p", "--port", type=int, default=7890, help="Clash HTTP代理端口 (默认: 7890)"
    )
    parser.add_argument(
        "-s",
        "--socks-port",
        type=int,
        default=7891,
        help="Clash SOCKS代理端口 (默认: 7891)",
    )
    parser.add_argument(
        "--external-controller",
        default="127.0.0.1:9090",
        help="Clash外部控制器地址 (默认: 127.0.0.1:9090)",
    )

    # 模式配置
    parser.add_argument(
        "--mode",
        choices=["Rule", "Global", "Direct"],
        default="Rule",
        help="Clash运行模式 (默认: Rule)",
    )
    parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error", "silent"],
        default="info",
        help="日志级别 (默认: info)",
    )

    # 功能选项
    parser.add_argument("--allow-lan", action="store_true", help="允许局域网连接")
    parser.add_argument(
        "--no-rules", action="store_true", help="不添加默认规则，仅生成代理配置"
    )
    parser.add_argument(
        "--custom-rules", type=str, help="自定义规则文件路径，将替换默认规则"
    )
    parser.add_argument(
        "--timeout", type=int, default=30, help="网络请求超时时间(秒) (默认: 30)"
    )

    # 代理组配置
    parser.add_argument(
        "--proxy-group-name", default="PROXY", help="主代理组名称 (默认: PROXY)"
    )
    parser.add_argument(
        "--auto-group-name", default="Auto", help="自动选择组名称 (默认: Auto)"
    )
    parser.add_argument(
        "--url-test-url",
        default="http://www.gstatic.com/generate_204",
        help="URL测试地址 (默认: http://www.gstatic.com/generate_204)",
    )
    parser.add_argument(
        "--url-test-interval", type=int, default=300, help="URL测试间隔(秒) (默认: 300)"
    )

    # 其他选项
    parser.add_argument("-v", "--verbose", action="store_true", help="显示详细输出信息")
    parser.add_argument(
        "--version", action="version", version="SSR to Clash Converter 1.0.0"
    )

    args = parser.parse_args()

    # 创建转换器
    converter = SSRToClashConverter()

    # 配置转换器参数
    converter.clash_config["port"] = args.port
    converter.clash_config["socks-port"] = args.socks_port
    converter.clash_config["external-controller"] = args.external_controller
    converter.clash_config["mode"] = args.mode
    converter.clash_config["log-level"] = args.log_level
    converter.clash_config["allow-lan"] = args.allow_lan

    # 更新代理组名称
    converter.clash_config["proxy-groups"][0]["name"] = args.proxy_group_name
    converter.clash_config["proxy-groups"][1]["name"] = args.auto_group_name
    converter.clash_config["proxy-groups"][1]["url"] = args.url_test_url
    converter.clash_config["proxy-groups"][1]["interval"] = args.url_test_interval

    # 处理规则配置
    if args.no_rules:
        converter.clash_config["rules"] = ["MATCH,PROXY"]
    elif args.custom_rules:
        try:
            with open(args.custom_rules, "r", encoding="utf-8") as f:
                custom_rules = [line.strip() for line in f.readlines() if line.strip()]
                converter.clash_config["rules"] = custom_rules
        except Exception as e:
            print(f"读取自定义规则文件失败: {e}")
            sys.exit(1)

    # 设置网络超时
    converter.timeout = args.timeout

    if args.verbose:
        print("=" * 60)
        print("SSR订阅地址转Clash配置转换器")
        print("=" * 60)
        print(f"订阅地址: {args.subscription_url}")
        print(f"输出文件: {args.output if not args.stdout else '标准输出'}")
        print(f"HTTP端口: {args.port}")
        print(f"SOCKS端口: {args.socks_port}")
        print(f"运行模式: {args.mode}")
        print(f"日志级别: {args.log_level}")
        print(f"允许局域网: {args.allow_lan}")
        print("=" * 60)
    else:
        print("SSR订阅地址转Clash配置转换器")
        print("=" * 50)

    try:
        # 转换配置
        clash_config = converter.convert_subscription_to_clash(args.subscription_url)

        if clash_config:
            if args.stdout:
                # 输出到标准输出
                print(clash_config)
            else:
                # 保存到文件
                converter.save_clash_config(clash_config, args.output)
                print(
                    f"\n转换完成！共转换 {len(converter.clash_config['proxies'])} 个节点"
                )
                print(f"请将 {args.output} 文件导入到Clash客户端中使用")
        else:
            print("转换失败，请检查订阅地址是否正确")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n用户中断操作")
        sys.exit(1)
    except Exception as e:
        print(f"转换过程中发生错误: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
