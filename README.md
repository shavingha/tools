# Clash Subscription Manager

一个用于刷新订阅、生成 Clash 配置并在本机重启 Clash 的小型工具集。

## 当前仓库约定

- 敏感信息不提交到仓库：订阅 URL、生成后的本地配置、`.env`、运行日志都会被忽略。
- 运行时配置放在 `.env` 中，可从 `.env.example` 复制。
- 本地生成的 Clash 配置默认输出到 `config.local.yaml`。
- 旧入口 `ssr.py` 和 `clash_cron.sh` 仍然保留为兼容包装器，新入口分别是 `subscription_to_clash.py` 和 `refresh_clash.sh`。

## 快速开始

1. 安装依赖：`pip install -r requirements.txt`
2. 复制环境变量模板：`cp .env.example .env`
3. 在 `.env` 中填入真实的订阅地址
4. 手动生成配置：`python3 subscription_to_clash.py --from-env -o config.local.yaml`
5. 刷新并检查 Clash：`bash refresh_clash.sh`

## GitHub 清理建议

- 立即轮换已经暴露过的订阅凭据和 GitHub Token。
- 如果历史提交中也包含这些敏感信息，建议后续再做一次历史清理。
