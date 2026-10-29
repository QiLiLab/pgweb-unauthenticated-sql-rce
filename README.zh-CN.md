# Pgweb 0Day：匿名 SQL 访问及条件性操作系统命令执行

[English](README.md)

## 概要

当 Pgweb 实例可在没有 HTTP 鉴权的情况下访问，且已经连接 PostgreSQL 时，匿名访问者可通过 `GET /api/query` 提交 SQL。如果数据库连接使用 PostgreSQL 超级用户，访问者可借助 `COPY ... TO PROGRAM` 以 **PostgreSQL 服务进程用户** 的身份执行操作系统命令。PostgreSQL 还允许被授予 `pg_execute_server_program` 权限的角色使用该功能；随包复现脚本只检查超级用户角色。

这一 0Day 问题**依赖具体部署配置**。命令在数据库服务器上执行，数据库服务器可能与 Pgweb 所在主机不同。证据记录展示了三个 Pgweb 0.17.0 实例中的完整链路，数据库连接用户均为具有超级用户权限的 `postgres`。记录采集于 2026-10-20；公开材料已移除目标身份信息。

| 项目 | 内容 |
| --- | --- |
| 产品 | [Pgweb](https://github.com/sosedoff/pgweb) |
| 分类 | 0Day；匿名 SQL 访问，以及满足权限条件时的远程命令执行 |
| 报告日期 | 2026-10-22 |
| 完整链路实测的 Pgweb 版本 | 0.17.0 |
| 必要暴露条件 | Pgweb API 无 HTTP 鉴权即可访问，且已有数据库连接 |
| 命令执行的附加条件 | PostgreSQL 超级用户或 `pg_execute_server_program` 权限 |
| 执行位置与身份 | 数据库主机上的 PostgreSQL 服务进程用户 |
| 2026-10-29 核对的版本 | [v0.17.0](https://github.com/sosedoff/pgweb/releases/tag/v0.17.0) |

## 技术依据

Pgweb v0.17.0 [仅在 `AuthUser` 和 `AuthPass` 同时非空时启用 HTTP BasicAuth](https://github.com/sosedoff/pgweb/blob/v0.17.0/pkg/cli/cli.go#L197-L210)，而[命令行选项](https://github.com/sosedoff/pgweb/blob/v0.17.0/pkg/command/options.go#L41-L45)没有设置鉴权默认值。[官方 Dockerfile](https://github.com/sosedoff/pgweb/blob/v0.17.0/Dockerfile#L43-L48)以 `--bind=0.0.0.0 --listen=8081` 启动；独立二进制程序的 `--bind` 默认值则是 `localhost`。因此，实际网络暴露取决于部署方式。

[路由定义](https://github.com/sosedoff/pgweb/blob/v0.17.0/pkg/api/routes.go#L21-L57)注册了 `GET /api/query`。[`RunQuery`](https://github.com/sosedoff/pgweb/blob/v0.17.0/pkg/api/api.go#L310-L320) 将提交的 SQL 交给 [`HandleQuery`](https://github.com/sosedoff/pgweb/blob/v0.17.0/pkg/api/api.go#L555-L565)，后者调用当前数据库客户端执行查询。PostgreSQL [官方文档](https://www.postgresql.org/docs/current/sql-copy.html)说明，`COPY ... TO PROGRAM` 在数据库服务器上执行，并要求超级用户或相应预定义权限。

```text
匿名 HTTP 访问 → Pgweb /api/query → PostgreSQL 执行 SQL
→ 有权限的 COPY ... TO PROGRAM → 在数据库主机上执行操作系统命令
```

若没有所需的 PostgreSQL 权限，匿名 SQL 仍可能在数据库角色自身的权限范围内产生影响。本报告的命令执行证据对应超级用户连接。

## 复现与观测

本地复现环境使用 Pgweb 0.17.0 和 PostgreSQL 16，未设置 `--auth-user` 与 `--auth-pass`。复现使用固定标记，没有启动交互式 shell，也未修改应用数据：

```sql
SELECT current_user,
       (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS is_superuser;

COPY (SELECT 'NCCPROBE') TO PROGRAM 'cat > /tmp/ncc_pg_probe';
SELECT pg_read_file('/tmp/ncc_pg_probe');
COPY (SELECT '') TO PROGRAM 'rm -f /tmp/ncc_pg_probe';
```

[PoC 记录](evidence/Pgweb_Unauth_RCE_poc.txt)保留了三个实测实例的 SQL、HTTP 状态码和响应字段。原公网地址已替换为保留的 `192.0.2.0/24` 文档地址，数据库标识符已统一替换为 `REDACTED_DB`。每个案例的角色检查均返回 `is_superuser: true`，读回结果包含 `NCCPROBE`，清理后再次读取返回文件不存在。

| 案例 | Pgweb | PostgreSQL | 观测结果 |
| --- | --- | --- | --- |
| 1 | 0.17.0 | 16.15 | 标记读回，清理复核成功 |
| 2 | 0.17.0 | 16.14 | 标记读回；清理复核首次超时，重试后成功 |
| 3 | 0.17.0 | 18.1 | 标记读回，清理复核成功 |

记录还以注释和匿名形式列出七个匿名 SQL 可用的实例；这些条目本身没有独立证明操作系统命令执行。

[复现脚本](repro/Pgweb_Unauth_RCE_repro.py)仅依赖 Python 标准库。它先检查 `/api/info` 和数据库角色，仅在角色为超级用户时运行默认 `id` 命令。脚本还支持目标列表、FOFA 测绘和自定义命令；目录中没有 FOFA 密钥或配置文件。在已授权的本地环境中，单目标调用方式为：

```bash
python repro/Pgweb_Unauth_RCE_repro.py http://127.0.0.1:8081
```

本地生成的目标列表、FOFA 配置和结果文件可能包含真实地址或密钥，不应提交到公开仓库。常见文件名已由 [`.gitignore`](.gitignore) 排除。

### 脱敏截图

以下图片是报告截图的脱敏版本，遮盖了主机地址、数据库标识符、本地路径、账户图像和无关资产信息。原始截图不包含在本仓库中。

![已脱敏的资产测绘截图](assets/asset-search-redacted.png)

*资产测绘背景。搜索命中本身不能证明所有结果均存在漏洞。*

**案例 1 — PostgreSQL 16.15**

![案例 1 的脱敏命令执行截图](assets/case-1-redacted.png)

**案例 2 — PostgreSQL 16.14**

![案例 2 的脱敏命令执行截图](assets/case-2-redacted.png)

**案例 3 — PostgreSQL 18.1**

![案例 3 的脱敏命令执行截图](assets/case-3-redacted.png)

*三张案例截图保留了角色检查、命令结果和清理记录，同时遮盖目标身份；可阅读的请求和响应细节见 PoC 记录。*

## 与已有报告的关系

[Pgweb issue #869](https://github.com/sosedoff/pgweb/issues/869)描述了 `--connect-backend` 模式下直接访问 `/api/connect` 的授权绕过。本报告针对 HTTP 无鉴权、已有数据库连接及 `/api/query` 的组合。本仓库未自行分配 CVE 编号。

## 缓解建议

1. 同时设置 `--auth-user` 和 `--auth-pass`，或在反向代理处强制鉴权。仅设置其中一个参数不会启用 Pgweb 的 BasicAuth 中间件。
2. 限制 Pgweb 服务的网络可达范围。使用容器镜像时，不应在缺少鉴权层的情况下将 8081 端口直接暴露到公网。
3. 让 Pgweb 使用专用的最小权限 PostgreSQL 角色，避免授予超级用户和 `pg_execute_server_program` 权限，并按需限制服务器文件访问权限。
4. 检查 Pgweb 与 PostgreSQL 日志中异常的匿名查询及 `COPY ... PROGRAM` 行为。

## 文件

| 路径 | 内容 |
| --- | --- |
| [`README.md`](README.md) | 英文报告首页 |
| [`.gitignore`](.gitignore) | 排除常见的本地密钥、目标列表、结果文件和 Python 缓存 |
| [`evidence/Pgweb_Unauth_RCE_poc.txt`](evidence/Pgweb_Unauth_RCE_poc.txt) | 英文 PoC 记录；公网地址已替换，数据库标识符已脱敏 |
| [`repro/Pgweb_Unauth_RCE_repro.py`](repro/Pgweb_Unauth_RCE_repro.py) | 复现脚本；注释、帮助信息和终端提示均为英文 |
| [`assets/asset-search-redacted.png`](assets/asset-search-redacted.png) | 脱敏的资产测绘截图 |
| [`assets/case-1-redacted.png`](assets/case-1-redacted.png)、[`assets/case-2-redacted.png`](assets/case-2-redacted.png)、[`assets/case-3-redacted.png`](assets/case-3-redacted.png) | 三个命令执行案例的脱敏截图 |
