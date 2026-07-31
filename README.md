# Sub2API Recorder

Sub2API Recorder 是一个独立的 FastAPI 旁路审计服务。Nginx `mirror`
复制请求到内部采集入口；采集失败不会改变主请求的响应。请求按
`Asia/Hong_Kong` 自然月写入独立 SQLite 文件，历史消息和 content block
使用规范化 JSON 的 SHA-256 内容寻址复用。

实现范围与安全边界：

- 只记录请求，不读取或记录 Sub2API 的流式响应。
- 个人审计默认关闭；只有已解析到用户且该用户主动开启后，才持久化后续请求。
- 不在 SQLite 或应用日志中保存明文 API token。
- 只读查询 Sub2API PostgreSQL 的 `api_keys` 和 `users`；服务中没有写 SQL。
- 审计页面只读；个人入口仅显示当前 Authentik 用户自己的记录，管理员入口
  另行要求精确白名单。
- 月库永久保留本地副本；历史月可自动压缩、AES-256-GCM 加密后上传 S3。
- 单次页面查询最多 90 天。

详细设计与取舍见 [PLAN.md](PLAN.md)。

## 文件布局

每个月库是自包含的：

```text
data/
├── audit-preferences.sqlite3
├── audit-2026-07.sqlite3
├── audit-2026-06.sqlite3
├── audit-2026-06.archive.json
├── logs/
│   └── sub2api-recorder.log
├── .archive-tmp/
└── .tmp/
```

`audit-YYYY-MM.archive.json` 仅在对象大小和 SHA-256 元数据校验成功后原子
写入。上传成功不会删除 SQLite 原文件。

`audit-preferences.sqlite3` 保存每个用户名的采集开关，默认无记录即为关闭。
它不包含请求正文，也不属于月度 S3 归档；部署时应随本地配置数据单独备份。

应用日志写入 `AUDIT_DATA_DIR/logs/sub2api-recorder.log`，单个文件达到
10 MB 后由 Loguru 自动滚动；当前文件加滚动文件总共最多保留 6 个。日志也会
继续输出到容器标准错误流，且不会记录 URI、Token、请求体或 PostgreSQL DSN。

## 配置

复制 `.env.example` 为 `.env`，至少替换所有 `REPLACE_...` 项。三个密钥
必须彼此独立：

- `AUDIT_PROXY_SECRET`：Nginx 到服务的信任边界，至少 32 bytes。
- `AUDIT_TOKEN_HMAC_KEY`：计算 token 指纹；更换后不能跨月按指纹关联。
- `AUDIT_ARCHIVE_KEY`：恰好 32 bytes 的 AES key，推荐 `base64:` 格式。

生成示例：

```bash
openssl rand -base64 48
openssl rand -base64 32
```

`AUDIT_USERNAME_ALLOWLIST` 是审计管理员名单，按逗号分隔并精确、区分大小写
匹配。也可使用每行一个用户名的 `AUDIT_USERNAME_ALLOWLIST_FILE`；空行和 `#`
注释会忽略。未在名单中的 Authentik 用户仍可访问 `/audit/`，但只能读取
`token_dimensions.username` 与其 Authentik 用户名精确匹配的记录。

如果暂不配置对象存储，可显式设 `AUDIT_ARCHIVE_ENABLED=false`。这不会影响
月度物理分库或本地保留，只会跳过自动加密上传。

## 只读 PostgreSQL 账号

以管理员身份审阅并执行
[`deploy/create-readonly-role.sql`](deploy/create-readonly-role.sql)。随后用该
账号验证 `SELECT` 成功、`UPDATE` 失败，再将 DSN 写入 `.env`。

应用连接时还会设置：

```text
default_transaction_read_only=on
statement_timeout=2000
```

PostgreSQL 不可用、超时或 token 不存在时，请求仍会写入 SQLite，并将关联
状态标为 `unavailable` 或 `not_found`。驱动异常内容不会写入日志，避免 DSN
凭据泄漏。

## 启动审计服务

先准备数据目录权限，再只启动本项目的容器：

```bash
mkdir -p data
chown 10001:10001 data
docker compose build
docker compose up -d sub2api-recorder
```

Compose 只将端口映射到宿主机 `127.0.0.1:9203`，并加入已经存在的
`sub2api_default` 网络。Uvicorn 固定单 worker，SQLite 使用 WAL、
`foreign_keys=ON`、`synchronous=FULL` 和串行写事务。

列表、月份和详情读取在独立的有界线程池中执行；每次任务只在线程内创建自己的
只读 SQLite 连接，不与写入连接共享。默认使用 2 个读取线程和 128 MiB 的按字节
LRU 总缓存，可通过 `AUDIT_READ_WORKERS`、`AUDIT_CACHE_BYTES` 调整。缓存包括
内容哈希对象、序列化后的精简详情，以及最多 2 条完整详情；完整详情默认 120 秒
过期，可通过 `AUDIT_FULL_CACHE_TTL_SECONDS` 调整。超过缓存总量一半的单个对象
不会缓存。

这些命令不会要求重启 Sub2API/PostgreSQL/Redis，但首次接入 Nginx 必须由
运维人员单独校验并 reload Nginx。

## Nginx 接入

审阅 [`deploy/nginx-sub2api-audit.conf`](deploy/nginx-sub2api-audit.conf)，
把其中两条 `mirror` 指令加入现有 `/v1` location，再加入精确的
`location = /_audit_ingest`、`/audit/` 和 `/admin/audit/` location。注意：

- 内部 mirror location 必须带开头的 `/`。
- 两处 `X-Audit-Proxy-Secret` 必须与 `.env` 完全一致。
- `/audit/` 与 `/admin/audit/` 都必须沿用现有 Authentik `auth_request` include。
- Nginx 必须覆盖 `X-authentik-username`，不能信任客户端传入值。
- Authentik 用户名必须与 Sub2API `users.username` 精确、区分大小写一致；否则
  个人入口不会显示任何记录。
- 该虚拟主机的 access log 格式不得包含 `$http_authorization`；示例切换到
  内建 `combined` 格式。

只做配置验证：

```bash
nginx -t
```

验证成功后是否 reload 由运维人员决定；本项目不会自动修改或重启外部
Nginx。

采集入口支持原始 GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD method。服务先从
Token 只读解析 Sub2API 用户名并检查内存中的个人开关；未解析到用户或开关关闭时
直接返回 `204`，不会在 Recorder 的临时目录写入正文。开关开启后，请求体才写入
`/data/.tmp`，按流计算原始 SHA-256，再在单个 SQLite 事务中写入对象、引用和
请求行。事务提交前不会返回 `204`。

## 审计页面/API

个人用户访问 `/audit/`，审计管理员访问 `/admin/audit/`。页面资源全部本地提供，
没有 CDN。服务对页面、脚本、样式和 API 都进行两层检查：

1. `X-Audit-Proxy-Secret` 必须匹配。
2. `X-authentik-username` 必须存在；管理员入口还必须命中精确白名单。

缺失身份返回 `401`，非白名单用户访问管理员入口返回 `403`。个人入口在所有列表、
月份统计和详情 SQL 中强制加入当前用户名条件；直接猜测他人的详情 ID 返回 `404`。
升级前已经存在的无 Token、解析失败或未关联用户名记录只对管理员可见；新请求若
无法解析用户则不会采集。详情缓存按权限范围分键，
个人缓存命中前仍会重新检查当前归属，避免缓存绕过授权。页面使用 `textContent`
展示 URI、用户名和 Prompt，响应包含 `Cache-Control: no-store`、CSP、仅允许同源
iframe 以及禁止 MIME sniffing 等头。

接口：

- `GET <入口>/api/requests`：时间、model、URI、token 后缀、key/user 筛选，
  游标分页；个人入口会忽略传入的 username 并固定为当前用户。
- `GET <入口>/api/requests/{month}/{id}`：还原完整 JSON 语义请求。
- `GET <入口>/api/months`：管理员查看本地月库元数据；个人仅能看到自己有记录的
  月份和个人记录数，不暴露全库大小与归档状态。
- `GET <入口>/api/context`：页面使用的服务时区、服务当前时间、当前身份与权限范围。

这里的 `<入口>` 是 `/audit`（个人）或 `/admin/audit`（管理员）。管理员打开
`/audit/` 时也按个人范围查询，不会自动提升权限。

个人入口顶部提供“记录新请求”开关，对应：

- `GET /audit/api/preference`：读取当前用户的开关，首次访问为关闭。
- `PUT /audit/api/preference`：以 `{"enabled": true|false}` 更新当前用户自己的开关。

开启只影响之后到达的新请求；关闭会停止新增采集，但不会删除或隐藏已有历史记录。
偏好会持久化到 `audit-preferences.sqlite3`，并在进程启动时载入内存，采集热路径不会
为每个请求同步查询偏好数据库。新版本开始，不可解析用户归属的请求不会再采集。

审计页面默认以精简模式显示请求内容，只保留最近的语义项并限制超长文本；
可在详情中切换为完整内容。详情 API 默认保持完整还原语义，传
`view=compact` 可取得相同的精简视图。正文对象按内容哈希复用，新请求只为
首次出现的对象写入关系引用，完整根模板仍可精确还原原始 JSON 语义。
精简视图只解析根模板及所选序列的最后 8 项，不会先重建完整正文。
日期输入、快捷时间范围、列表与详情显示均以服务端
`AUDIT_TIMEZONE` 为准，不使用浏览器所在时区。
- `GET /healthz`：仅可信代理可调用，报告当前月库、只读 PostgreSQL、归档和已开启
  审计的用户数量。

还原保证 JSON 语义一致，不保证原始空格、键顺序或数字的文本写法一致。
非 JSON/损坏 JSON 以完整 base64 内容返回。

## 月度归档和恢复

进入新月时，服务先创建新写库，再 checkpoint、完整性检查并关闭旧库。
后台任务会扫描所有未成功归档的历史库并指数退避重试。对象路径：

```text
<prefix>/YYYY/MM/audit-YYYY-MM.sqlite3.zst.aes
<prefix>/YYYY/MM/audit-YYYY-MM.sqlite3.manifest.json
```

密文格式使用随机 96-bit nonce 和 AES-256-GCM，格式 header 作为 AAD；
manifest 记录原库与密文的 SHA-256、大小、记录数、schema version 和 key ID。

手动补传一个已经封存的月：

```bash
docker compose run --rm sub2api-recorder \
  sub2api-recorder archive --month 2026-06
```

恢复默认拒绝覆盖已有文件：

```bash
docker compose run --rm sub2api-recorder \
  sub2api-recorder restore --month 2026-06 \
  --destination /data/restored/audit-2026-06.sqlite3
```

恢复流程依次验证密文哈希、GCM tag、原库哈希和 SQLite
`PRAGMA integrity_check`，最后才原子移动到目标路径。历史 key 必须按
`AUDIT_ARCHIVE_KEY_ID` 保留；丢失加密 key 无法恢复备份。

## 本地开发与测试

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-test.lock
.venv/bin/pytest
```

测试覆盖语义还原、历史去重、token 不落盘、鉴权、90 天限制、分页、月库
轮转以及加密篡改检测。
