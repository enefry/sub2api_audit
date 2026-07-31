# Sub2API 审计记录工具实施计划

## 总体方案

- 新建独立 FastAPI 服务，监听宿主机 `127.0.0.1:9203`，由 Nginx `mirror` 旁路发送 `/v1/*` 请求；审计服务异常不得影响 Sub2API 主请求。
- 使用按月独立的 SQLite 文件：`audit-YYYY-MM.sqlite3`，按 `Asia/Hong_Kong` 划分月份。当前月可写，历史月封存只读，不自动删除。
- 完整保存请求语义内容，但不保存明文 token；通过 HMAC 指纹、掩码及 Sub2API `api_key_id/user_id` 完成审计关联。
- 网页分为个人入口 `/audit/` 和管理员入口 `/admin/audit/`，仅提供只读列表、筛选和请求详情，不提供删除、修改或导出。
- 个人采集开关默认关闭，用户只能修改自己的开关；关闭停止新增采集但保留历史记录。
- 最多查询 90 天，可跨月查询；冷备采用 S3 兼容对象存储、客户端 AES-256-GCM 加密，并继续保留本地副本。

## 核心实现

### 请求采集与 Nginx

- 修正现有 mirror location 缺少 `/` 的问题，内部入口改为精确匹配，例如 `location = /_audit_ingest`。
- mirror 显式传递原始 method、URI、query、客户端 IP、User-Agent、Content-Type、Authorization 和请求体；FastAPI 成功持久化后返回 `204`。
- 使用共享随机密钥保护内部采集接口，应用只信任 Nginx 注入的 `X-Audit-Proxy-Secret`。
- 增加 `/audit/` 与 `/admin/audit/` 反向代理，并继续使用现有 Authentik `auth_request`。
- 为该站点调整日志格式，停止记录完整 `Authorization`，避免明文 token 继续出现在 access log。
- 保持 Nginx mirror 的故障隔离：审计服务超时、拒绝或离线时，Sub2API 主请求仍正常转发。

### SQLite 月度分库与去重

每个月库均自包含以下逻辑数据：

- `requests`：时间、method、model、token/URI 外键、来源信息、请求大小、原始内容哈希、解析状态。
- `token_dimensions`：HMAC-SHA256 指纹、末尾掩码、Sub2API `api_key_id/user_id` 及当时的 key/user 名称快照。
- `uri_dimensions`：去重后的原始 URI。
- `content_objects`：按规范化 JSON 的 SHA-256 寻址并压缩存储的内容对象。
- `request_content_refs`：仅保存请求首次引入的历史消息、input item、content block
  JSON Pointer 引用；完整顺序由内容寻址的根模板保留。
- 必要的时间、model、URI、token、用户索引和 schema 版本表。

去重行为：

- 支持 OpenAI Responses、Chat Completions、Anthropic Messages，以及常见 `messages/input/contents/system/instructions/prompt` 结构。
- 将历史消息和嵌套 content block 规范化后分别内容寻址；重复携带的历史只增加引用，不重复保存内容。
- 请求其余字段也作为内容对象保存，因此重复的 tools、配置和完整相同请求可以复用。
- 使用流式 JSON 解析处理大请求，避免按请求体上限一次性载入内存；无法识别的合法 JSON 使用通用树解析，非 JSON 请求保存为压缩的内容寻址对象。
- 详情页根据模板和有序引用还原完整 JSON；保证 JSON 语义内容完整，不保证原始空格、缩进和键顺序完全一致。
- SQLite 开启 WAL、foreign keys、busy timeout，并使用单 Uvicorn worker 和串行写事务；写入完成后才向 mirror 返回 `204`。

### Sub2API 只读关联

- 创建专用 PostgreSQL 只读账号，仅授予 `api_keys`、`users` 的 `SELECT` 权限，并设置 `default_transaction_read_only=on`。
- 收到请求后从 `Authorization: Bearer`、`X-API-Key` 等支持的 token 头提取明文，只读查询 `api_keys.key` 唯一索引，记录关联 ID 与显示快照，然后立即丢弃明文。
- SQLite 仅保存 `HMAC(token)` 和末尾掩码；HMAC 密钥通过环境变量提供，不进入数据库或日志。
- PostgreSQL 暂时不可用时仍保存请求和 token 指纹，标记为 `unresolved`，不得阻塞采集；应用始终不向 Sub2API 数据库写入。

### 审计网页与接口

- `GET /audit/`：个人只读审计页面；`GET /admin/audit/`：管理员全局审计页面。两者复用本地静态资源，不依赖外部 CDN。
- `GET <入口>/api/requests`：按时间范围、model、URI、token 掩码、key/user 条件筛选，使用时间加 ID 的游标分页；个人入口强制匹配当前用户名。
- `GET <入口>/api/requests/{month}/{id}`：从指定月库还原请求详情，并在 SQL 中校验归属。
- `GET <入口>/api/months`：管理员列出完整月库元数据；个人仅列出自己的月份和记录量。
- `GET/PUT /audit/api/preference`：读取或更新当前用户自己的采集开关。
- `GET /healthz`：报告当前月库、PostgreSQL 只读连接和最近归档状态。

认证规则：

- Nginx 必须先完成 Authentik 验证并覆盖写入 `X-authentik-username`。
- FastAPI 同时校验代理共享密钥和 Authentik 用户名；缺失用户名返回 `401`。
- `/admin/audit/` 要求用户名命中管理员白名单，未命中返回 `403`；`/audit/` 对所有已认证用户开放，但所有读取都在服务端按用户名隔离。
- 采集前必须成功解析 Sub2API 用户名并命中已开启的个人偏好；默认、无 Token、解析失败和关闭状态均不读取或持久化正文。
- 用户名和管理员白名单均精确、区分大小写匹配，白名单通过环境变量或只读配置文件提供。
- 页面设置 `Cache-Control: no-store`、严格 CSP，并对 Prompt 内容进行 HTML 转义。

## 月度切换与冷备

- 月份变化时先创建并切换到新月库，再封存旧库，避免归档过程阻塞新请求。
- 封存流程：关闭写连接、`wal_checkpoint(TRUNCATE)`、`PRAGMA integrity_check`、统计记录数、生成原始库 SHA-256。
- 使用 Zstandard 压缩后，以 AES-256-GCM 加密；归档格式携带版本、随机 nonce 和 key ID。
- 自动上传到 S3 兼容存储，路径采用 `<prefix>/YYYY/MM/audit-YYYY-MM.sqlite3.zst.aes`，同时上传包含 schema 版本、大小、记录数和双重哈希的清单。
- 上传后通过对象大小及元数据校验，写本地归档状态 sidecar；失败采用指数退避重试，不修改或删除原月库。
- 应用启动时自动扫描所有尚未成功归档的封存月并补传。
- 提供恢复命令：下载、验证密文哈希、AES-GCM 解密、解压、验证原始 SHA-256 和 SQLite integrity check，再放回数据目录。
- S3 endpoint、region、bucket、prefix、凭据、归档 key/key ID 均通过环境变量配置；首版上传成功后仍永久保留本地月库。

## 部署与测试

- 提供 `Dockerfile`、Compose 配置、依赖锁定、示例环境变量和运维说明。
- 审计容器加入现有 `sub2api_default` 网络访问 PostgreSQL，同时只映射 `127.0.0.1:9203` 给宿主机 Nginx。
- 数据卷保存月库、归档状态和临时归档文件；临时文件使用原子重命名，异常重启后可安全重试。

验证场景包括：

- Nginx `nginx -t`，并验证 mirror location、请求体和原始 URI 传递正确。
- 审计服务关闭、超时或返回错误时，Sub2API 主请求仍成功。
- 相同历史消息跨请求只存一份，详情还原后的 JSON 与原请求语义一致。
- 大型 Responses/Chat/Anthropic 请求能流式解析、去重并完整还原。
- 月末并发请求正确进入对应月份，旧月库封存后不再写入。
- 跨月 90 天筛选和游标分页无重复、无漏项。
- 管理员白名单用户可访问全局入口；普通用户只能在个人入口读取自己的记录，伪造或缺失 Authentik 用户被拒绝。
- 明文 token 不出现在 SQLite、应用日志、异常信息或 Nginx access log。
- PostgreSQL 账号执行写操作必然失败，数据库不可用时采集仍继续。
- S3 上传失败重试、密文篡改检测、归档恢复和 SQLite 完整性校验通过。

## 明确假设

- 只采集请求，不采集 Sub2API 的流式响应内容。
- 月库不自动过期或删除；90 天仅是单次网页查询跨度限制。
- 冷备默认使用 S3 兼容接口、客户端 AES-256-GCM，并保留全部本地副本。
- 网页首版不包含统计看板、记录删除、批量导出或独立用户体系。
