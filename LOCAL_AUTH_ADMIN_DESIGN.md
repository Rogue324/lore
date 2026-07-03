# Local Auth + Admin Console on Lore HTTP Server — 落地方案

> 目标：复用 `lore-server` 现有的 HTTP server（端口 41339，Axum + tower），
> 在其上扩展**本地用户管理 + 登录鉴权 + 管理后台 Web UI**。
> 完全不引入新端口、新协议、新外部服务。

---

## 0. 复用盘点

| 现成资源 | 状态 | 备注 |
|---|---|---|
| 端口 41339 | ✅ 在用 | 不冲突 |
| Axum 0.7 + tower-http（timeout/trace） | ✅ | 加 `set-cookie`、`fs` features |
| `ServerState` `.with_state()` 注入 | ✅ | 加字段 |
| `jsonwebtoken` crate | ✅ | 用于签发 session JWT |
| `rand` / `serde` / `serde_json` / `blake3` | ✅ | 全部够用 |
| `reqwest` | ✅ | 未来如要拉远端 JWKS 也现成 |
| `axum-test` 18.1.0 | ✅ | 集成测试 |
| `argon2` 密码 hash | ❌ 新增 | 推荐 `argon2 = "0.5"` |

---

## 1. 改造后路由

```
http://lore-server:41339/
├── /health_check                 现状：keep
├── /v1/repository/{id}/...        现状：keep（外部 Epic JWT）
├── /v1/presigned/...              现状：keep
│
├── /admin                         新增：SPA 入口 HTML
├── /admin/app.js                  新增：前端 JS
├── /admin/api/login               新增：登录（POST）
├── /admin/api/logout              新增：注销（POST）
├── /admin/api/me                  新增：当前用户信息（GET）
├── /admin/api/users               新增：用户列表/创建（GET/POST）
├── /admin/api/users/{id}          新增：用户查/改/删（GET/PATCH/DELETE）
├── /admin/api/users/{id}/password 新增：改密（POST）
└── /admin/api/repositories        新增：受管仓库列表
```

中间件规则：

- `/health_check` + `/v1/*`：**不挂** admin 中间件
- `/admin/api/login`：**不挂** admin 中间件
- `/admin/api/*` 其它：**挂** `require_admin`
- `/admin/*` 静态资源：放行

---

## 2. 新增文件结构

```
src/http/admin/
├── mod.rs              # pub use 入口 + create_router
├── config.rs           # AdminConfig / AdminSettings
├── auth.rs             # login / logout / me
├── users.rs            # 用户 CRUD
├── session.rs          # SessionStore + JWT 签发/解析
├── middleware.rs       # require_admin (FromRequestParts extractor)
├── store.rs            # UserStore trait + JsonFileUserStore
├── audit.rs            # 审计日志（可选）
└── static/
    ├── index.html
    └── app.js
```

---

## 3. 数据模型

```rust
// src/http/admin/auth.rs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminUser {
    pub id: Uuid,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,        // argon2 PHC string
    pub display_name: String,
    pub role: AdminRole,
    pub created_at: DateTime<Utc>,
    pub disabled: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum AdminRole {
    Admin,      // 用户管理 + 仓库管理
    Operator,   // 仓库管理
    Viewer,     // 只读
}

// src/http/admin/session.rs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    pub sub: Uuid,                // user_id
    pub username: String,
    pub role: AdminRole,
    pub exp: i64,
    pub iat: i64,
    pub jti: Uuid,                // 用于吊销
}
```

---

## 4. 用户存储三档

| 档 | 实现 | 适用 |
|---|---|---|
| **M1** | `Arc<RwLock<HashMap<Uuid, AdminUser>>>` | 单元测试 / 演示 |
| **M2** | `JsonFileUserStore`：内存 + 启动加载 `users.json` + 写盘 | 单进程生产 |
| **M3** | `sqlx` + SQLite/Postgres | 多实例 / 审计 |

### M2 骨架

```rust
// src/http/admin/store.rs
#[async_trait]
pub trait UserStore: Send + Sync {
    async fn list(&self) -> Result<Vec<AdminUser>>;
    async fn get(&self, id: Uuid) -> Result<Option<AdminUser>>;
    async fn find_by_username(&self, username: &str) -> Result<Option<AdminUser>>;
    async fn upsert(&self, user: AdminUser) -> Result<()>;
    async fn delete(&self, id: Uuid) -> Result<()>;
}

pub struct JsonFileUserStore {
    path: PathBuf,
    inner: Arc<RwLock<HashMap<Uuid, AdminUser>>>,
}

impl JsonFileUserStore {
    pub async fn load(path: PathBuf) -> Result<Self> {
        let map: HashMap<Uuid, AdminUser> = if path.exists() {
            let bytes = tokio::fs::read(&path).await?;
            serde_json::from_slice(&bytes).unwrap_or_default()
        } else {
            let admin = AdminUser {
                id: Uuid::new_v4(),
                username: "admin".into(),
                password_hash: hash_password("admin")?,    // WARN 提示改密
                display_name: "Default Admin".into(),
                role: AdminRole::Admin,
                created_at: Utc::now(),
                disabled: false,
            };
            let mut m = HashMap::new();
            m.insert(admin.id, admin);
            m
        };
        Ok(Self { path, inner: Arc::new(RwLock::new(map)) })
    }

    async fn persist(&self, map: &HashMap<Uuid, AdminUser>) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(map)?;
        let tmp = self.path.with_extension("json.tmp");
        tokio::fs::write(&tmp, &bytes).await?;
        tokio::fs::rename(&tmp, &self.path).await?;        // 原子写
        Ok(())
    }
}
```

---

## 5. Session JWT（HS256）

```rust
// src/http/admin/session.rs
pub struct SessionVerifier {
    encoding: EncodingKey,
    decoding: DecodingKey,
    issuer: String,
    audience: String,
    ttl_seconds: i64,
}

impl SessionVerifier {
    pub fn new(secret: &str, ttl_seconds: i64) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret.as_bytes()),
            decoding: DecodingKey::from_secret(secret.as_bytes()),
            issuer: "local-admin".into(),
            audience: "lore-server-admin".into(),
            ttl_seconds,
        }
    }

    pub fn sign(&self, claims: &SessionClaims) -> Result<String> {
        let header = Header::new(Algorithm::HS256);
        let token = encode(&header, claims, &self.encoding)?;
        Ok(token)
    }

    pub fn verify(&self, token: &str) -> Result<SessionClaims> {
        let mut v = Validation::new(Algorithm::HS256);
        v.set_issuer(&[&self.issuer]);
        v.set_audience(&[&self.audience]);
        v.validate_exp = true;
        let data = decode::<SessionClaims>(token, &self.decoding, &v)?;
        Ok(data.claims)
    }
}

#[derive(Default)]
pub struct SessionStore {
    inner: Arc<RwLock<HashMap<Uuid, SessionEntry>>>,
}
struct SessionEntry { user_id: Uuid, expires_at: i64 }
```

---

## 6. 鉴权中间件

```rust
// src/http/admin/middleware.rs
pub struct AdminAuth(pub SessionClaims);

#[async_trait]
impl<S> FromRequestParts<S> for AdminAuth
where
    S: Send + Sync,
    AdminAppState: FromRef<S>,
{
    type Rejection = StatusCode;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let admin: AdminAppState = AdminAppState::from_ref(state);

        let token = parse_session_cookie(parts.headers.get(COOKIE))
            .or_else(|| parse_bearer(parts.headers.get(AUTHORIZATION)))
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let claims = admin.session_verifier.verify(&token)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        if admin.session_store.is_revoked(claims.jti).await {
            return Err(StatusCode::UNAUTHORIZED);
        }
        Ok(Self(claims))
    }
}
```

**关键**：业务 JWT（`/v1/repository/*`，走 `auth/jwt.rs`）与 session JWT（`/admin/*`，走 `admin/session.rs`）**完全隔离**——两套密钥、两套 issuer、两套 audience。

---

## 7. 登录端点

```rust
// src/http/admin/auth.rs
pub async fn login(
    State(state): State<AdminAppState>,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let user = state.user_store.find_by_username(&req.username).await?
        .ok_or(ApiError::InvalidCredentials)?;     // 故意跟"密码错"返回相同错误

    if user.disabled || !verify_password(&req.password, &user.password_hash)? {
        return Err(ApiError::InvalidCredentials);
    }

    let now = Utc::now();
    let claims = SessionClaims {
        sub: user.id,
        username: user.username.clone(),
        role: user.role,
        iat: now.timestamp(),
        exp: (now + Duration::seconds(state.session_verifier.ttl_seconds)).timestamp(),
        jti: Uuid::new_v4(),
    };
    let token = state.session_verifier.sign(&claims)?;
    state.session_store.put(claims.jti, user.id, claims.exp).await?;

    let cookie = format!(
        "session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
        token, state.session_verifier.ttl_seconds
    );
    if state.cookie_secure {
        // append "; Secure"
    }

    Ok(([(SET_COOKIE, cookie)], Json(LoginResponse { token, expires_in: state.session_verifier.ttl_seconds })))
}
```

---

## 8. Router 装配

```rust
// src/http/admin/mod.rs
pub const INDEX_HTML: &str = include_str!("static/index.html");
pub const APP_JS:     &str = include_str!("static/app.js");

pub fn create_router(state: AdminAppState) -> Router<AdminAppState> {
    let public = Router::new()
        .route("/admin",           get(|| async { Html(INDEX_HTML) }))
        .route("/admin/app.js",    get(|| async { ([("content-type","application/javascript")], APP_JS) }))
        .route("/admin/api/login", post(auth::login));

    let protected = Router::new()
        .route("/admin/api/logout",           post(auth::logout))
        .route("/admin/api/me",               get(auth::me))
        .route("/admin/api/repositories",     get(repositories::list))
        .nest("/admin/api/users",             users::create_router());

    public.merge(protected)
         .route_layer(middleware::from_fn_with_state(state.clone(), require_admin_or_public))
         .with_state(state)
}
```

> 注：`/admin/api/login` 和 `/admin/*` 静态资源不能被 `require_admin` 拦截——`require_admin_or_public` 用路径白名单短路（或者更简单：把 admin 中间件**只**挂到 `protected` 这个子 router 上）。

---

## 9. 复用 gRPC 客户端

```rust
pub async fn list_managed_repositories(
    State(state): State<AdminAppState>,
    AdminAuth(_claims): AdminAuth,
) -> Result<Json<Vec<RepositoryInfo>>, ApiError> {
    let mut client = RepositoryServiceClient::new(state.grpc_channel.clone());
    let mut req = Request::new(ListRepositoriesRequest::default());
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", state.internal_service_token).parse().unwrap(),
    );
    let stream = client.list_repositories(req).await?;
    let infos = stream.into_inner().into_inner().collect::<Vec<_>>().await;
    Ok(Json(infos))
}
```

`internal_service_token` 由服务端启动时生成（一次性写盘到 `admin.token`），不依赖外部 IdP。

---

## 10. 静态资源

### `static/index.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Lore Admin Console</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root { color-scheme: light dark; }
    body { font: 14px/1.5 -apple-system, system-ui, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; }
    nav { display: flex; gap: 1rem; border-bottom: 1px solid #ccc; padding-bottom: .5rem; }
    nav a { cursor: pointer; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: .5rem; border-bottom: 1px solid #eee; text-align: left; }
    .hidden { display: none; }
    .role-Admin { color: #d6336c; font-weight: 600; }
    .role-Operator { color: #1971c2; }
    .role-Viewer { color: #666; }
  </style>
</head>
<body>
  <div id="login-view">
    <h1>Lore Admin Login</h1>
    <form id="login-form">
      <label>Username <input name="username" required autofocus></label><br>
      <label>Password <input name="password" type="password" required></label><br>
      <button type="submit">Sign in</button>
    </form>
    <div id="login-error" style="color:red"></div>
  </div>
  <div id="app-view" class="hidden">
    <nav>
      <a data-tab="users">Users</a>
      <a data-tab="repositories">Repositories</a>
      <span style="margin-left:auto">Logged in as <b id="me-username"></b> (<span id="me-role"></span>) · <a id="logout">Logout</a></span>
    </nav>
    <section id="tab-users" class="tab"></section>
    <section id="tab-repositories" class="tab hidden"></section>
  </div>
  <script type="module" src="./app.js"></script>
</body>
</html>
```

### `static/app.js`

```js
const API = '/admin/api';

async function api(path, opts = {}) {
  opts.credentials = 'include';
  opts.headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  const r = await fetch(API + path, opts);
  if (r.status === 401) { showLogin(); throw new Error('unauthorized'); }
  if (!r.ok) throw new Error((await r.json()).message || r.statusText);
  return r.status === 204 ? null : r.json();
}

document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const data = new FormData(e.target);
  try {
    await api('/login', { method: 'POST', body: JSON.stringify({
      username: data.get('username'), password: data.get('password')
    })});
    showApp();
  } catch (err) {
    document.getElementById('login-error').textContent = 'Invalid credentials';
  }
});

async function showApp() {
  document.getElementById('login-view').classList.add('hidden');
  document.getElementById('app-view').classList.remove('hidden');
  const me = await api('/me');
  document.getElementById('me-username').textContent = me.username;
  document.getElementById('me-role').textContent = me.role;
  if (me.role === 'Admin') await renderUsers();
  await renderRepositories();
}

async function renderUsers() {
  const users = await api('/users');
  document.getElementById('tab-users').innerHTML = `
    <h2>Users</h2>
    <table><thead><tr><th>Username</th><th>Role</th><th>Created</th><th>Status</th><th></th></tr></thead>
    <tbody>${users.map(u => `
      <tr><td>${u.username}</td><td class="role-${u.role}">${u.role}</td>
      <td>${u.created_at.slice(0,10)}</td>
      <td>${u.disabled ? 'Disabled' : 'Active'}</td>
      <td><button data-del="${u.id}">Delete</button></td></tr>
    `).join('')}</tbody></table>
  `;
}

document.getElementById('logout').onclick = async () => {
  await api('/logout', { method: 'POST' });
  document.cookie = 'session=; Max-Age=0; Path=/';
  location.reload();
};

// 启动时：试探 me，若 401 留在登录页
fetch(API + '/me', { credentials: 'include' })
  .then(r => r.ok ? showApp() : null)
  .catch(() => {});
```

---

## 11. ServerState / Settings 扩展

```rust
// src/http/server.rs
#[derive(Clone)]
pub struct ServerState {
    pub immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    pub mutable_store:   Arc<dyn lore_storage::MutableStore>,
    pub jwt_verifier:    Option<JwtVerifier>,
    pub max_file_size:   u64,
    pub presign_config:  Option<PresignConfig>,
    pub admin_state:     Option<AdminAppState>,         // ← 新增
}

#[derive(Clone)]
pub struct AdminAppState {
    pub user_store:    Arc<dyn UserStore>,
    pub session_store: Arc<SessionStore>,
    pub session_verifier: SessionVerifier,
    pub grpc_channel:  tonic::transport::Channel,
    pub internal_service_token: String,
    pub cookie_secure: bool,
}
```

`create_router` 加一段：

```rust
if let Some(admin) = shared_state.admin_state.clone() {
    router = router.nest("/", admin::create_router(admin));
}
```

Settings：

```rust
pub struct LoreHttpServerSettings {
    // ... 已有
    pub admin: Option<AdminSettings>,
}

pub struct AdminSettings {
    pub enabled: bool,
    pub users_file: PathBuf,
    pub session_jwt_secret: String,
    pub session_ttl_seconds: i64,
    pub cookie_secure: bool,
    pub internal_service_token: Option<String>,         // None = 启动时自动生成
}
```

`local.toml` 段：

```toml
[server.http.admin]
enabled = true
users_file = "/var/lib/lore/admin_users.json"
session_jwt_secret = "change-me-32-bytes-minimum-please-rotate"   # 强烈建议从 ENV 注入
session_ttl_seconds = 28800                                       # 8h
cookie_secure = true
# internal_service_token = "auto-generated-on-first-startup"
```

---

## 12. 关键安全决策

| 决策 | 理由 |
|---|---|
| argon2 密码 hash | OWASP 推荐 |
| 登录失败统一返回 InvalidCredentials | 防用户枚举 |
| session cookie HttpOnly + SameSite=Strict | 防 XSS 偷 cookie + 防 CSRF |
| 业务 JWT 与 session JWT 隔离 | 避免管理端误用业务账号；密钥、issuer、audience 全分开 |
| session 用 JWT 而非 server-side session id | 无状态、水平扩展 |
| 独立 `[server.http.admin] enabled` 开关 | 紧急关停 |
| 首次启动写默认 admin/admin + WARN 提示 | 引导首次使用 |
| 审计日志（`admin_audit.log`） | 谁在什么时间改了什么 |
| CSRF 防护 | SameSite=Strict 已挡 90%；高敏操作加 `__Host-` 前缀或双 cookie |

---

## 13. 落地清单（M2 档最小集）

| # | 文件 | 改动 | 风险 |
|---|---|---|---|
| 1 | `lore-server/Cargo.toml` | 加 `argon2 = "0.5"`；`tower-http` 加 `set-cookie`、`fs` features | 低 |
| 2 | `src/http/admin/` | **新增** 8 文件 | — |
| 3 | `src/http/admin/mod.rs` | `create_router(AdminAppState)` | — |
| 4 | `src/http/server.rs` | `ServerState`/`LoreHttpServerSettings` 加 admin 字段；`create_router` 加 nest | 低 |
| 5 | `src/settings.rs` | 解析 `AdminSettings` | 低 |
| 6 | `config/default.toml` | 加 `[server.http.admin]` 注释示例 | 0 |
| 7 | `config/local.toml` | 启用 `enabled = true` + 配 secret | 0 |
| 8 | `src/server.rs::serve` | 构造 `AdminAppState` 并注入 | 低 |
| 9 | `tests/admin_api.rs` | 集成测试：登录 → 创建用户 → 用新账号登录 → 改密 → 注销 | 中 |
| 10 | `docs/admin.md` | 运维文档：首次超管、轮转 secret、备份 users.json | 0 |

---

## 14. 端到端测试脚本

```bash
# 1) 启动
LORE__server__http__admin__enabled=true \
LORE__server__http__admin__session__jwt__secret="$(openssl rand -hex 32)" \
cargo run -p lore-server --bin loreserver

# 2) 登录（首次启动会创建默认 admin/admin，stdout 打 WARN 提醒）
curl -i -X POST http://localhost:41339/admin/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}'

# 3) 用 cookie 调管理 API
curl http://localhost:41339/admin/api/users \
  -H "Cookie: session=eyJ..."

# 4) 创建用户
curl -X POST http://localhost:41339/admin/api/users \
  -H "Cookie: session=eyJ..." \
  -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"correct-horse","role":"Operator"}'

# 5) 浏览器访问
open http://localhost:41339/admin
```

---

## 15. 一个常被忽略的细节

如果想让 gRPC 业务 API 也能用 admin session JWT 调（不推荐但偶尔方便），
给 `auth/jwt.rs::JwtVerifier::verify_token` 的 `validation.iss` 加 `local-admin` 即可。
默认配置**不**启用——业务 API 走 Epic JWT，管理后台走 session JWT。

---

## 16. 实施状态（M2 档已落地）

| # | 文件 | 状态 | 备注 |
|---|---|---|---|
| 1 | `lore-server/Cargo.toml` | ✅ | `argon2 = "0.5"`、`chrono` 走 workspace；`tower-http` 加 `set-cookie`、`fs` |
| 2 | `src/http/admin/{mod,session,store,config,audit,auth,users,middleware}.rs` | ✅ | 8 文件全部落盘 |
| 3 | `src/http/admin/static/{index.html,app.js,app.css}` | ✅ | 单页 SPA + 浅色/深色主题 |
| 4 | `src/http/server.rs` | ✅ | `LoreHttpServerSettings`、`create_router` 第 4 参 `Option<AdminAppState>`，`LoreHttpServer::serve` 第 5 参 |
| 5 | `src/http/mod.rs` | ✅ | `pub mod admin;` 注册 |
| 6 | `src/settings.rs` | ✅ | `HttpSettings` 加 `admin: Option<AdminSettings>` |
| 7 | `src/server.rs` | ✅ | 构造 `admin_state` 并传入 `launch_http_server`；`info!` 日志带 `users_file` 路径 |
| 8 | 12 个 `create_router` 测试调用点 | ✅ | 全部加 `None` 第 4 参 |
| 9 | `config/default.toml` | ✅ | 注释示例块说明启用步骤 |
| 10 | `config/local.toml` | ✅ | `enabled = true` + 开发用 secret，方便本地起服务直接试 |
| 11 | 端到端集成测试 | ✅ | `src/http/admin/tests.rs` 覆盖：登录/me、错误密码无枚举、CRUD 全流程、角色矩阵、自删防护、修改自密码、注销吊销、缺 token 401、静态首页可访问 |

### 路由速查

| 方法 | 路径 | 角色要求 | 说明 |
|---|---|---|---|
| GET  | `/admin/`                  | —       | 静态首页（login SPA） |
| GET  | `/admin/app.{js,css}`      | —       | 静态资源 |
| POST | `/admin/auth/login`        | —       | 用户名+密码登录；防枚举 |
| POST | `/admin/auth/logout`       | session | 撤销 `jti`（即便未过期也立即失效） |
| GET  | `/admin/auth/me`           | session | 当前会话+用户信息 |
| POST | `/admin/auth/me/password`  | session | 改自己密码（需旧密码校验） |
| GET  | `/admin/users/`            | ≥ Operator | 用户列表（防 harvest） |
| POST | `/admin/users/`            | Admin   | 创建用户 |
| GET  | `/admin/users/{id}`        | ≥ Operator | 查单个用户 |
| PATCH| `/admin/users/{id}`        | Admin   | 改 display_name / role / disabled |
| DELETE| `/admin/users/{id}`       | Admin   | 删除用户（自己删自己会被拒） |
| POST | `/admin/users/{id}/password` | Admin | 超管强制改密 |

### 本地试一下

```bash
# 已默认在 local.toml 里开了；直接起服务
cargo run -p lore-server --bin loreserver
# 浏览器打开
http://localhost:41339/admin/
# 默认账号 admin / admin（首次登录后请改密）
```

### 已知后续工作

- **审计日志落盘**：当前只发到 `tracing` 目标 `lore.admin.audit`，没单独写 `admin_audit.log`。生产前需要 `tracing-appender` 路由到一个滚动文件。
- **CSRF 强化**：当前靠 `SameSite=Strict` 挡 90% CSRF；下一步可以给 state-changing 路由加 `__Host-` 前缀 + double-submit cookie。
- **WebSocket / 操作审计**：管理员操作 gRPC 仓库本身仍走 `jwt_verifier` 那条线；audit 只覆盖 admin 用户管理，不覆盖 gRPC 业务调用——按需扩展。
- **rate limit on `/admin/auth/login`**：当前没有，可在 axum 中间件层加 `governor`。
- **CI 集成**：本地 Rust 工具链不可用，`cargo check -p lore-server` 由用户在本地跑。
