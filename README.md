# clove1gk

A modular, framework-agnostic authentication & authorization middleware for Rust.

Supports **Axum** and **Actix-web** via bridge adapters — same core, zero duplication.

---

## How It Works

Authentication runs as a 6-step pipeline:

```
STEP 1 — Token Extraction      → reads Authorization header
STEP 2 — Token Validation      → verifies JWT signature / expiry
STEP 3 — Claims Extraction     → maps token payload to your structs
STEP 4 — Context Loading       → loads user data from your DB
STEP 5 — Custom Validation     → runs your business rules (tenant, plan, etc.)
STEP 6 — Guard Check           → enforces roles & permissions
```

Each step is a trait you implement once — the framework calls them in order.

---

## Usage — Axum

```rust
async fn admin_handler(
    Protected(ctx): Protected<AppState>,
) -> impl IntoResponse {
    Json(json!({ "user": ctx.subject_id() }))
}
```

## Usage — Actix-web

```rust
async fn admin_handler(
    ctx: ActixProtected<AppState, DefaultAuthContext>,
) -> impl Responder {
    HttpResponse::Ok().json(json!({ "user": ctx.context.subject_id() }))
}
```

---

## Extractor Levels

| Extractor    | Steps Run | Use When                        |
|--------------|-----------|---------------------------------|
| `TokenClaims`| 1 → 3     | You only need the token payload |
| `AuthUser`   | 1 → 4     | You need the loaded user        |
| `Protected`  | 1 → 6     | Full auth + guard enforcement   |

---

## License

MIT
