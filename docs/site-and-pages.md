# Docs + marketing site (GitHub Pages)

**Status:** Planned — enable when ready (not blocking MVP protocol waves)  
**Owner decision (2026-07-31):** Serve **docs and marketing** via **GitHub Pages**.

## Goals

| Surface | Purpose |
|---------|---------|
| **Marketing** | Landing: what Thunderducks is, non-goals (no tokens/chain), AGPL, get-started links |
| **Docs** | Threat model, architecture, protocol notes, CLI/web guides as they land |

## Recommended shape (when we flip it on)

1. **Source of truth in-repo**
   - Marketing: `site/` (static HTML or minimal SSG — keep boring)
   - Technical docs: expand `docs/` (Markdown); optional mdBook later if nav grows
2. **Publish path:** GitHub Actions → GitHub Pages  
   - Build on `main` (or `docs` branch if we want freeze control)  
   - Output artifact uploaded to Pages  
3. **URL:** `https://everwood-technologies.github.io/thunderducks/`  
   (custom domain later if desired — not required for MVP)
4. **Do not** put secrets, private keys, or operator-only runbooks on the public site.

## Enable checklist (execute later)

- [ ] Minimal `site/index.html` (or SSG) marketing page  
- [ ] Docs index linking `threat-model.md`, `architecture.md`, README  
- [ ] Workflow `.github/workflows/pages.yml` (peaceable with existing `ci.yml`)  
- [ ] Repo Settings → Pages → source = GitHub Actions  
- [ ] Smoke-check published URL  
- [ ] README badge/link to the site  

## Non-blocking rule

Protocol Waves **B–F** do not depend on Pages. Ship site when messaging is worth the polish (suggested: around **M4/M5** or earlier if you want a public face sooner).
