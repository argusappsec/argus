# Changelog

## [0.2.0](https://github.com/argusappsec/argus/compare/v0.1.0...v0.2.0) (2026-07-08)


### Features

* **persona:** operator-chosen instance name via persona.name ([#46](https://github.com/argusappsec/argus/issues/46)) ([3d746c6](https://github.com/argusappsec/argus/commit/3d746c64f2d00e44ce4437c1949b5ccc4909920f))

## [0.1.0](https://github.com/argusappsec/argus/compare/v0.0.1...v0.1.0) (2026-07-07)


### Features

* **agent:** emit acknowledgment tool result on finalize_report ([b4c24e6](https://github.com/argusappsec/argus/commit/b4c24e616f16b1283f15294e625ac26ceaefb90f))
* **agent:** inject MEMORY.md into the system prompt to close the loop ([17f6516](https://github.com/argusappsec/argus/commit/17f6516a6d9c2faee3081dc38958ea42b3d2c829))
* batteries-included runtime image, doctor image-contract gate, CI/CD to GHCR ([#42](https://github.com/argusappsec/argus/issues/42)) ([182384f](https://github.com/argusappsec/argus/commit/182384f05cec489f9512d984a04f5e559399a8c1))
* **brand:** peacock-feather logo, Apache-2.0 license, org avatar ([445b119](https://github.com/argusappsec/argus/commit/445b1197978807430ee2a2c59b213f7f5225054d))
* built-in skills via embed.FS + Catalog + 5 bundled skills ([#14](https://github.com/argusappsec/argus/issues/14)) ([be76c4b](https://github.com/argusappsec/argus/commit/be76c4b6889cbf942b94e8f98d4318efdac65b02))
* **config,init:** auto-load ~/.argus/.env and prompt for API key in init ([2abe1af](https://github.com/argusappsec/argus/commit/2abe1afe031da2d7a8a6bd9b6d6d5435f9709657))
* **deploy:** Kubernetes hosting — Dockerfile, ADR 0012, hosting guide ([8fd1cf2](https://github.com/argusappsec/argus/commit/8fd1cf226106252ee7959939a5dee9b186814591))
* **doctor:** pre-flight check for binaries, config, SOUL, context ([078e9d9](https://github.com/argusappsec/argus/commit/078e9d921db5e0e92fe7aaeeb5bf72d243ad45e4))
* **github:** GitHub channel — automatic PR security reviews + conversational [@argus](https://github.com/argus) ([#24](https://github.com/argusappsec/argus/issues/24)) ([4eacfbe](https://github.com/argusappsec/argus/commit/4eacfbe1a42a3ff508b50ff1a2110a387613d6c1))
* **init,config:** huh-driven init form + argus.yaml ready for multi-provider ([27adbea](https://github.com/argusappsec/argus/commit/27adbea6f99c14538643ce2276327d2c764f46f6))
* **init:** add bootstrap interview command to create SOUL.md ([aeca865](https://github.com/argusappsec/argus/commit/aeca865c9a9fde0aacc173ded29acbea0fe42cb2))
* **mcp:** MCP channel — Argus as a consultable colleague ([#27](https://github.com/argusappsec/argus/issues/27)) ([#33](https://github.com/argusappsec/argus/issues/33)) ([5c34f2c](https://github.com/argusappsec/argus/commit/5c34f2cc4ae54e8f39a5fe918ab8d8cdf5518f2c))
* **memory:** add memory-curator subagent ([e3bcca8](https://github.com/argusappsec/argus/commit/e3bcca89bb096ab9e51fb9fade2f18e944c4ec18))
* **release:** release-please — changelog, semver bumps, GitHub Releases (ADR 0014) ([#43](https://github.com/argusappsec/argus/issues/43)) ([d8fc6de](https://github.com/argusappsec/argus/commit/d8fc6de432905366f1f2a46a0dcfd6ef59fe3bae))
* **review:** interactive by default, --headless for CI ([fcd5a55](https://github.com/argusappsec/argus/commit/fcd5a55c7f4f03a72340c3669be5c0ea9ce7d3ee))
* **skill:** built-in authz-audit white-box BOLA/BFLA skill ([#15](https://github.com/argusappsec/argus/issues/15)) ([25ccdfb](https://github.com/argusappsec/argus/commit/25ccdfb6393fcc5fe34ef14c506afe8324433292))
* skills ([#2](https://github.com/argusappsec/argus/issues/2)) ([dbb4715](https://github.com/argusappsec/argus/commit/dbb4715d8362a2b2f317ca75c33d02ad9a9cec80))
* thom ([356a632](https://github.com/argusappsec/argus/commit/356a632da67a280ac6f51427bb4c3a67d24797fe))
* **tool:** add write_context for agent-driven knowledge capture ([ae0a425](https://github.com/argusappsec/argus/commit/ae0a42500121a870ac0afec0f7d406d4bdddfd06))
* **tui,chat:** add interactive bubbletea chat with slash commands ([6772cc5](https://github.com/argusappsec/argus/commit/6772cc58220d008de273050e930ff5a4ffd3d616))
* **tui:** Claude Code-style chat layout with viewport and spinner ([f260d43](https://github.com/argusappsec/argus/commit/f260d4349340ed94fa5324ce915f88175b803d66))
* v0.2 — session-aware tools, conversation log, SOUL, context, start_review ([d8ddc54](https://github.com/argusappsec/argus/commit/d8ddc543070b06cd57b11cb0c8a11142f3e3f040))


### Bug Fixes

* **agent,chat,init:** preserve multi-turn context across agent runs ([e04ad08](https://github.com/argusappsec/argus/commit/e04ad0849c0bda70862b69a513e446bcb5897817))
* **agent,tui:** natural pause on text-only response + drop user echo ([d16d7a2](https://github.com/argusappsec/argus/commit/d16d7a299f30f9024a9265c38c2dac0014954225))
* **init:** avoid nil-pointer panic when starting the bootstrap interview ([2180fbb](https://github.com/argusappsec/argus/commit/2180fbbcc0f0154f3f9c54a9c82d1d345f7a26c7))
* **init:** exit the TUI after SOUL.md is written ([a00a4c9](https://github.com/argusappsec/argus/commit/a00a4c96d499460460683455f6017ec40e2a4182))
* **release:** bootstrap manifest at 0.0.1 so the first release is 0.1.0 ([#45](https://github.com/argusappsec/argus/issues/45)) ([4206c88](https://github.com/argusappsec/argus/commit/4206c88c98411fac11ed9ce25c613584f67b9d6d))
* **security:** gitleaks via temp file + tolerate exit-1 when report present ([98cbc1c](https://github.com/argusappsec/argus/commit/98cbc1ca65bc96b38a5f1e458459cdd1b91e9e60))
