# Plan de calidad SkillSentry — código limpio, estable y profesional

**Fecha:** 21-oct-2026 · **Estado:** baseline auditado (56/56 tests, build limpio) · **Objetivo:** nivel competitivo DEV Challenge S4 (26–31 oct)

## 1. Veredicto de la auditoría

El núcleo está **bien construido**: separación limpia parser/reglas/scanner/report, reglas puras y documentadas, mapeo a OWASP LLM/AST10/MCP en cada finding, cero dependencias runtime, TS estricto, 56 tests. La arquitectura no necesita reescritura — necesita **corrección de defectos confirmados, blindaje de determinismo y señales profesionales** que un jurado técnico busca en los primeros 5 minutos.

## 2. Defectos confirmados con repro (P0)

| # | Defecto | Evidencia | Impacto |
|---|---------|-----------|---------|
| D1 | `--no-color` es no-op | CLI emite 390 bytes con escapes ANSI con y sin flag. `enabled` se captura al importar `util/text.ts`; `parseArgs` setea `NO_COLOR` después | Flag roto en producción/CI pipes |
| D2 | Estado residual de regex `/g` compartidos entre escaneos | Mismo archivo B: 1 finding CRITICAL solo, **0** tras escanear A (`obfuscation.ts:64` hace `.test()` sin resetear `lastIndex`) | **No-determinismo**: falsos negativos dependientes del orden de archivos. Grave para una herramienta de seguridad |
| D3 | Blobs base64/hex duplican findings | 96×`A` matchea BASE64_BLOB **y** HEX_BLOB → dos findings idénticos 9.5 | Ruido, parece descuidado en una demo ante jueces |
| D4 | `--ai-timeout abc` → `setTimeout(NaN)` | `Number(argv[++i] ?? 20000)` sin validar | NaN aborta el request inmediatamente: capa AI "rota" silenciosa |
| D5 | Código muerto: `const started = Date.now(); void started;` (scanner.ts), `aiCanRaise` sin usos (ai.ts) | grep: 0 referencias | Smell de limpieza; API pública con función muerta |
| D6 | Frontmatter multilinea (YAML `|`/`>`) se pierde | `description: |` captura literal `"|"`; líneas indentadas ignoradas | Skills reales usan descripciones multilinea → superficie de escaneo incompleta |
| D7 | BOM inicial rompe el reconocimiento de frontmatter | `\uFEFF---` no matchea `^---` | Falso "sin frontmatter" en archivos de Windows/editor |
| D8 | Evidencia de SS-007 construida con needle compuesto que puede no existir en el texto | `evidenceFor(text, verb+slice)` → cae al fallback de 180 chars sin relación | Evidencia engañosa en reportes |

## 3. Mejoras priorizadas

### P0 — Corrección (implementar ya)
1. **Colores dinámicos**: `ansi` consulta `process.env.NO_COLOR` en cada render (sin captura de import-time).
2. **Política "cero estado regex compartido"**: helper `firstMatch(re, text)` que clona el patrón; migrar las 9 reglas. Elimina la clase entera de D2.
3. **Dedupe de blobs solapados** (D3): si dos patrones matchean el mismo span, un solo finding.
4. **CLI robusto** (D4): validar `--ai-timeout` finito > 0; `--version` lee `package.json` (sin drift); exportar `parseArgs` puro para testear.
5. **Parser endurecido** (D6, D7): block scalars `|`/`|-`/`>`/`>-`, strip BOM, tests CRLF/comillas.
6. **Evidencia honesta** (D8): SS-007 usa el ítem como needle.
7. **Limpieza** (D5): eliminar dead code.

### P1 — Estabilidad demostrable (tests que cazan la clase de bug)
8. **`test/determinism.test.ts`**: (a) mismo input 2× → salida idéntica; (b) orden A,B vs B,A → mismos per-file findings (regresión D2); (c) findings estables tras 5 escaneos.
9. **`test/cli.test.ts`**: `parseArgs` puro — flags, `--fail-on` inválido, timeout no numérico, paths default.
10. **Parser edge cases**: multilinea, BOM, CRLF, listas con comillas.
11. **`noUncheckedIndexedAccess: true`** en tsconfig + corregir los errores que destape (estándar TS profesional).
12. **Dashboard**: límite de tamaño en `POST /api/scan` (400k chars → 413) — DoS local trivial hoy.

### P1 — Profesionalismo (señales para el jurado)
13. **ESLint 9 flat config + typescript-eslint**, 0 warnings exigidos en CI (dev-deps; la promesa de 0 deps *runtime* se mantiene).
14. **Scripts**: `typecheck`, `lint`; **CI**: `npm ci` (reproducible) + steps lint/typecheck + self-scan (ya existía).
15. **Docs**: `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md` (Keep a Changelog), bump **0.2.0**.
16. **README**: sección Provenance (genealogía y referencias), nota de determinismo garantizado por test.

### P2 — Roadmap post-challenge (documentado, no implementar hoy)
- Cobertura con `@vitest/coverage-v8` + badge · SARIF para GitHub code scanning · benchmarks · property-based tests (fast-check) · `skillsentry diff` (rug-pull).

## 4. Criterios del jurado → acción de este plan

| Criterio S4 | Evidencia tras el plan |
|---|---|
| Calidad de ingeniería | 0 bugs conocidos, ESLint limpio, TS hiper-estricto, CI con `npm ci` |
| Estabilidad | Suite de determinismo explícita; fixtures adversariales como tests de regresión |
| Profesionalismo | CHANGELOG/CONTRIBUTING/SECURITY, versionado semántico, docs por regla |
| Uso de IA open-source | ya cubierto (capa semántica Ollama/Gemma, degradación elegante) |
| Seguridad del propio repo | dogfooding self-scan en CI + masking de secretos (ya existía) |

## 5. Presupuesto y orden de ejecución

- **Hoy (local, 0 acciones GitHub):** P0 completo + P1 (tests, tsconfig, eslint, dashboard guard, docs, CI).
- **Mañana (anti-ban renovado):** push del commit de calidad v0.2.0 + tag; verificar CI verde en remoto.
- **Criterio de aceptación:** `npm test` verde (≥ 70 tests), `npm run lint` 0 warnings, `npm run typecheck` limpio, build + self-scan OK, misma demo visual sin regresiones.
