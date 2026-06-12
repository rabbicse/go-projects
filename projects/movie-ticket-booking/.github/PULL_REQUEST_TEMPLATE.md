## Summary

<!-- 1–3 bullet points describing what this PR does -->

## Type of Change

- [ ] Bug fix (non-breaking — fixes an issue)
- [ ] Feature (non-breaking — adds functionality)
- [ ] Breaking change (changes existing API or behavior)
- [ ] Refactor (no functional changes)
- [ ] Documentation
- [ ] Infrastructure / DevOps

## Test Plan

- [ ] `make test-unit` passes
- [ ] `make lint` passes
- [ ] `npm run type-check` passes (if frontend changed)
- [ ] Manual testing steps:
  1. ...
  2. ...

## Layer Checklist

- [ ] Domain layer has no new external imports
- [ ] Business logic is in the application layer, not handlers
- [ ] New domain errors are typed sentinels in `domain/*/errors.go`
- [ ] New HTTP status mappings are added to `apierr/errors.go`

## Documentation

- [ ] `CLAUDE.md` updated (if commands, architecture, or config changed)
- [ ] Relevant `docs/` updated (if behavior changed)
- [ ] Swagger spec updated (if API changed) — run `make sync-swagger`

## Breaking Changes

<!-- Describe any breaking changes to the API or configuration -->
