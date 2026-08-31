# Golden fixtures for layout_v2 + coverage

Each fixture has an `input/` (recorded discovery + namespace metadata) and an
`expected/` (the byte-equal tree `GenerateLayoutV2` + `BuildCoverage` +
`MarshalCoverage` produce for that input). `fixture_golden_test.go` loads
both, runs the pipeline, and asserts byte equality.

The rule the expected/ trees lock in is documented in
[`../../../../docs/architecture/ADR-016-amendment-flux-standard-alignment.md`](../../../docs/architecture/ADR-016-amendment-flux-standard-alignment.md)
(owner-follows-tier, applied across namespaces, app-scoped CRs, and
the values patch). If a fixture diff doesn't match what that rule
prescribes, the engine changed in a way that should be either reverted
or recorded as a new amendment to the note.

## Fixtures

- **mature-tenant-prd** — mature tenant cluster. Exercises:
  helm matched/unmatched mix, native CRs (Kafka, KafkaTopic, KafkaUser,
  ScaledObject), tier-aware namespace placement (infrastructure-tier
  namespaces routed to `infrastructure/configs/`, app namespaces routed
  to `apps/<env>/`), namespace metadata preservation, and the
  base/env split with patches.
- **fresh-tenant-dev** — fresh tenant cluster. Exercises the
  empty→populated `infrastructure/configs/` transition: the observability
  namespace lands there and is the only thing in `infrastructure/configs/`,
  so the cluster pointer files gain a synthesized `infra-configs` Flux
  Kustomization and the `apps` Kustomization's `dependsOn` chain
  re-orders. This coverage was added when the namespace placement rule
  was made tier-aware (see `layout_paths.go::classifyNativeTier`).

## Updating expected/

If a layout change is intentional, regenerate the produced tree and
overwrite `expected/` from it:

```
go run ./cmd/gitops-fixture-dump \
  --fixture internal/gitops/testdata/<fixture> \
  --cluster <cluster> --env <env> \
  --out /tmp/dump
rm -rf internal/gitops/testdata/<fixture>/expected
cp -R /tmp/dump internal/gitops/testdata/<fixture>/expected
```

Diff the change before committing. The expected/ tree is the spec; a
silent re-record loses the property the fixtures exist to protect.
