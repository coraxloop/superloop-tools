The `superloop-lint` binary accepts these commands; each corpus command reads one configuration snapshot from `--root` before it runs, while `fmt` takes Markdown paths and has no root.

|Command|Purpose|
|-------|-------|
|`export --root ROOT --owner OWNER --out PATH`|Write one local owner's deterministic TOML registry; optional `--write-report FILE --write-stamp FILE` publishes a build report and success stamp.|
|`citation-sites --root ROOT`|Emit the check recognizer's resolved citation sites as versioned JSON (`class.linter.citation-sites` 1.0.0) for the public cut; addresses and paths only, never document text.|
|`check`|Judge the corpus and report findings.|
|`report`, `coverage`, `shape`|Describe the reference graph, claims and sizes.|
|`assemble`, `burn`, `project`, `fix`|Verify or maintain declared and generated surfaces.|
|`fmt`|Format Markdown or check its formatting.|

## Unit test matrix · `tab:superlooplint:bin-unit-test-matrix`

**Table (Unit test matrix)**

No unit tests in this folder.
