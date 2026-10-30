# CI workflow updates

The workflow changes for this branch are provided as a patch instead of a direct
edit because the automation token used to push the branch is not allowed to
modify `.github/workflows`:

```shell
git apply docs/ci/workflow-updates.patch
```

The patch:

* moves CI to Python 3.12 and removes the `prompt_toolkit`/`sed` workarounds
  (PyInquirer is no longer a dependency);
* adds a unit-test matrix for 3.11/3.12/3.13 that runs the standard-library
  test suite and `grapheneX --validate`;
* adds a Bandit and pip-audit job;
* fixes the Ruff workflow path filter (`grapheneX/**` -> `graphenex/**`).

**Until the patch is applied, the old workflow will fail**: it pins Python 3.10
(the project now requires 3.11+), patches a `prompt_toolkit` file that is no
longer installed, and upgrades `flask_socketio` outside of poetry.
