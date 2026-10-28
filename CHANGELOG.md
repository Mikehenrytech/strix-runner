# Changelog

All notable changes are recorded here. This project follows semantic versioning.

## 1.12.0

- Add `Run Dir` column to the compact history table (`history --all`).
- Add `Model` column to the history table and details view.
- Show model information extracted from `run.json` (`llm_usage.agents[].model`).
- Include `run_dir_relative` and `models` in history JSON and HTML exports.

## 1.11.0

- Profile-based launcher for Strix pentests.
- Save and run named application profiles with multiple URLs and code paths.
- Local application lifecycle management with start/stop commands.
- Configuration verification and atomic writes.
- Historical run browsing with JSON and standalone HTML exports.
- Native interactive session resumption.
- Read-only web dashboard moved to the `strix-runner-dashboard` repository.
