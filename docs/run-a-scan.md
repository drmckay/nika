## CLI Help
Run Nika against a source code repository.

### Usage
`python3 main.py --path <PATH> [--lang <LANG>] [--output <FILE>] [--config <FILE>] [--source_branch <BRANCH>] [--target_branch <BRANCH>]`

### Arguments
- `--path` (required): Path to the source directory or git repository to analyze.
- `--lang` (optional, default: `java`, choices: `java`): Programming language of the codebase.
- `--output` (optional, default: `report.html`): Path to save the HTML report.
- `--config` (optional, default: `config/crtConfig.yml`): Path to the YAML config file.
- `--source_branch` (optional, default: `None`): Branch to analyze in the git repository.
- `--target_branch` (optional, default: `None`): Branch to compare against in the git repository.

### Examples
- `python3 main.py --path /path/to/source --lang java --output report.html`