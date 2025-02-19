# Example Jira Fetch Tool 

An example Python CLI tool to fetch and process Jira issue data, exporting it to Excel, CSV, or JSON. Supports filtering, caching, and multiple authentication methods.

## Features
- Fetches fields from Jira issues for a specified project.
- Supports basic auth (email + API token/password), Personal Access Tokens (PATs), and OAuth 2.0 (3LO).
- Filters issues via JQL and post-fetch expressions (e.g., `fields_summary:bug`).
- Processes data in parallel for performance.
- Caches results locally to avoid repeated API calls.
- Exports to `xlsx`, `csv`, or `json` with incremental saving for large datasets.
- Lists available fields with `--list-fields`.
- Logs activity to `jira_fetch.log`.

## Requirements
- Python 3.8+
- [Poetry](https://python-poetry.org/) for dependency management
- Jira instance (Cloud or Server/Data Center)

## Installation
1. Clone or download this repository to your local machine:
   ```bash
   git clone <repository-url> jira_fetch
   cd jira_fetch
   ```
   Or manually create a jira_fetch directory and add the provided files.

2. Install Poetry if you don't have it yet:
   ```bash
   pip install poetry
   ```
   This installs the Poetry tool globally.

3. Set up the project with Poetry:
   ```bash
   poetry install
   ```
   This command:
   - Creates a virtual environment automatically (typically in ~/.cache/pypoetry/virtualenvs or a local .venv)
   - Installs all dependencies listed in pyproject.toml
   - Makes the jira-fetch command available within the virtual environment

4. Verify setup by checking the version:
   ```bash
   poetry run jira-fetch --version
   ```

5. (Optional) Create a config.yaml file in the jira_fetch directory (see Configuration).

## Configuration
Create a config.yaml file in the project directory to customize settings:

```yaml
jira_url: "https://your-jira-instance.atlassian.net"
output_dir: "exports"
cache_dir: "cache"
cache_max_age: 43200  # 12 hours in seconds
oauth_client_id: "your-client-id"  # For OAuth 2.0
oauth_client_secret: "your-client-secret"  # For OAuth 2.0
oauth_redirect_uri: "http://localhost:8080/callback"  # For OAuth 2.0
```

Authentication options:
- Jira Cloud: Generate an API token [here](https://id.atlassian.com/manage/api-tokens) and set as JIRA_API_TOKEN environment variable
- Jira Server/Data Center: Use a username/password or PAT (if enabled)
- OAuth 2.0: Register an app in the Atlassian Developer Console to get client_id and client_secret

## Usage
Run the script using Poetry's virtual environment:

### Option 1: Activate the Virtual Environment
```bash
poetry shell
```
This activates the virtual environment; you'll see a prompt change (e.g., (jira-fetch-py3.8)).
Then use the script directly:
```bash
jira-fetch --help
```

### Option 2: Run Without Activating Shell
Use poetry run to execute commands without entering the shell:
```bash
poetry run jira-fetch --email user@example.com --project PROJ --format csv
```

## Examples

### Basic Auth (Jira Cloud)
First, set your API token:
```bash
export JIRA_API_TOKEN=your-api-token
```
Then run the command:
```bash
poetry run jira-fetch --email user@example.com --project PROJ --format csv
```

### Personal Access Token (Jira Server/Data Center)
```bash
poetry run jira-fetch --token-auth xyz789 --project PROJ --dry-run
```

### OAuth 2.0 (Jira Cloud)
```bash
poetry run jira-fetch --auth-type oauth --project PROJ --list-fields
```
Follow the browser prompt to authorize, then paste the redirect URL.

### List Available Fields
```bash
poetry run jira-fetch --email user@example.com --project PROJ --list-fields
```

### Filter and Export
```bash
poetry run jira-fetch --email user@example.com --project PROJ --fields "fields_summary,fields_assignee_name" --filter-expr "fields_summary:bug" --format json
```

## Options
- `--email`: Email for basic auth
- `--auth-type`: basic (default) or oauth
- `--project`: Jira project key (required)
- `--tags`: Filter by labels (multiple allowed)
- `--fields`: Comma-separated fields to extract (optional)
- `--custom-filter`: Additional JQL filter
- `--output`: Output filename
- `--format`: xlsx, csv, or json
- `--filter-expr`: Post-fetch filter (e.g., field:pattern)
- `--dry-run`: Preview first 5 results
- `--list-fields`: Show all available fields
- `--use-cache`: Use cached data
- `--refresh-cache`: Force API fetch
- `--simplify`: Convert complex fields to strings

## OAuth 2.0 Setup
1. Register an app in the Atlassian Developer Console
2. Set oauth_client_id, oauth_client_secret, and oauth_redirect_uri in config.yaml
3. Run with --auth-type oauth; authorize in the browser when prompted
4. Tokens are stored in oauth_tokens.json and refreshed automatically

## Logging
Logs are written to jira_fetch.log for debugging and auditing.

## Limitations
- Excel output limited to 1,048,576 rows
- OAuth requires manual redirect URL pasting (CLI limitation)
- Large datasets may consume significant memory; use --simplify or --format json for efficiency

## Troubleshooting
- Check jira_fetch.log for errors
- Ensure jira_url matches your instance
- Verify auth credentials or OAuth setup if connection fails
- Run poetry check to validate pyproject.toml
