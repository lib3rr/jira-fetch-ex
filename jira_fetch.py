import click
import pandas as pd
from jira import JIRA
from jira.exceptions import JIRAError
from typing import List, Dict, Optional, Tuple
from pathlib import Path
import os
import json
import keyring
from click import progressbar
import flatten_json
import re
import time
import logging
import yaml
import requests
from requests_oauthlib import OAuth2Session
import webbrowser

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("jira_fetch.log")],
)
logger = logging.getLogger(__name__)


# Configuration
def load_config(config_path: Path = Path("config.yaml")) -> Dict:
    default_config = {
        "jira_url": os.getenv("JIRA_URL", "https://your-jira-instance.atlassian.net"),
        "output_dir": "jira_exports",
        "cache_dir": "jira_cache",
        "service_name": "jira_fetch_tool",
        "cache_max_age": 86400,
        "oauth_client_id": None,
        "oauth_client_secret": None,
        "oauth_redirect_uri": "http://localhost:8080/callback",
    }
    if config_path.exists():
        with open(config_path, "r") as f:
            user_config = yaml.full_load(f) or {}
        default_config.update(user_config)
    return default_config


CONFIG = load_config()

# OAuth 2.0 Settings
OAUTH_AUTH_URL = "https://auth.atlassian.com/authorize"
OAUTH_TOKEN_URL = "https://auth.atlassian.com/oauth/token"
OAUTH_SCOPES = ["read:jira-work", "offline_access"]  # Basic read scope + refresh token


def fetch_oauth_tokens(client_id: str, client_secret: str, redirect_uri: str) -> Dict:
    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=OAUTH_SCOPES)
    auth_url, state = oauth.authorization_url(
        OAUTH_AUTH_URL, audience="api.atlassian.com"
    )
    logger.info(f"Opening browser for OAuth authorization: {auth_url}")
    webbrowser.open(auth_url)
    redirect_response = click.prompt("Paste the full redirect URL after authorization")
    return oauth.fetch_token(
        OAUTH_TOKEN_URL,
        authorization_response=redirect_response,
        client_secret=client_secret,
    )


def refresh_oauth_token(client_id: str, client_secret: str, refresh_token: str) -> Dict:
    oauth = OAuth2Session(client_id)
    return oauth.refresh_token(
        OAUTH_TOKEN_URL, refresh_token=refresh_token, client_secret=client_secret
    )


def connect_to_jira(
    email: str = "",
    token: Optional[str] = None,
    auth_type: str = "basic",
    token_auth: Optional[str] = None,
) -> JIRA:
    if auth_type == "oauth":
        if not (CONFIG.get("oauth_client_id") and CONFIG.get("oauth_client_secret")):
            raise click.BadParameter(
                "OAuth requires client_id and client_secret in config.yaml"
            )
        token_file = Path("oauth_tokens.json")
        tokens = (
            json.load(token_file.open("r"))
            if token_file.exists()
            else fetch_oauth_tokens(
                CONFIG["oauth_client_id"],
                CONFIG["oauth_client_secret"],
                CONFIG["oauth_redirect_uri"],
            )
        )
        if time.time() > tokens.get("expires_at", 0):
            tokens = refresh_oauth_token(
                CONFIG["oauth_client_id"],
                CONFIG["oauth_client_secret"],
                tokens["refresh_token"],
            )
            with open(token_file, "w") as f:
                json.dump(tokens, f)
        try:
            return JIRA(
                server=CONFIG["jira_url"],
                oauth={"access_token": tokens["access_token"], "token_type": "Bearer"},
            )
        except JIRAError as e:
            raise click.BadParameter(f"Jira connection failed with OAuth: {e}")
    elif auth_type == "basic":
        if token_auth:
            try:
                return JIRA(server=CONFIG["jira_url"], token_auth=token_auth)
            except JIRAError as e:
                raise click.BadParameter(f"Jira connection failed with PAT: {e}")
        env_token = os.getenv("JIRA_API_TOKEN")
        if not token and not env_token:
            try:
                token = keyring.get_password("jira_fetch_tool", email)
            except keyring.errors.KeyringError:
                print("Keyring unavailable, using plain token")
            if not token:
                raise click.BadParameter(
                    "No token provided, stored, or set in JIRA_API_TOKEN environment variable"
                )
        token = token or env_token
        try:
            return JIRA(server=CONFIG["jira_url"], basic_auth=(email, token))
        except JIRAError as e:
            raise click.BadParameter(f"Jira connection failed: {e}")
    else:
        raise click.BadParameter("Auth type must be 'basic' or 'oauth'")


def build_jql_query(
    project: str, tags: Optional[List[str]] = None, custom_filters: Optional[str] = None
) -> str:
    if not project:
        raise click.BadParameter("Project key cannot be empty")
    base_query = f"project = {project}"
    if tags:
        tags_str = " AND ".join(f'labels = "{tag}"' for tag in tags if tag)
        base_query += f" AND {tags_str}"
    if custom_filters:
        base_query += f" AND {custom_filters}"
    return base_query


def fetch_issues(
    jira: JIRA, jql: str, batch_size: int = 100, retry_delay: int = 5
) -> List[Dict]:
    start_at = 0
    all_issues = []
    while True:
        try:
            issues = jira.search_issues(
                jql, startAt=start_at, maxResults=batch_size, fields=None
            )
            all_issues.extend(issue.raw for issue in issues)
            if len(issues) < batch_size:
                break
            start_at += batch_size
            logger.info(f"Fetched {start_at} issues...")
        except JIRAError as e:
            if e.status_code == 429:
                logger.warning(f"Rate limit hit, retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
                continue
            logger.error(f"Failed to fetch issues: {e}")
            raise click.BadParameter(f"Failed to fetch issues: {e}")
    return all_issues


def cache_issues(issues: List[Dict], project: str) -> Path:
    (Path("jira_cache") / project).mkdir(parents=True, exist_ok=True)
    cache_file = Path("jira_cache") / f"{project}_issues.json"
    with open(cache_file, "w") as f:
        json.dump(issues, f, indent=2)
    return cache_file


def load_cached_issues(project: str) -> Optional[List[Dict]]:
    cache_file = Path("jira_cache") / f"{project}_issues.json"
    if (
        cache_file.exists()
        and (time.time() - cache_file.stat().st_mtime) < CONFIG["cache_max_age"]
    ):
        try:
            with open(cache_file, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.warning(f"Corrupted cache file: {cache_file}. Ignoring")
    return None


def extract_key_value_pairs(description: str) -> List[Tuple[str, str]]:
    if description is None:
        return []  # Return empty list if description is None
    return [
        (k.strip(), v.strip())
        for line in description.split("\n")
        if ":" in line
        for k, v in [line.split(":", 1)]
    ]


def flatten_issue(issue: Dict, simplify: bool = False) -> Dict:
    flat = flatten_json.flatten(issue, separator="_")
    if simplify:
        flat = {
            k: str(v) if isinstance(v, (dict, list)) else v for k, v in flat.items()
        }
    return flat


def filter_issues(issues: List[Dict], filter_expr: Optional[str]) -> List[Dict]:
    if not filter_expr:
        return issues
    return [
        issue
        for issue in issues
        if (
            ":" in filter_expr
            and any(
                re.search(
                    filter_expr.split(":")[1],
                    str(flatten_issue(issue).get(filter_expr.split(":")[0], "")),
                    re.IGNORECASE,
                )
            )
        )
        or re.search(filter_expr, str(flatten_issue(issue).values()), re.IGNORECASE)
    ]


def extract_fields(issues: List[Dict], fields: List[str]) -> List[Dict]:
    return [
        {
            "key": issue["key"],
            **{field: flatten_issue(issue).get(field, "N/A") for field in fields},
        }
        for issue in issues
    ]


def list_available_fields(issues: List[Dict]) -> List[str]:
    return sorted({k for issue in issues for k in flatten_issue(issue).keys()})


def save_to_file(data, filename, format):
    output_dir = Path("jira_exports")
    output_dir.mkdir(exist_ok=True)
    output_path = output_dir / f"{filename}.{format}"
    df = pd.DataFrame(data)
    if format == "csv":
        df.to_csv(output_path, index=False)
    elif format == "xlsx":
        df.to_excel(output_path, index=False)
    elif format == "json":
        df.to_json(output_path, orient="records", indent=2)
    else:
        raise ValueError(f"Unsupported format: {format}")
    logger.info(f"Data saved to {output_path}")


@click.command()
@click.option("-e", "--email", help="Email for basic auth")
@click.option(
    "-t",
    "--token",
    help="API token or password for basic auth (optional, defaults to JIRA_API_TOKEN env var)",
    hide_input=True,
    default=None,
)
@click.option(
    "-p", "--project", prompt="Project Key", help="Jira project key", required=True
)
@click.option(
    "-tag",
    "--tags",
    multiple=True,
    help="Tags/labels to filter issues (e.g., --tags bug)",
)
@click.option(
    "-f", "--fields", help="Fields to extract (comma-separated, optional)", default=None
)
@click.option(
    "-cf", "--custom-filter", help="Additional JQL filter (e.g., 'status = Done')"
)
@click.option(
    "-o", "--output", default="jira_export", help="Output filename (without extension)"
)
@click.option(
    "-fmt",
    "--format",
    type=click.Choice(["csv", "xlsx", "json"]),
    default="csv",
    help="Output format",
)
@click.option(
    "-fe",
    "--filter-expr",
    help="Post-fetch filter (e.g., 'fields_summary:bug' or 'bug')",
)
@click.option("-dr", "--dry-run", is_flag=True, help="Print first 5 results to console")
@click.option("-lf", "--list-fields", is_flag=True, help="List all available fields")
@click.option("-uc", "--use-cache", is_flag=True, help="Use cached data if available")
@click.option("-rc", "--refresh-cache", is_flag=True, help="Force refresh of cache")
@click.option(
    "-s", "--simplify", is_flag=True, help="Convert complex field types to strings"
)
@click.option(
    "-at",
    "--auth-type",
    default="basic",
    type=click.Choice(["basic", "oauth"]),
    help="Authentication type",
)
@click.option(
    "-ta",
    "--token-auth",
    default=None,
    help="Personal Access Token for Jira Server/Data Center",
)
@click.option(
    "-pd",
    "--parse-description",
    is_flag=True,
    help="Parse 'Key: Value' pairs from description",
)
def fetch_jira_data(
    email,
    token,
    project,
    tags,
    fields,
    custom_filter,
    output,
    format,
    filter_expr,
    dry_run,
    list_fields,
    use_cache,
    refresh_cache,
    simplify,
    auth_type,
    token_auth,
    parse_description,
):
    try:
        if token and auth_type == "basic":
            keyring.set_password("jira_fetch_tool", email, token)

        jira = connect_to_jira(email, token, auth_type, token_auth)
        jql = build_jql_query(project, tags, custom_filter)
        logger.info(f"Executing JQL: {jql}")

        issues = (
            load_cached_issues(project)
            if use_cache and not refresh_cache
            else fetch_issues(jira, jql) if not use_cache or refresh_cache else None
        )
        if not issues:
            logger.info("No issues found")
            return

        if list_fields:
            logger.info("Available fields:")
            for field in list_available_fields(issues):
                click.echo(f"  - {field}")
            return

        issues = filter_issues(issues, filter_expr) if filter_expr else issues

        if parse_description:
            rows = []
            specified_fields = fields.split(",") if fields else []
            for issue in issues:
                issue_key = issue["key"]
                issue_fields = issue.get("fields", {})
                row_data = {"Issue Key": issue_key}
                for field in specified_fields:
                    row_data[field] = issue_fields.get(field, "N/A")

                description = issue_fields.get("description", "")
                for key, value in extract_key_value_pairs(description):
                    row = row_data.copy()
                    row["Description Key"] = key
                    row["Description Value"] = value
                    rows.append(row)

            if dry_run:
                logger.info("Dry run output (first 5 results):")
                for row in rows[:5]:
                    click.echo(row)
                if len(rows) > 5:
                    click.echo(f"... (first 5 shown, total {len(rows)} rows)")
            else:
                save_to_file(rows, output, format)
        else:
            processed_data = (
                extract_fields(issues, [f.strip() for f in fields.split(",")])
                if fields
                else list(map(lambda i: flatten_issue(i, simplify), issues))
            )
            if dry_run:
                logger.info("Dry run output (first 5 results):")
                click.echo(json.dumps(processed_data[:5], indent=2))
                if len(processed_data) > 5:
                    click.echo(f"... (first 5 shown, total {len(processed_data)} rows)")
            else:
                save_to_file(processed_data, output, format)

    except click.BadParameter as e:
        logger.error(f"Error: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise


if __name__ == "__main__":
    fetch_jira_data()
