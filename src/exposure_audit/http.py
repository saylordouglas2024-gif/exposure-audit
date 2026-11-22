"""A small shared HTTP session with sane defaults."""

from __future__ import annotations

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import USER_AGENT

TIMEOUT = 15


def session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    retry = Retry(total=2, backoff_factor=0.5, status_forcelist=(502, 503, 504),
                  allowed_methods=("GET", "HEAD"))
    s.mount("https://", HTTPAdapter(max_retries=retry, pool_maxsize=16))
    return s
