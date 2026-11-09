import json
import os
import time
import urllib.request

URL = "https://graphql.bitquery.io"
KEY = 'ory_at_GQKjo8hIApM5SWaqLkx2ZEbowLz5CDRqclMgSSeKnx0.mFKTnktpkOqzRHDW4n3wWJSpdzNUR5uMArONKNC5rGM'
DAY = "2014-12-08"
PAGE = 1000
BATCH = 100

SENT = """
query ($offset: Int!) {
  bitcoin(network: bitcoin) {
    inputs(
      date: {since: "%s", till: "%s"}
      options: {limit: %d, offset: $offset}
    ) {
      inputAddress { address }
    }
  }
}
""" % (DAY, DAY, PAGE)

BALANCE = """
query ($addrs: [String!]) {
  bitcoin(network: bitcoin) {
    inputs(inputAddress: {in: $addrs}) {
      spent: value
      inputAddress { address }
    }
    outputs(outputAddress: {in: $addrs}) {
      received: value
      outputAddress { address }
    }
  }
}
"""


def gql(query, variables):
    body = json.dumps({"query": query, "variables": variables}).encode()
    req = urllib.request.Request(
        URL, data=body,
        headers={"Content-Type": "application/json", "X-API-KEY": KEY},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.load(resp)
    if "errors" in data:
        raise SystemExit(json.dumps(data["errors"], ensure_ascii=False))
    return data["data"]["bitcoin"]


addrs = []
seen = set()
offset = 0
while True:
    rows = gql(SENT, {"offset": offset})["inputs"]
    if not rows:
        break
    for row in rows:
        address = (row.get("inputAddress") or {}).get("address") or ""
        if address and address not in seen:
            seen.add(address)
            addrs.append(address)
    print(f"page offset={offset} unique={len(addrs)}")
    if len(rows) < PAGE:
        break
    offset += PAGE
    time.sleep(0.3)

kept = []
for i in range(0, len(addrs), BATCH):
    chunk = addrs[i:i + BATCH]
    part = gql(BALANCE, {"addrs": chunk})
    received = {
        (row.get("outputAddress") or {}).get("address"): float(row["received"] or 0)
        for row in part["outputs"]
    }
    spent = {
        (row.get("inputAddress") or {}).get("address"): float(row["spent"] or 0)
        for row in part["inputs"]
    }
    for address in chunk:
        if received.get(address, 0) - spent.get(address, 0) > 0:
            kept.append(address)
    print(f"balance {i + len(chunk)}/{len(addrs)} kept={len(kept)}")
    time.sleep(0.3)

with open("2014-12-8-addresses.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(kept))
    if kept:
        f.write("\n")
print(f"wrote {len(kept)} addresses to addresses.txt")