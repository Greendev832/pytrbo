import json
import requests
from dune_client.types import QueryParameter
from dune_client.client import DuneClient
from dune_client.query import QueryBase
import pandas as pd

# Initialize Dune client
# API_KEY = os.getenv("DUNE_API_KEY")  # or replace with your key
API_KEY = "crEAUJpSrSTN6YAiA7jBXH0HgfKkkdtm"
dune = DuneClient(API_KEY)

# SQL query for early Ethereum addresses
sql_query = """
WITH first_seen AS (
    SELECT "from" AS address, MIN(block_time) AS first_tx_time
    FROM ethereum.transactions
    GROUP BY 1
)
SELECT *
FROM first_seen
WHERE first_tx_time >= TIMESTAMP '2014-01-30'
AND first_tx_time < TIMESTAMP '2015-12-31'
ORDER BY first_tx_time ASC
LIMIT 1000;
"""

# -----------------------------
# Submit query to Dune
# -----------------------------
query_id = 8401839

# Fetch results (wait until Dune finishes execution)
# -----------------------------
# Fetch results
# -----------------------------
# url = f"https://api.dune.com/api/v1/query/{query_id}/results"

# headers = {
# "X-DUNE-API-KEY": API_KEY
# }

# response = requests.get(url, headers=headers)

# print(response.status_code)
# print(response.text)
# query = QueryBase(
#     name="My Query",
#     query_id=query_id,
# )

# query_result = dune.run_query(query)
result = dune.get_latest_result('8401839', max_age_hours=8) 
print(len(result.result.rows))
    # Convert to DataFrame
df = pd.DataFrame(result.result.rows)


# -----------------------------
# Convert to pandas DataFrame
# -----------------------------
df = pd.DataFrame(result.result.rows)
print(df.head())
# -----------------------------
# Save to CSV
# -----------------------------
df.to_csv("early_bit__2014_out_addresses.csv", index=False)
print("Saved results to early_eth_bal_addresses.csv")