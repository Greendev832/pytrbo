from google.cloud import bigquery

client = bigquery.Client()

query = """
SELECT DISTINCT from_address 
FROM `bigquery-public-data.crypto_ethereum.transactions` 
LIMIT 1000
"""

query_job = client.query(query)
for row in query_job:
    print(row.from_address)