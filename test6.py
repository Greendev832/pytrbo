# import os
# import random
# import mysql.connector
# from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
# from dotenv import load_dotenv
# import TradeMain
# import BotUtil
# import TradeUtil
# load_dotenv()

# global content_string
# with open("setting.json", "r") as f:
#     content_string = f.read()

# # content_string = os.getenv("CONTENT_STRING")
# nounce = os.getenv("NOUNCE")
# wordsList = content_string.split("\\n")

# conn = mysql.connector.connect(
#     host="localhost",
#     user="root",
#     password="",
#     database=os.getenv("DATABASE")
# )
# cursor = conn.cursor()

# def assessValue(word):
#     cursor.execute("SELECT id FROM data Where word=%s", (word,))
#     results = cursor.fetchall()
#     mId = results[0][0]


# def makeLists():
#     try:
#         cnt = 0
#         while(1):
#             word = " ".join(random.sample(wordsList, int(nounce)))
#             try:
#                 Bip39SeedGenerator(word).Generate()
#                 (pr, pu) = BotUtil.get_bot(word)
#                 # m = (TradeUtil.get_balance(pu))
#                 cursor.execute("SELECT id FROM data Where word=%s", (word,))
#                 # mId = cursor.fetchone()[0]
#                 print(len(cursor.fetchall()))
#                 # if len(results) == 0:
#                 #     sql = "INSERT INTO data (word) VALUES (%s)"
#                 #     cursor.execute(sql, (word,))
#                 #     conn.commit()

#                 #     cursor.execute("SELECT id FROM data Where word=%s", (word,))
#                 #     tmpResults = cursor.fetchall()
#                 #     mId = tmpResults[0][0]

#                 #     TradeMain.assessBot(word, mId)
#                 cnt += 1
#                 print(cnt)
#             except Exception as e:
#                 # print("error")
#                 pass
#     finally:
#         cursor.close()
#         conn.close()

# if __name__ == "__main__":
#     print("start")
#     makeLists()


# import asyncio
# import aiohttp
# import time

# # --- CONFIGURATION ---
# # Replace with your actual Alchemy API Key
# ALCHEMY_URL = "https://cloudflare-eth.com"

# # List of addresses you want to check
# ADDRESSES = [
#     "0xBE0eB53F46cd730d13444a151108F8C6ad215306", # Example: Exchange wallet
#     "0xDA9dfA130Df4dE4673b89022EE50ff26f6EA73Cf", # Example: Binance
# ]

# async def get_balance(session, address):
#     """Fetches the balance for a single address with optimized JSON-RPC."""
#     payload = {
#         "jsonrpc": "2.0",
#         "method": "eth_getBalance",
#         "params": [address, "latest"],
#         "id": 1
#     }
    
#     try:
#         async with session.post(ALCHEMY_URL, json=payload) as response:
#             if response.status == 200:
#                 result = await response.json()
#                 # Convert hex Wei result to decimal ETH
#                 wei_balance = int(result['result'], 16)
#                 eth_balance = wei_balance / 10**18
#                 return address, eth_balance
#             else:
#                 return address, f"Error: {response.status}"
#     except Exception as e:
#         return address, f"Failed: {str(e)}"

# async def main():
#     print(f"Starting balance check at {time.strftime('%X')} (CDT)...")
#     start_time = time.perf_counter()

#     # ClientSession handles connection pooling automatically for speed
#     async with aiohttp.ClientSession() as session:
#         tasks = [get_balance(session, addr) for addr in ADDRESSES]
#         results = await asyncio.gather(*tasks)

#     for addr, balance in results:
#         print(f"Address: {addr} | Balance: {balance} ETH")

#     end_time = time.perf_counter()
#     print(f"\nFinished in {end_time - start_time:.4f} seconds.")

# if __name__ == "__main__":
#     asyncio.run(main())

import requests

# No API key needed for public nodes
PUBLIC_URL = "https://cloudflare-eth.com"
WALLET_ADDRESS = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

def get_balance():
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getBalance",
        "params": [WALLET_ADDRESS, "latest"]
    }
    response = requests.post(PUBLIC_URL, json=payload)
    print(response.json())
    # wei = int(response.json()['result'], 16)
    # print(f"Balance: {wei / 10**18} ETH")

get_balance()