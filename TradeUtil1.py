from web3 import Web3
from decimal import Decimal, getcontext
import os

getcontext().prec = 50  # high precision
RPC_URL = "https://Mainnet.infura.io/v3/47b321fdde0c47dba9d6bb3fbdda726c"
w3 = Web3(Web3.HTTPProvider(RPC_URL))

def get_balance(address):
    checksum = Web3.to_checksum_address(address)

    balance_wei = w3.eth.get_balance(checksum)

    # precise conversion
    balance_eth = Decimal(balance_wei) / Decimal(10**18)

    return balance_eth

# addr = "0xf8AFf1b46E30ecBB6BFAD49513f18c4f31E3661e"
# balance = get_balance(addr)

# print("Exact balance:", balance)