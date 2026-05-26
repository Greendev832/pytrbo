import os
import random
# import mysql.connector
# from dotenv import load_dotenv
import BotUtil
from eth_account import Account
import TradeUtil
# load_dotenv()

botW = ""
with open("1.txt", "r") as f:
    botW = f.read()
# (pr, pu) = BotUtil.get_bot(botW)
pr = botW
if len(pr) == 64:
    hex_part = botW.replace("0x", "")
    fixed_hex = hex_part.zfill(64)
    pr = "0x" + fixed_hex

# Derive the account object
account = Account.from_key(pr)

pu = account.address
m = (TradeUtil.get_balance(pu))
print(pu)
if m > 0:
    print("yes")