import os
import random
import mysql.connector
from dotenv import load_dotenv
import BotUtil
import TradeUtil
load_dotenv()

botW = ""
with open("1.txt", "r") as f:
    botW = f.read()

(pr, pu) = BotUtil.get_bot(botW)
# m = (TradeUtil.get_balance(pu))
print(pu)
# if m > 0:
#     print("yes")