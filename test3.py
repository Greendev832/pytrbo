import os
import random
import mysql.connector
from dotenv import load_dotenv
import BotUtil
import TradeUtil
load_dotenv()


conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database=os.getenv("DATABASE")
)
cursor = conn.cursor()

def getTradeBotBalance():
    try:
        cnt = 0
        mId = 0
        cursor.execute("SELECT MAX(balance), count(*) FROM trade")
        results = cursor.fetchall()
        print(results[0][0], ' ', results[0][1])
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    print("start")
    getTradeBotBalance()
    # print(wordsList)
    # print(nounce)