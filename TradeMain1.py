import os
import random
import mysql.connector
from dotenv import load_dotenv
import BotUtil
import TradeUtil1
load_dotenv()
tCount = 0
sCount = 0

conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database=os.getenv("DATABASE")
)
cursor = conn.cursor()

def assessBot(botW, mId):
    global tCount, sCount
    pu = None
    try:
        (pr, pu) = BotUtil.get_bot(botW)
    except Exception as e:
        print(str(e))
    if pu != None:
        sql = "INSERT INTO bot (mId, pr, pu) VALUES (%s, %s, %s)"
        cursor.execute(sql, (mId, pr, pu))
        conn.commit()

        m_balance = TradeUtil1.get_balance(pu)
        # if m_balance >= 0:
        sql = "INSERT INTO trade (mId, balance) VALUES (%s, %s)"
        cursor.execute(sql, (mId, m_balance))
        conn.commit()
        sCount += 1
        tCount += 1
        # print(tCount," ", sCount )

def makeLists():
    try:
        cnt = 0
        mId = 0
        cursor.execute("SELECT MAX(mId) FROM bot")
        results = cursor.fetchall()
        if results[0][0] == None:
            mId = 0
        else:
            mId = int(results[0][0])
        mId += 1
        print(mId)
        while(1):
            cursor.execute("SELECT id, word FROM data Where id=%s", (mId,))
            results = cursor.fetchall()
            if len(results) > 0:
                botW = results[0][1]
                assessBot(botW, mId)
                # print(mId, " ", results[0][0])
                cnt += 1
                # print(cnt)
                mId += 1
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    print("start")
    makeLists()
