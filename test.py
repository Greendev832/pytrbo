import os
import random
import mysql.connector
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
from dotenv import load_dotenv
import TradeMain
load_dotenv()

global content_string
with open("setting.json", "r") as f:
    content_string = f.read()

# content_string = os.getenv("CONTENT_STRING")
nounce = os.getenv("NOUNCE")
wordsList = content_string.split("\\n")

conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database=os.getenv("DATABASE")
)
cursor = conn.cursor()

def assessValue(word):
    cursor.execute("SELECT id FROM data Where word=%s", (word,))
    results = cursor.fetchall()
    mId = results[0][0]


def makeLists():
    try:
        cnt = 0
        while(1):
            word = " ".join(random.sample(wordsList, int(nounce)))
            try:
                Bip39SeedGenerator(word).Generate()
                cursor.execute("SELECT * FROM data Where word=%s", (word,))
                results = cursor.fetchall()
                if len(results) == 0:
                    sql = "INSERT INTO data (word) VALUES (%s)"
                    cursor.execute(sql, (word,))
                    conn.commit()

                    cursor.execute("SELECT id FROM data Where word=%s", (word,))
                    tmpResults = cursor.fetchall()
                    mId = tmpResults[0][0]

                    TradeMain.assessBot(word, mId)
                    cnt += 1
                    print(cnt)
            except Exception as e:
                pass
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    print("start")
    makeLists()
