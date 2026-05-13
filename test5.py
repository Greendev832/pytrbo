import os
import mysql.connector
from decimal import Decimal, getcontext
from dotenv import load_dotenv
import requests
load_dotenv()

conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database=os.getenv("DATABASE")
)
cursor = conn.cursor()

def getBal(addr: str):
    req = requests.get(f"https://ethereum.atomicwallet.io/api/v2/address/{addr}")
    if req.status_code == 200:
        return dict(req.json())["balance"]
    else:
        return "0"


def func():
    val = getBal('0x742d35Cc6634C0532925a3b844Bc454e4438f44e')
    val = Decimal(val) / Decimal(10**18)
    print(val)
    # print(val)
    # if val > 0:
    #     print("ok")
    # sql = """
    # INSERT INTO testda (wo)
    # VALUES (%s)
    # ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id);
    # """

    # cursor.execute(sql, (word,))
    # conn.commit()

    # mId = cursor.lastrowid


if __name__ == "__main__":
    print("start")
    func()
