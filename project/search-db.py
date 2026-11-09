import os
import random
import mysql.connector
from sage.all import EllipticCurve, GF, inverse_mod, Integer

# global content_string
# with open("setting.json", "r") as f:
#     content_string = f.read()

# content_string = os.getenv("CONTENT_STRING")

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
E = EllipticCurve(GF(p), [0, 7])
G = E(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 
          0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="kbase"
)
cursor = conn.cursor()

def assessValue(word):
    cursor.execute("SELECT id FROM data Where word=%s", (word,))
    results = cursor.fetchall()
    mId = results[0][0]


def makeLists():
    try:
        cursor.execute("SELECT Max(id) FROM ktable", ())
        results = cursor.fetchall()
        print((results))
        idx = 0
        if (results[0][0]) == None:
            idx = 0
        else:
            idx = results[0][0]
        k = idx
        cnt = 0
        while(1):
            
            try:
                
                k  = k +1
                R = k * G
                r = Integer(R[0]) % n
                # print(R)
                # print(r)
                # break
                sql = "INSERT INTO ktable (k, r) VALUES (%s, %s)"
                cursor.execute(sql, (str(k),str(r)))
                conn.commit()

                # cursor.execute("SELECT id FROM data Where word=%s", (word,))
                # tmpResults = cursor.fetchall()
                # mId = tmpResults[0][0]

                
            except Exception as e:
                print(str(e))
                break
                pass
    finally:
        cursor.close()
        conn.close()

def get_x(k):
    try:                    
        # k  = k +1
        R = k * G
        r = Integer(R[0]) % n
        # print(R)
        print(r)
        print(f"{r:064x}")
        # break

        # cursor.execute("SELECT id FROM data Where word=%s", (word,))
        # tmpResults = cursor.fetchall()
        # mId = tmpResults[0][0]

    except Exception as e:
        print(str(e))


if __name__ == "__main__":
    print("start")
    # makeLists()
    get_x(pow(2, 64)+79)
