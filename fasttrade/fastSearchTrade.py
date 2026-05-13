import os
import random
import mysql.connector
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
from dotenv import load_dotenv
import CusBotUtil
import CommonUtil
load_dotenv()

global content_string

# content_string = os.getenv("CONTENT_STRING")
nounce = os.getenv("NOUNCE")
wordsList = CommonUtil.get_words()

def compare(tar, soList):
    for so in soList:
        if tar.lower() == so.lower():
            return True
    return False

def searchTrades(tar):
    try:
        cnt = 0
        while(1):
            word = " ".join(random.sample(wordsList, int(nounce)))
            try:
                Bip39SeedGenerator(word).Generate()
                pri = None
                pu = None
                idx = 0
                for idx in range(0,5):
                    (pri, pu) = CusBotUtil.get_bot(word, idx)
                    if compare(pu, tar):
                        with open("searchTrade.txt", "a") as file:
                            file.write(pri+"\t"+pu+"\n")

                        with open("wordTrade.txt", "a") as file:
                            file.write(word+"\n")
                cnt += 1
                print(cnt)
            except Exception as e:
                pass
                # print(str(e))
    finally:
        pass

if __name__ == "__main__":
    print("start")
    tar = ["0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "0x8D18D00074DD99dE3e3F22210b705b9B0a19835a","0x6b032BC79811cFaE9D30d19C9FCdE27e62804D33","0x07964f135f276412b3182a3B2407b8dd45000000","0x7D45AB18086303B477d86a69B9a5E8D4F7b7d8c0"]
    searchTrades(tar)
