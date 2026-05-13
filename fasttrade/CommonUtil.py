import os
from dotenv import load_dotenv

wordsList = []

def get_words():
    global wordsList
    if wordsList == []:
        content_string = ""
        with open("setting.json", "r") as f:
            content_string = f.read()
        wordsList = content_string.split("\\n")
    return wordsList
