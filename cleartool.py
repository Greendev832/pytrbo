import os

# fileName = "tox.ini"

def clearFunc(fileName):
    finalList = []
    with open(fileName, "r") as f:
        splitedLists = f.read().splitlines()
        finalList = [line for line in splitedLists if not line.strip().startswith("#")]

    # print("\n".join(finalList))
    new_data = "\n".join(finalList)
    with open(fileName, "w") as file:
        file.write(new_data)

# fileName = "bottest.py"
# clearFunc(fileName)