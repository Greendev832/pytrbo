import os

A_PATH = "test.pm"
V_PATH = "val.pm"
def getDefaultA():
    with open(A_PATH, "r") as f:
        content_string = f.read()
    wList = content_string.split("\n")
    return wList[0]

def getDefaultV():
    with open(V_PATH, "r") as f:
        content_string = f.read()
    wList = content_string.split("\n")
    return float(wList[0])

def setV(val):
    if os.path.exists(V_PATH):
        with open(V_PATH, 'w') as file:
            pass
        with open(V_PATH, "a") as file:
            file.write(str(val))
    else:
        with open(V_PATH, "a") as file:
            file.write(str(val))

setV(0.0001)
print(getDefaultV())