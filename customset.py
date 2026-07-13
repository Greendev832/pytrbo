import os

A_PATH = "test.pm"
B_PATH = "test1.pm"
V_PATH = "val.pm"
K_PATH = "ke.pm"
VAL_PATH = "number.pm"

def get_num():
    with open(VAL_PATH, "r") as f:
        content_string = f.read()
    wList = content_string.split("\n")
    return int(wList[0])

def set_num(val):
    if os.path.exists(VAL_PATH):
        with open(VAL_PATH, 'w') as file:
            pass
        with open(VAL_PATH, "a") as file:
            file.write(str(val))
    else:
        with open(VAL_PATH, "a") as file:
            file.write(str(val))

def getDefaultA():
    with open(A_PATH, "r") as f:
        content_string = f.read()
    wList = content_string.split("\n")
    return wList[0]

def getDefaultB():
    with open(B_PATH, "r") as f:
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

def getDefaultK():
    with open(K_PATH, "r") as f:
        content_string = f.read()
    wList = content_string.split("\n")
    return (wList[0])

def setK(val):
    if os.path.exists(K_PATH):
        with open(K_PATH, 'w') as file:
            pass
        with open(K_PATH, "a") as file:
            file.write(str(val))
    else:
        with open(K_PATH, "a") as file:
            file.write(str(val))

setV(0.0001)
print(getDefaultV())