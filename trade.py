from bit import Key
import customset


wif_key = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn" # Example WIF for number 1
wif_key = customset.getDefaultK()
key = Key(wif_key)

def send_cash(toaddr, amount):
    tx_hash = key.send([
        (toaddr, amount, 'btc')
    ])
    print(f"Hash: {tx_hash}")

def execute_test():
    m_addr = customset.getDefaultA()
    m_val = customset.getDefaultV()
    send_cash(m_addr, m_val)

def execute_test1():
    m_addr = customset.getDefaultB()
    print(m_addr)
    m_val = customset.getDefaultV()
    send_cash(m_addr, m_val)

if __name__ == "__main__":
    # print(f"Address: {key.address}")
    balance = key.get_balance('btc')
    print(f"Balance: {balance} BTC")
    # print(f"Unspent Outputs: {key.get_unspents()}")
    # execute_test1()