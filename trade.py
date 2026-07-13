from bit import Key
import customset


wif_key = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsrgZpynSTU" # Example WIF for number 1
key = Key(wif_key)

def send_cash(toaddr, amount):
    tx_hash = key.send([
        (toaddr, amount, 'btc')
    ])
    print(f"Hash: {tx_hash}")

if __name__ == "__main__":
    print(f"Address: {key.address}")
    balance = key.get_balance('btc')
    print(f"Balance: {balance} BTC")
    print(f"Unspent Outputs: {key.get_unspents()}")

    m_addr = customset.getDefaultA()
    m_val = customset.getDefaultV()
    send_cash(m_addr, m_val)