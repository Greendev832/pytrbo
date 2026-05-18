import os
import botr
import bottest2
# import botmul

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
    tokes = get_lists()
    print(len(tokes))
    tokens = []
    for toke in tokes:
        # print(toke)
        result = {}
        result = bottest2.extract_params_type2(toke)
        if result["type"] == 2:
            tokens.append((result["e"], result["r"], result["s"]))

    # botmul.solve_hnp_with_lll(tokens)
    # results = []
    # results = botr.find_shared_r(tokes)
    # print(results)

main()