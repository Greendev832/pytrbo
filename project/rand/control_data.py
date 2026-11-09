import json

def load_data():
    content = ""
    with open("dice_address.txt", "r", encoding="utf-8") as file:
        content = file.read()

    raws = content.split("\n")
    result_list = []
    for raw in raws:
        if raw != "":
            word_list = raw.split("\t")
            print(word_list)
            print(len(word_list))
            result = {}
            result["label"] = word_list[0][:5]
            result["time"] = int(word_list[1])*1000
            result['target'] = []
            for idx in range(2, len(word_list)):
                integer_r = int(word_list[idx], 16)
                result['target'].append(integer_r)
                # result['target'].append(word_list[idx])
            # print(result)
            result_list.append(result)
    print(result_list)
    return result_list
    

if __name__ == "__main__":
    result_list =  load_data()
    with open("tar_addresses.json", "w", encoding="utf-8") as f:
        json.dump(result_list, f, indent=4)
