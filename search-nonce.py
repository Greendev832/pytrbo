import math
import pandas as pd
import json
import secrets
import random
from collections import Counter, defaultdict

# secp256k1 curve order
N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)


def to_int(x):
    x = str(x).lower().replace("0x", "").strip()
    return int(x, 16)


def leading_zero_bits(x, bits=256):
    return bits - x.bit_length() if x else bits


def chi_square_buckets(rs, bucket_count=256):
    expected = len(rs) / bucket_count
    buckets = [0] * bucket_count

    for r in rs:
        b = min((r * bucket_count) // N, bucket_count - 1)
        buckets[b] += 1

    chi2 = sum((obs - expected) ** 2 / expected for obs in buckets)
    return chi2, buckets


def shannon_entropy(values):
    total = len(values)
    counts = Counter(values)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def bit_frequency(rs):
    out = []
    n = len(rs)

    for bit in range(256):
        ones = sum((r >> bit) & 1 for r in rs)
        ratio = ones / n
        out.append({
            "bit": bit,
            "ones": ones,
            "zeros": n - ones,
            "one_ratio": ratio,
            "deviation": abs(ratio - 0.5)
        })

    return out


def leading_zero_histogram(rs):
    return dict(Counter(leading_zero_bits(r) for r in rs))


def monte_carlo_chi_pvalue(observed_chi, sample_size, rounds=5000):
    """
    Empirical p-value:
    how often random uniform r-values produce chi-square >= observed.
    """
    hits = 0

    for _ in range(rounds):
        sim_rs = [secrets.randbelow(N - 1) + 1 for _ in range(sample_size)]
        sim_chi, _ = chi_square_buckets(sim_rs)

        if sim_chi >= observed_chi:
            hits += 1

    return hits / rounds


def chronological_windows(df, windows=4):
    if "time" not in df.columns:
        return []

    df = df.sort_values("time").reset_index(drop=True)
    size = max(1, len(df) // windows)

    results = []

    for i in range(windows):
        part = df.iloc[i * size:(i + 1) * size] if i < windows - 1 else df.iloc[i * size:]
        if len(part) < 30:
            continue

        rs = [to_int(x) for x in part["r"]]
        chi, _ = chi_square_buckets(rs)

        results.append({
            "window": i + 1,
            "count": len(rs),
            "r_lt_n_2_pct": sum(r < N // 2 for r in rs) / len(rs) * 100,
            "r_lt_n_4_pct": sum(r < N // 4 for r in rs) / len(rs) * 100,
            "r_lt_n_8_pct": sum(r < N // 8 for r in rs) / len(rs) * 100,
            "chi_square_256": chi,
            "avg_leading_zero_bits": sum(leading_zero_bits(r) for r in rs) / len(rs),
        })

    return results

def runs_test_bit_sequence(bits):
    n = len(bits)
    
    if n < 2:
        return None

    pi = sum(bits) / n
    

    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return {
            "p_value": 0.0,
            "reason": "bit balance too biased for runs test"
        }

    runs = 1
    for i in range(1, n):
        if bits[i] != bits[i - 1]:
            runs += 1

    expected = 2 * n * pi * (1 - pi)
    variance = 2 * n * pi * (1 - pi) * (2 * n * pi * (1 - pi) - 1) / (n - 1)

    z = (runs - expected) / math.sqrt(variance)

    # two-sided normal approximation
    p = math.erfc(abs(z) / math.sqrt(2))

    return {
        "runs": runs,
        "expected": expected,
        "z_score": z,
        "p_value": p
    }


def runs_tests_for_r_bits(rs):
    results = []

    for bit in range(256):
        bits = [(r >> bit) & 1 for r in rs]
        test = runs_test_bit_sequence(bits)

        if test:
            test["bit"] = bit
            results.append(test)

    return sorted(results, key=lambda x: x["p_value"])

def pearson_corr(xs, ys):
    n = len(xs)
    if n < 3:
        return 0.0

    mx = sum(xs) / n
    my = sum(ys) / n

    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    dx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    dy = math.sqrt(sum((y - my) ** 2 for y in ys))

    if dx == 0 or dy == 0:
        return 0.0

    return num / (dx * dy)

def benjamini_hochberg(pvalues):
    """
    pvalues:
        [(bit, pvalue), ...]

    returns:
        [(bit, raw_p, adjusted_p)]
    """

    m = len(pvalues)

    ranked = sorted(pvalues, key=lambda x: x[1])

    adjusted = []

    prev = 1.0

    for i in reversed(range(m)):
        bit, p = ranked[i]

        q = min(prev, p * m / (i + 1))

        prev = q

        adjusted.append((bit, p, q))

    adjusted.reverse()

    return adjusted

def serial_correlation_tests(rs):
    if len(rs) < 3:
        return {}

    low = [r & 0xff for r in rs]
    high = [(r >> 248) & 0xff for r in rs]
    norm = [r / N for r in rs]

    return {
        "r_corr": pearson_corr(norm[:-1], norm[1:]),
        "low_byte_corr": pearson_corr(low[:-1], low[1:]),
        "high_byte_corr": pearson_corr(high[:-1], high[1:])
    }

def shuffle_runs_test(rs, bit=235, trials=1000):
    """
    Returns the empirical p-value for the observed runs statistic
    under random permutations of the signature order.
    """

    original_bits = [(r >> bit) & 1 for r in rs]

    observed_test = runs_test_bit_sequence(original_bits)

    if "runs" not in observed_test:
        return {
            "bit": bit,
            "error": observed_test.get("reason", "runs test failed"),
            "shuffle_p": None
        }

    observed_z = abs(observed_test["z_score"])

    count = 0

    for _ in range(trials):
        shuffled = original_bits[:]
        random.shuffle(shuffled)

        sim_test = runs_test_bit_sequence(shuffled)

        if "z_score" not in sim_test:
            continue

        if abs(sim_test["z_score"]) >= observed_z:
            count += 1

    return {
        "bit": bit,
        "observed_runs": observed_test["runs"],
        "observed_z": observed_test["z_score"],
        "shuffle_p": count / trials
    }

def bit_balance(rs, bit):

    ones = sum((r >> bit) & 1 for r in rs)

    return {
        "bit": bit,
        "ones": ones,
        "zeros": len(rs)-ones,
        "ratio": ones/len(rs)
    }

def window_runs(rs, bit=235, window=100):

    out=[]

    for i in range(0,len(rs),window):

        block=rs[i:i+window]

        if len(block)<40:
            continue

        bits=[(r>>bit)&1 for r in block]

        t=runs_test_bit_sequence(bits)

        if "runs" not in t:
            continue

        out.append({
            "start":i,
            "end":i+len(block),
            "runs":t["runs"],
            "p":t["p_value"]
        })

    return out

def visualize_bit(rs, bit):

    bits=[str((r>>bit)&1) for r in rs]

    return "".join(bits)

def overlapping_windows(rs, window=100, step=25):
    for start in range(0, len(rs) - window + 1, step):
        yield start, rs[start:start + window]


def bit_window_runs_heatmap(rs, window=100, step=25):
    heatmap = {}

    for bit in range(256):
        heatmap[bit] = []

        for start, block in overlapping_windows(rs, window, step):
            bits = [(r >> bit) & 1 for r in block]
            test = runs_test_bit_sequence(bits)

            if "z_score" not in test:
                continue

            heatmap[bit].append({
                "start": start,
                "end": start + len(block),
                "z": test["z_score"],
                "p": test["p_value"],
                "runs": test["runs"],
                "expected": test["expected"],
            })

    return heatmap


def summarize_heatmap(heatmap):
    summary = []

    for bit, values in heatmap.items():
        zs = [abs(v["z"]) for v in values]

        summary.append({
            "bit": bit,
            "max_abs_z": max(zs),
            "mean_abs_z": sum(zs) / len(zs),
            "windows_over_2": sum(z > 2 for z in zs),
            "windows_over_3": sum(z > 3 for z in zs),
        })

    return sorted(summary, key=lambda x: x["max_abs_z"], reverse=True)


def ascii_heatmap(bit_windows):
    chars = " .:-=+*#%@"
    out = []

    for v in bit_windows:
        z = abs(v["z"])
        idx = min(int(z), len(chars) - 1)
        out.append(chars[idx])

    return "".join(out)


def neighbor_heatmap_report(heatmap, target_bit=235, radius=3):
    report = []

    for bit in range(target_bit - radius, target_bit + radius + 1):
        if bit < 0 or bit > 255:
            continue

        values = heatmap[bit]
        zs = [abs(v["z"]) for v in values]

        report.append({
            "bit": bit,
            "max_abs_z": max(zs),
            "mean_abs_z": sum(zs) / len(zs),
            "windows_over_2": sum(z > 2 for z in zs),
            "windows_over_3": sum(z > 3 for z in zs),
            "ascii": ascii_heatmap(values),
        })

    return report


def classify_bit_heatmap(row):
    if row["windows_over_3"] >= 3:
        return "Persistent"
    if row["windows_over_2"] >= 3:
        return "Moderate"
    if row["max_abs_z"] > 3:
        return "Transient"
    return "Normal"

def population_bit_runs_report(results, target_bit=235):
    rows = []

    for r in results:
        signer = r["signer"]

        bit_row = None
        for item in r.get("runs_tests_lowest_p", []):
            if item["bit"] == target_bit:
                bit_row = item
                break

        heat = r.get("heatmap_report")
        heat_row = None
        if heat:
            for n in heat.get("neighbors", []):
                if n["bit"] == target_bit:
                    heat_row = n
                    break

        rows.append({
            "signer": signer,
            "signature_count": r["signature_count"],
            "target_bit": target_bit,
            "bit_raw_p": bit_row["p_value"] if bit_row else None,
            "bit_adjusted_p": bit_row["adjusted_p"] if bit_row else None,
            "bit_z": bit_row["z_score"] if bit_row else None,
            "heat_max_abs_z": heat_row["max_abs_z"] if heat_row else None,
            "heat_mean_abs_z": heat_row["mean_abs_z"] if heat_row else None,
            "heat_windows_over_2": heat_row["windows_over_2"] if heat_row else None,
            "heat_windows_over_3": heat_row["windows_over_3"] if heat_row else None,
            "heat_class": heat_row["class"] if heat_row else None,
        })

    return pd.DataFrame(rows)

def analyze_signer(signer, group, monte_carlo=False):
    rs = [to_int(x) for x in group["r"]]
    total = len(rs)

    repeated = {hex(r): c for r, c in Counter(rs).items() if c > 1}

    chi, buckets = chi_square_buckets(rs)
    bits = bit_frequency(rs)

    runs = runs_tests_for_r_bits(rs)

    shuffle_result = None

    
        
    raw = [(x["bit"], x["p_value"]) for x in runs]

    adjusted = benjamini_hochberg(raw)
    adj_map = {
        bit: q
        for bit, p, q in adjusted
    }

    for r in runs:
        r["adjusted_p"] = adj_map[r["bit"]]
    significant_runs = [
        r
        for r in runs
        if r["adjusted_p"] < 0.05
    ]
    # if significant_runs:
    #     bit = significant_runs[0]["bit"]
    #     shuffle_result = shuffle_runs_test(rs, bit)

    for run in significant_runs:
        bit = run["bit"]

        heatmap = bit_window_runs_heatmap(
            rs,
            window=100,
            step=25
        )

        summary = summarize_heatmap(heatmap)

        neighbor_report = neighbor_heatmap_report(
            heatmap,
            target_bit=bit,
            radius=3
        )

        for row in neighbor_report:
            row["class"] = classify_bit_heatmap(row)

        heatmap_report = {
            "target_bit": bit,
            "top_bits": summary[:10],
            "neighbors": neighbor_report,
        }

        run["balance"] = bit_balance(rs, bit)
        run["shuffle"] = shuffle_runs_test(rs, bit)
        run["windows"] = window_runs(rs, bit)
        run["heatmap_report"] = heatmap_report
        

    serial = serial_correlation_tests(rs)

    low_bytes = [r & 0xff for r in rs]
    high_bytes = [(r >> 248) & 0xff for r in rs]

    top_biased_bits = sorted(bits, key=lambda x: x["deviation"], reverse=True)[:10]

    suspicious_buckets = []
    expected = total / 256

    for i, obs in enumerate(buckets):
        z = (obs - expected) / math.sqrt(expected)
        if abs(z) >= 2.5:
            suspicious_buckets.append({
                "bucket": i,
                "observed": obs,
                "expected": expected,
                "z_score": z
            })

    mc_p = None
    if monte_carlo:
        mc_p = monte_carlo_chi_pvalue(chi, total, rounds=5000)

    score = 0
    score += len(repeated) * 100
    score += max(b["deviation"] for b in bits) * 100
    score += max(0, (chi - 255) / 20)

    return {
        "signer": signer,
        "signature_count": total,
        "repeated_r_count": len(repeated),
        "repeated_r_values": repeated,

        "r_lt_n_2_pct": sum(r < N // 2 for r in rs) / total * 100,
        "r_lt_n_4_pct": sum(r < N // 4 for r in rs) / total * 100,
        "r_lt_n_8_pct": sum(r < N // 8 for r in rs) / total * 100,
        "r_lt_n_16_pct": sum(r < N // 16 for r in rs) / total * 100,

        "avg_leading_zero_bits": sum(leading_zero_bits(r) for r in rs) / total,
        "max_leading_zero_bits": max(leading_zero_bits(r) for r in rs),
        "leading_zero_histogram": leading_zero_histogram(rs),

        "low_byte_entropy": shannon_entropy(low_bytes),
        "high_byte_entropy": shannon_entropy(high_bytes),

        "chi_square_256": chi,
        "monte_carlo_chi_pvalue": mc_p,
        "max_bit_deviation": max(b["deviation"] for b in bits),
        "top_biased_bits": top_biased_bits,
        "suspicious_buckets": suspicious_buckets,

        "chronological_windows": chronological_windows(group),
        "suspicion_score": score,
        "runs_tests_lowest_p": runs[:10],
        "serial_correlation": serial,

        "significant_runs": significant_runs,

        # "shuffle_test": shuffle_result,
        # "bit_balance": bit_balance(rs, bit),
        # "window_runs": window_runs(rs, bit)
    }




def analyze_all(csv_file):
    """
    CSV must contain at least:
    signer,r

    Optional:
    s,z,txid,time
    """

    # df = pd.read_csv(csv_file)

    # grouped = defaultdict(list)
    monte_carlo = True
    src = []
    rows = []
    words = get_words()
    for word in words:
        if len(word) > 0:
            obj = json.loads(word)
            obj['signer'] = obj['pubkey']
            obj['time'] = obj['blocktime']
            rows.append(obj)
            # rows.append({
            #     "signer": obj["pubkey"],
            #     "r": obj["r"],
            #     "s": obj.get("s"),
            #     "z": obj.get("z"),
            #     "txid": obj.get("txid"),
            #     "time": obj.get("blocktime"),
            #     "prefix": obj.get("prefix"),
            # })
            # src.append(json.loads(word))
   

    # for _, row in df.iterrows():
    #     grouped[row["pubkey"]].append(row.to_dict())

    rows.sort(
        key=lambda x: (
            x["block_height"],
            x["tx_index"],
            x.get("vid", 0)
        )
    )

    df = pd.DataFrame(rows)

    results = []

    for signer, group in df.groupby("signer"):
        if len(group) < 100:
            continue

        results.append(
            analyze_signer(
                signer,
                group,
                monte_carlo=monte_carlo
            )
        )

    return sorted(
        results,
        key=lambda x: x["suspicion_score"],
        reverse=True
    )

def get_words():
    wordsList = []
    if wordsList == []:
        content_string = ""
        # with open("test.txt", "r") as f:
        # with open("keq-total-1.txt", "r") as f:
        with open("keq-total-1.txt", "r") as f:
            content_string = f.read()
        # print(content_string)
        wordsList = content_string.split("\n")
        
    return wordsList


if __name__ == "__main__":
    ranked = analyze_all("signatures.csv")
    

    summary = []

    for r in ranked:
        summary.append({
            "signer": r["signer"],
            "signature_count": r["signature_count"],
            "repeated_r_count": r["repeated_r_count"],
            "r_lt_n_2_pct": r["r_lt_n_2_pct"],
            "r_lt_n_4_pct": r["r_lt_n_4_pct"],
            "r_lt_n_8_pct": r["r_lt_n_8_pct"],
            "r_lt_n_16_pct": r["r_lt_n_16_pct"],
            "avg_leading_zero_bits": r["avg_leading_zero_bits"],
            "low_byte_entropy": r["low_byte_entropy"],
            "high_byte_entropy": r["high_byte_entropy"],
            "chi_square_256": r["chi_square_256"],
            "monte_carlo_chi_pvalue": r["monte_carlo_chi_pvalue"],
            "max_bit_deviation": r["max_bit_deviation"],
            "suspicion_score": r["suspicion_score"],
            "runs_tests_lowest_p": r["runs_tests_lowest_p"],
            "significant_runs": r["significant_runs"],
            "serial_correlation": r["serial_correlation"]
        })
        # print(r)
    print(summary)

    # out = pd.DataFrame(summary)
    # out.to_csv("ranked_signers.csv", index=False)

    # print(out.head(20))