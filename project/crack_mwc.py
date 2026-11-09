import random
from z3 import BitVec, BitVecVal, Solver, sat

# ----------------------------------------------------------------------
# 1. Implementation of V8's legacy MWC1616 generator
# ----------------------------------------------------------------------
class V8_MWC1616:
    def __init__(self, s1, s2):
        self.s1 = s1 & 0xFFFFFFFF
        self.s2 = s2 & 0xFFFFFFFF

    def next_int(self):
        # Update s1 and s2
        self.s1 = (18030 * (self.s1 & 0xFFFF) + (self.s1 >> 16)) & 0xFFFFFFFF
        self.s2 = (30903 * (self.s2 & 0xFFFF) + (self.s2 >> 16)) & 0xFFFFFFFF
        # Combine to 32-bit integer
        return ((self.s1 << 16) + (self.s2 & 0xFFFF)) & 0xFFFFFFFF

    def next_float(self):
        # Emulates Math.random() in legacy V8
        return self.next_int() / (2**32)


# ----------------------------------------------------------------------
# 2. Crack internal state using Z3 from observed values
# ----------------------------------------------------------------------
def crack_mwc1616(observed_floats):
    """
    Given at least 2 or 3 observed Math.random() floats,
    recovers the internal state (s1, s2) and returns a cloned generator.
    """
    # Convert floats back to 32-bit integers
    observed_ints = [int(round(f * (2**32))) & 0xFFFFFFFF for f in observed_floats]
    print(observed_ints)

    solver = Solver()

    # Symbolic variables for the initial s1 and s2
    s1 = BitVec('s1', 32)
    s2 = BitVec('s2', 32)

    cur_s1 = s1
    cur_s2 = s2

    # Add constraints for each observed number
    for val in observed_ints:
        # Step forward
        cur_s1 = (BitVecVal(18030, 32) * (cur_s1 & 0xFFFF) + (cur_s1 >> 16))
        cur_s2 = (BitVecVal(30903, 32) * (cur_s2 & 0xFFFF) + (cur_s2 >> 16))

        # Output equation: ((cur_s1 << 16) + (cur_s2 & 0xFFFF)) == val
        out = (cur_s1 << 16) + (cur_s2 & 0xFFFF)
        solver.add(out == BitVecVal(val, 32))

    if solver.check() == sat:
        model = solver.model()
        rec_s1 = model[s1].as_long()
        rec_s2 = model[s2].as_long()
        return rec_s1, rec_s2
    else:
        raise ValueError("Could not find a valid PRNG state.")


# ----------------------------------------------------------------------
# 3. Demonstration
# ----------------------------------------------------------------------
if __name__ == "__main__":
    # Secret seed inside the victim's browser
    secret_s1 = random.randint(1, 0xFFFFFFFF)
    secret_s2 = random.randint(1, 0xFFFFFFFF)
    victim_prng = V8_MWC1616(secret_s1, secret_s2)

    # Attacker captures 3 consecutive Math.random() calls
    observed = [victim_prng.next_float() for _ in range(3)]
    print(f"Observed outputs: {observed}")

    # Solve for internal state
    recovered_s1, recovered_s2 = crack_mwc1616(observed)
    print(f"\n[+] Recovered initial s1: 0x{recovered_s1:08x} (Actual: 0x{secret_s1:08x})")
    print(f"[+] Recovered initial s2: 0x{recovered_s2:08x} (Actual: 0x{secret_s2:08x})")

    # Clone the generator to predict future outputs
    attacker_prng = V8_MWC1616(recovered_s1, recovered_s2)
    
    # Fast-forward past the 3 observed values
    for _ in range(3):
        attacker_prng.next_float()

    # Predict next 5 numbers
    print("\nPredicting the next 5 calls:")
    for i in range(pow(2,3)):
        actual = victim_prng.next_float()
        predicted = attacker_prng.next_float()
        print(f"Call {i+1}: Predicted = {predicted:.12f} | Actual = {actual:.12f} | Match: {predicted == actual}")