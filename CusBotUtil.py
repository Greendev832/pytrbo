from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes

def get_bot(mnemonic, idx):
    seed_bytes = ""
    pri = None
    pub = None
    try:
        seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
        wallet = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
        account = wallet.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(idx)
        pri = account.PrivateKey().Raw().ToHex()
        pub = account.PublicKey().ToAddress()
    except Exception as e:
        pass
    return (pri, pub)