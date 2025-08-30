from coincurve import PrivateKey
from eth_utils import keccak, to_checksum_address


class Signer:
    def __init__(self, private_key: str, chain_id: int):
        assert private_key is not None and chain_id is not None

        self.private_key = private_key
        key_hex = private_key[2:] if private_key.startswith("0x") else private_key
        self._private_key = PrivateKey(bytes.fromhex(key_hex))
        self._address = to_checksum_address(
            keccak(self._private_key.public_key.format(compressed=False)[1:])[-20:]
        )
        self.chain_id = chain_id

    def address(self):
        return self._address

    def get_chain_id(self):
        return self.chain_id

    def sign(self, message_hash):
        """
        Signs a message hash
        """
        if isinstance(message_hash, str):
            msg_bytes = bytes.fromhex(
                message_hash[2:] if message_hash.startswith("0x") else message_hash
            )
        else:
            msg_bytes = message_hash

        signature = self._private_key.sign_recoverable(msg_bytes, hasher=None)
        r = signature[:32].hex()
        s = signature[32:64].hex()
        v = signature[64] + 27
        return f"0x{r}{s}{v:02x}"
