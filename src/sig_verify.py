import ecdsa

digest_hex = "0200000001223ebf37da5987ed45ec2bdee33697e6fdd752823b645d545cac8994ff158c88110000001976a914d96ad3c56a2d03446c0192712119b6741d3d9ee788acffffffff0260ea0000000000001976a914ed614881f32c024a80d1b6b58dfed8f493f41c7288ac95a14200000000001976a91499ccf9022fe5173d2194659687382f235169bc5788ac00000000"
public_key_hex = '02b97a7f40dfd0a9989143797ded1ba7abc9105f5fc8b87ac2fce695de29684902'
signature_hex = '61386fe18b1c5f253b294d16d70d428ebaa357038765d99be99c659e57c58739139af2dd45b144c912542cc5549da70a952ccadc10056a826c5acb449a816c83'

def verify_signature(public_key_hex, signature_hex, digest_hex):
    # Convert hex strings to bytes
    public_key_bytes = bytes.fromhex(public_key_hex)
    signature_bytes = bytes.fromhex(signature_hex)
    digest_bytes = bytes.fromhex(digest_hex)

    # Create a verifying key from the public key
    verifying_key = ecdsa.VerifyingKey.from_string(public_key_bytes, curve=ecdsa.SECP256k1)

    # Verify the signature
    try:
        result = verifying_key.verify(signature_bytes, digest_bytes)
        return result
    except ecdsa.BadSignatureError:
        return False


verification_result = verify_signature(public_key_hex, signature_hex, digest_hex)

if verification_result:
    print("Signature is valid.")
else:
    print("Signature is invalid.")
