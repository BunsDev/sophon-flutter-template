import 'dart:convert';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:pointycastle/export.dart';

Uint8List bigIntToBytes(BigInt value, int length) {
  Uint8List result = Uint8List(length);
  for (int i = 0; i < length; i++) {
    result[length - 1 - i] = (value >> (8 * i)).toUnsigned(8).toInt();
  }
  return result;
}

String signStringWithEIP191(String message, String privateKeyHex) {
  Uint8List messageBytes = Uint8List.fromList(utf8.encode(message));
  Uint8List privateKeyBytes = Uint8List.fromList(hex.decode(privateKeyHex));

  ECCurve_secp256k1 curve = ECCurve_secp256k1();
  ECPrivateKey privateKey =
      ECPrivateKey(BigInt.parse(hex.encode(privateKeyBytes), radix: 16), curve);

  ECDSASigner signer = ECDSASigner(HMac(SHA256Digest(), 64) as Digest?);
  signer.init(true, PrivateKeyParameter<PrivateKey>(privateKey));

  ECSignature signature = signer.generateSignature(messageBytes) as ECSignature;
  Uint8List rBytes = bigIntToBytes(signature.r, 32);
  Uint8List sBytes = bigIntToBytes(signature.s, 32);

  Uint8List signatureBytes = Uint8List(64);
  signatureBytes.setRange(0, 32, rBytes);
  signatureBytes.setRange(32, 64, sBytes);

  return hex.encode(signatureBytes);
}
