import 'dart:typed_data';

import 'package:eth_sig_util/eth_sig_util.dart';

String signStringWithEIP712(
  String message,
  String privateKeyHex,
) {
  final List<int> codeUnits = message.codeUnits;
  final Uint8List messageInUint8 = Uint8List.fromList(codeUnits);

  return EthSigUtil.signMessage(
    privateKey: privateKeyHex,
    message: messageInUint8,
  );
}
