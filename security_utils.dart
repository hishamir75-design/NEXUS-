import 'dart:convert';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SecurityUtils {
  static const _storage = FlutterSecureStorage();

  // توليد أو جلب مفتاح التشفير
  static Future<encrypt.Key> _getEncryptionKey() async {
    String? savedKey = await _storage.read(key: 'nexus_master_key');
    if (savedKey == null) {
      final newKey = encrypt.Key.fromSecureRandom(32); // 256-bit
      await _storage.write(key: 'nexus_master_key', value: newKey.base64);
      return newKey;
    }
    return encrypt.Key.fromBase64(savedKey);
  }

  // تشفير البيانات
  static Future<String> encryptData(String plainText) async {
    final key = await _getEncryptionKey();
    final iv = encrypt.IV.fromSecureRandom(12);
    final encrypter = encrypt.Encrypter(encrypt.AES(key, mode: encrypt.AESMode.gcm));
    final encrypted = encrypter.encrypt(plainText, iv: iv);
    return "${iv.base64}:${encrypted.base64}";
  }

  // فك التشفير
  static Future<String> decryptData(String encryptedWithIv) async {
    final parts = encryptedWithIv.split(':');
    final iv = encrypt.IV.fromBase64(parts[0]);
    final encryptedContent = parts[1];
    final key = await _getEncryptionKey();
    final encrypter = encrypt.Encrypter(encrypt.AES(key, mode: encrypt.AESMode.gcm));
    return encrypter.decrypt64(encryptedContent, iv: iv);
  }
}
