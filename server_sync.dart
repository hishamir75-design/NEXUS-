import 'dart:convert';
import 'package:dio/dio.dart';
import 'security_utils.dart';
import 'user_session.dart';

class ServerSync {
  static final Dio _dio = Dio(BaseOptions(
    baseUrl: "https://your-server.com/api",
    connectTimeout: 10000,
    receiveTimeout: 10000,
    headers: {"Content-Type": "application/json"},
  ));

  static Future<void> upload(Map<String, dynamic> message) async {
    try {
      if (UserSession.jwtToken == null) return;
      String encrypted = await SecurityUtils.encryptData(jsonEncode(message));
      await _dio.post(
        "/upload",
        data: {"payload": encrypted},
        options: Options(headers: {"Authorization": "Bearer ${UserSession.jwtToken}"}),
      );
    } catch (e) {
      print("⚠️ Upload failed, will retry: $e");
      // OfflineQueue هيتعامل مع Retry
    }
  }

  static Future<List<Map<String, dynamic>>> download() async {
    try {
      if (UserSession.jwtToken == null) return [];
      final resp = await _dio.post(
        "/download",
        data: {"device_id": "unique_device_id"},
        options: Options(headers: {"Authorization": "Bearer ${UserSession.jwtToken}"}),
      );
      List<Map<String, dynamic>> messages = [];
      for (var encMsg in resp.data['messages']) {
        String decrypted = await SecurityUtils.decryptData(encMsg);
        messages.add(jsonDecode(decrypted));
      }
      return messages;
    } catch (e) {
      print("⚠️ Download failed: $e");
      return [];
    }
  }
}
