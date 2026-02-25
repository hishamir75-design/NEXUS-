import 'security_utils.dart';
import 'server_sync.dart';
import 'offline_queue.dart';

class UserSession {
  static String? jwtToken;

  static Future<Map<String, dynamic>> register(
      String username, String password, String rawBiometric) async {
    final payload = {
      "username": username,
      "password": password,
      "biometric_hash": await SecurityUtils.encryptData(rawBiometric),
    };
    jwtToken = "simulate_jwt_register";
    print("✅ Registered offline payload: $payload");
    return {"status": "success", "jwt": jwtToken};
  }

  static Future<Map<String, dynamic>> login(
      String username, String password, String rawBiometric) async {
    final payload = {
      "username": username,
      "password": password,
      "biometric_hash": await SecurityUtils.encryptData(rawBiometric),
    };
    jwtToken = "simulate_jwt_login";
    print("✅ Login offline payload: $payload");
    return {"status": "otp_required", "otp": "123456", "jwt": jwtToken};
  }

  static Future<Map<String, dynamic>> verifyOtp(
      String username, String code, String rawBiometric) async {
    print("✅ OTP Verified for $username code $code");
    return {"status": "verified", "jwt": jwtToken};
  }

  static Future<void> uploadMessage(Map<String, dynamic> message) async {
    if (jwtToken == null) return;
    try {
      await ServerSync.upload(message);
    } catch (_) {
      OfflineQueue.add(message); // لو فشل ضيفه للـ Queue
    }
  }

  static Future<List<Map<String, dynamic>>> downloadMessages() async {
    if (jwtToken == null) return [];
    return await ServerSync.download();
  }
}
