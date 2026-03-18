Import 'dart:convert';
import 'dart:io';
import 'package:crypto/crypto.dart';
import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:hive/hive.dart';
import 'security_utils.dart';

class NexusSecurityLayer {
  static final Dio dio = Dio();

  // ================= CERTIFICATE PINNING =================
  static void initSecurity() {
    dio.httpClientAdapter = IOHttpClientAdapter()
      ..createHttpClient = () {
        final client = HttpClient();
        client.badCertificateCallback =
            (X509Certificate cert, String host, int port) {
          // ⚠️ لازم تجيب fingerprint الحقيقي من السيرفر
          const allowedFingerprint = "YOUR_REAL_CERT_HASH";
          final certBytes = cert.der;
          final digest = sha256.convert(certBytes).toString();
          return digest == allowedFingerprint;
        };
        return client;
      };
  }

  // ================= REQUEST SIGNING =================
  static Future<Map<String, String>> signRequest(String body) async {
    final timestamp = DateTime.now().millisecondsSinceEpoch.toString();
    final nonce = DateTime.now().microsecondsSinceEpoch.toString();
    final deviceId = await SecurityUtils.getDeviceId();
    final raw = "$body|$timestamp|$nonce|$deviceId";
    final signature = await SecurityUtils.hmacSha256(raw);

    return {
      "X-Signature": signature,
      "X-Timestamp": timestamp,
      "X-Nonce": nonce,
      "X-Device-Id": deviceId,
    };
  }

  // ================= RATE LIMIT =================
  static DateTime? _lastCall;

  static bool canCall() {
    final now = DateTime.now();
    if (_lastCall == null || now.difference(_lastCall!).inMilliseconds > 500) {
      _lastCall = now;
      return true;
    }
    return false;
  }

  // ================= AUDIT LOG =================
  static Future<void> auditLog(String action, String status) async {
    try {
      await dio.post(
        "/audit",
        data: {
          "action": action,
          "status": status,
          "time": DateTime.now().toIso8601String(),
        },
      );
    } catch (_) {
      // متوقع يفشل أحياناً، نتجاهل
    }
  }
}

// ================= SYNC QUEUE =================
Future<void> processSyncQueue() async {
  final box = await Hive.openBox('offline_queue');

  for (var key in box.keys) {
    final data = box.get(key);

    try {
      // محاولة الإرسال
      await NexusSecurityLayer.dio.post("/sync", data: data);
      await box.delete(key); // نجح؟ امسحه من الذاكرة

    } on DioException catch (e) {
      if (e.response?.statusCode == 401) {
        // 🚨 التوكن انتهى، وقف الـ Queue
        print("🚨 Unauthorized! Stopping Queue and forcing Login.");
        break;
      }

      if (e.type == DioExceptionType.connectionTimeout ||
          e.type == DioExceptionType.connectionError) {
        // 🌐 مشكلة نت بسيطة
        print("🌐 Connection lost. Keeping message in queue for later.");
        break; // وقف المحاولات مؤقتًا
      }

      // أي خطأ تاني (مثلاً 500 أو 400)
      print("⚠️ Server Error: ${e.message}");
    }
  }
}
