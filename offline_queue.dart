import 'dart:collection';
import 'server_sync.dart';
import 'user_session.dart';

class OfflineQueue {
  static final Queue<Map<String, dynamic>> _queue = Queue();

  static void add(Map<String, dynamic> message) {
    _queue.add(message);
    print("🗂 Added to Offline Queue: $message");
  }

  static Future<void> processQueue() async {
    while (_queue.isNotEmpty) {
      final msg = _queue.first;
      try {
        await UserSession.uploadMessage(msg);
        _queue.removeFirst();
        print("✅ Message uploaded successfully");
      } catch (e) {
        print("⚠️ Retry later: $e");
        break; // Stop processing to retry later
      }
    }
  }
}
