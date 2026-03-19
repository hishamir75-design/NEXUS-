import 'dart:convert';
import 'dart:math';
import 'package:hive/hive.dart';
import 'security_utils.dart';

class OfflineQueue {
  static const String _boxName = 'offline_queue';
  static Box<Map>? _box;

  // ================= INIT (Self-Healing) =================
  static Future<void> init() async {
    try {
      if (_box == null || !_box!.isOpen) {
        _box = await Hive.openBox<Map>(_boxName);
      }
    } catch (e) {
      print("⚠️ Hive corrupted. Attempting recovery...");

      try {
        await Hive.deleteBoxFromDisk(_boxName);
        _box = await Hive.openBox<Map>(_boxName);
        print("✅ Hive recovered successfully");
      } catch (e) {
        print("❌ Critical: Hive recovery failed: $e");
      }
    }
  }

  // ================= ADD (Encrypted + Atomic Write) =================
  static Future<void> add(Map<String, dynamic> message) async {
    try {
      await init();

      final key = _generateSecureKey();

      final encrypted =
          await SecurityUtils.encryptData(jsonEncode(message));

      await _box!.put(key, {
        "payload": encrypted,
        "timestamp": DateTime.now().millisecondsSinceEpoch,
      });

      // 🔥 إجبار الكتابة على القرص فوراً
      await _box!.flush();

      print("🗂 Stored securely in persistent queue");
    } catch (e) {
      print("❌ Failed to store message: $e");
    }
  }

  // ================= GET ALL (Safe Read) =================
  static Future<Map<String, Map<String, dynamic>>> getAll() async {
    try {
      await init();

      final raw = _box!.toMap();

      // 🔥 تنظيف أي بيانات تالفة
      final cleaned = <String, Map<String, dynamic>>{};

      for (var entry in raw.entries) {
        try {
          if (entry.value is Map &&
              entry.value["payload"] != null) {
            cleaned[entry.key] =
                Map<String, dynamic>.from(entry.value);
          }
        } catch (_) {
          continue; // skip corrupted entry
        }
      }

      return cleaned;
    } catch (e) {
      print("❌ Failed to read queue: $e");
      return {};
    }
  }

  // ================= REMOVE =================
  static Future<void> remove(String key) async {
    try {
      await init();
      await _box!.delete(key);
      await _box!.flush();
    } catch (e) {
      print("❌ Failed to delete message: $e");
    }
  }

  // ================= CLEAR =================
  static Future<void> clear() async {
    try {
      await init();
      await _box!.clear();
      await _box!.flush();
    } catch (e) {
      print("❌ Failed to clear queue: $e");
    }
  }

  // ================= SIZE (Monitoring) =================
  static Future<int> size() async {
    try {
      await init();
      return _box!.length;
    } catch (_) {
      return 0;
    }
  }

  // ================= SECURE KEY GENERATOR =================
  static String _generateSecureKey() {
    final time = DateTime.now().microsecondsSinceEpoch;
    final rand = Random.secure().nextInt(1 << 32);
    return "$time-$rand";
  }
}
