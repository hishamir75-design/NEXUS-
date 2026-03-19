import 'dart:convert';
import 'dart:math';
import 'package:hive/hive.dart';
import 'security_utils.dart';

class OfflineQueue {
  static const _boxName = 'offline_queue';
  static Box<Map>? _box;

  // ================= INIT =================
  static Future<void> init() async {
    try {
      if (_box == null || !_box!.isOpen) {
        _box = await Hive.openBox<Map>(_boxName);
      }
    } catch (e) {
      print("⚠️ Hive init failed, محاولة إصلاح...");

      try {
        await Hive.deleteBoxFromDisk(_boxName);
        _box = await Hive.openBox<Map>(_boxName);
      } catch (e) {
        print("❌ فشل إعادة إنشاء قاعدة البيانات: $e");
      }
    }
  }

  // ================= ADD =================
  static Future<void> add(Map<String, dynamic> message) async {
    try {
      await init();

      final key = DateTime.now().microsecondsSinceEpoch.toString() +
          Random.secure().nextInt(9999).toString();

      final encrypted =
          await SecurityUtils.encryptData(jsonEncode(message));

      await _box!.put(key, {"payload": encrypted});

      // 🔥 ضمان الكتابة على القرص فوراً (حماية من الكراش/فصل الكهرباء)
      await _box!.flush();

      print("🗂 Stored in persistent queue (secure + flushed)");
    } catch (e) {
      print("❌ Failed to add message: $e");
    }
  }

  // ================= GET ALL =================
  static Future<Map<String, Map<String, dynamic>>> getAll() async {
    try {
      await init();
      return _box!.toMap().cast<String, Map<String, dynamic>>();
    } catch (e) {
      print("❌ Failed to read queue: $e");
      return {}; // fallback آمن
    }
  }

  // ================= DELETE =================
  static Future<void> remove(String key) async {
    try {
      await init();
      await _box!.delete(key);

      // 🔥 تأكيد الحذف فعلياً من القرص
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

      // 🔥 تأكيد المسح النهائي
      await _box!.flush();
    } catch (e) {
      print("❌ Failed to clear queue: $e");
    }
  }
}
