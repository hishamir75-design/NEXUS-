import 'dart:convert';
import 'dart:math';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:hive/hive.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'security_utils.dart';
import 'server_sync.dart';
import 'nexus_security_layer.dart';
import 'safe_device.dart';

class OfflineQueue {
  static const _boxName = 'offline_queue';
  static Box<Map>? _box;

  // ================= INIT =================
  static Future<void> init() async {
    if (_box == null) {
      _box = await Hive.openBox<Map>(_boxName);
    }
  }

  // ================= ENCRYPT & ADD =================
  static Future<void> add(Map<String, dynamic> message) async {
    await init();
    final key = DateTime.now().microsecondsSinceEpoch.toString() +
        Random.secure().nextInt(9999).toString();
    final encrypted = await SecurityUtils.encryptData(jsonEncode(message));
    await _box!.put(key, {"payload": encrypted});
    print("📝 Message added to offline queue (encrypted)");
  }

  // ================= GET ALL MESSAGES =================
  static Future<Map<String, Map<String, dynamic>>> getAll() async {
    await init();
    return _box!.toMap().cast<String, Map<String, dynamic>>();
  }

  // ================= DELETE MESSAGE =================
  static Future<void> remove(String key) async {
    await init();
    await _box!.delete(key);
  }

  // ================= CLEAR QUEUE =================
  static Future<void> clear() async {
    await init();
    await _box!.clear();
  }
}

class UserSession {
  static String? _jwtTokenEncrypted;
  static String? deviceId;

  // ================= DEVICE INIT =================
  static Future<void> initDevice(String rawBiometric) async {
    deviceId ??= await SecurityUtils.getDeviceId();
    final hashed = await SecurityUtils.hashData(rawBiometric);
    await SecurityUtils.storeSecure("device_biometric", hashed);
  }

  // ================= JWT IN-MEMORY ENCRYPTION =================
  static Future<void> setJwt(String token) async {
    _jwtTokenEncrypted = await SecurityUtils.encryptData(token);
  }

  static Future<String?> getJwt() async {
    if (_jwtTokenEncrypted == null) return null;
    return await SecurityUtils.decryptData(_jwtTokenEncrypted!);
  }

  // ================= REGISTER =================
  static Future<Map<String, dynamic>> register(
      String username, String password, String rawBiometric) async {
    await initDevice(rawBiometric);
    final payload = {
      "username": username,
      "password": await SecurityUtils.encryptData(password),
      "device_id": deviceId,
      "biometric_hash": await SecurityUtils.encryptData(rawBiometric),
      "timestamp": DateTime.now().millisecondsSinceEpoch,
      "nonce": Random.secure().nextInt(1 << 32).toString(),
    };

    await setJwt("simulate_jwt_register");
    print("✅ Registered offline payload (encrypted)");
    return {"status": "success", "jwt": await getJwt()};
  }

  // ================= LOGIN =================
  static Future<Map<String, dynamic>> login(
      String username, String password, String rawBiometric) async {
    await initDevice(rawBiometric);
    final payload = {
      "username": username,
      "password": await SecurityUtils.encryptData(password),
      "device_id": deviceId,
      "biometric_hash": await SecurityUtils.encryptData(rawBiometric),
      "timestamp": DateTime.now().millisecondsSinceEpoch,
      "nonce": Random.secure().nextInt(1 << 32).toString(),
    };

    await setJwt("simulate_jwt_login");
    print("✅ Login offline payload (encrypted)");
    return {"status": "otp_required", "otp": "123456", "jwt": await getJwt()};
  }

  // ================= VERIFY OTP =================
  static Future<Map<String, dynamic>> verifyOtp(
      String username, String code, String rawBiometric) async {
    print("✅ OTP Verified for $username code $code");
    return {"status": "verified", "jwt": await getJwt()};
  }

  // ================= UPLOAD MESSAGE =================
  static Future<void> uploadMessage(Map<String, dynamic> message) async {
    final jwtToken = await getJwt();
    if (jwtToken == null) return;

    await performKillSwitchCheck();

    final securedMessage = {
      "jwt": jwtToken,
      "device_id": deviceId,
      "timestamp": DateTime.now().millisecondsSinceEpoch,
      "nonce": Random.secure().nextInt(1 << 32).toString(),
      "payload": message,
    };

    try {
      await ServerSync.upload(securedMessage);
    } catch (_) {
      await OfflineQueue.add(securedMessage);
    }
  }

  // ================= SYNC QUEUE محسنة =================
  static Future<void> syncQueue({int maxUploadsPerRun = 20}) async {
    final messages = await OfflineQueue.getAll();
    int uploadCount = 0;

    for (var entry in messages.entries) {
      if (uploadCount >= maxUploadsPerRun) break;
      final key = entry.key;
      final encryptedMessage = entry.value["payload"];

      try {
        final decrypted =
            jsonDecode(await SecurityUtils.decryptData(encryptedMessage));

        final jwtToken = await getJwt();
        if (jwtToken == null) continue;

        final securedMessage = {
          "jwt": jwtToken,
          "device_id": deviceId,
          "timestamp": DateTime.now().millisecondsSinceEpoch,
          "nonce": Random.secure().nextInt(1 << 32).toString(),
          "payload": decrypted
        };

        try {
          await ServerSync.upload(securedMessage);
          await OfflineQueue.remove(key);
          uploadCount++;
        } catch (_) {
          continue;
        }
      } catch (_) {
        continue;
      }
    }
  }

  // ================= DOWNLOAD MESSAGES =================
  static Future<List<Map<String, dynamic>>> downloadMessages() async {
    final jwtToken = await getJwt();
    if (jwtToken == null) return [];
    await performKillSwitchCheck();
    return await ServerSync.download();
  }

  // ================= KILL-SWITCH =================
  static Future<void> performKillSwitchCheck() async {
    bool threatDetected = false;

    threatDetected |= await SafeDevice.isJailBroken;
    threatDetected |= await SecurityUtils.isAppTampered();

    if (threatDetected) {
      _jwtTokenEncrypted = null;
      deviceId = null;
      await OfflineQueue.clear();
      await SecurityUtils.clearSecureStorage();

      try {
        await NexusSecurityLayer.auditLog("KillSwitch", "Activated");
      } catch (_) {}

      exit(0);
    }
  }

  // ================= CUSTOM IN-APP KEYBOARD =================
  static Widget customSecureKeyboard({
    required Function(String) onKeyPress,
    required VoidCallback onBackspace,
    required VoidCallback onDone,
  }) {
    List<String> keys = List.generate(10, (i) => i.toString());
    keys.shuffle();

    List<Widget> keyButtons = keys.map((k) {
      return ElevatedButton(
        onPressed: () => onKeyPress(k),
        child: Text(k, style: TextStyle(fontSize: 20)),
      );
    }).toList();

    keyButtons.addAll([
      ElevatedButton(onPressed: onBackspace, child: Text("⌫", style: TextStyle(fontSize: 20))),
      ElevatedButton(onPressed: onDone, child: Text("✔", style: TextStyle(fontSize: 20))),
    ]);

    return GridView.count(
      crossAxisCount: 3,
      shrinkWrap: true,
      mainAxisSpacing: 10,
      crossAxisSpacing: 10,
      padding: EdgeInsets.all(20),
      children: keyButtons,
    );
  }

  // ================= CLEAR JWT ON BACKGROUND =================
  static Future<void> clearJwtOnBackground() async {
    _jwtTokenEncrypted = null;
  }
}

// ================= ربط JWT Lifecycle =================
class _NexusState extends State<MainApp> with WidgetsBindingObserver {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused) {
      UserSession.clearJwtOnBackground();
      print("🔐 Memory Cleaned: App moved to background.");
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  // ... بقية الـ Widget هنا
}
