class OfflineAI {
  static void processMessage(Map<String, dynamic> message) {
    String text = message["text"] ?? "";
    List<String> keywords = _extractKeywords(text);
    message["keywords"] = keywords;
    print("💡 Offline AI keywords: $keywords");
  }

  static List<String> _extractKeywords(String text) {
    final words = text.split(' ');
    final unique = words.toSet().toList();
    return unique.length > 5 ? unique.sublist(0, 5) : unique;
  }
}
