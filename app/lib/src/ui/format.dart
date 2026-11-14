String two(int n) => n.toString().padLeft(2, '0');

/// `14:05` today, `Nov 13` otherwise.
String shortTime(DateTime t) {
  final now = DateTime.now();
  if (t.year == now.year && t.month == now.month && t.day == now.day) {
    return '${two(t.hour)}:${two(t.minute)}';
  }
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  return '${months[t.month - 1]} ${t.day}';
}
