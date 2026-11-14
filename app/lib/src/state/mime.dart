// MIME types from file names. The picker does not report one, and a type is only used to choose
// how to display a file, never to decide whether it is safe.

const _types = {
  'png': 'image/png',
  'jpg': 'image/jpeg',
  'jpeg': 'image/jpeg',
  'jfif': 'image/jpeg',
  'gif': 'image/gif',
  'webp': 'image/webp',
  'bmp': 'image/bmp',
  'heic': 'image/heic',
  'avif': 'image/avif',
  'svg': 'image/svg+xml',
  'mp4': 'video/mp4',
  'm4v': 'video/mp4',
  'mov': 'video/quicktime',
  'webm': 'video/webm',
  'mkv': 'video/x-matroska',
  'avi': 'video/x-msvideo',
  'mp3': 'audio/mpeg',
  'm4a': 'audio/mp4',
  'aac': 'audio/aac',
  'ogg': 'audio/ogg',
  'opus': 'audio/ogg',
  'wav': 'audio/wav',
  'flac': 'audio/flac',
  'pdf': 'application/pdf',
  'zip': 'application/zip',
  'txt': 'text/plain',
  'md': 'text/markdown',
  'json': 'application/json',
  'csv': 'text/csv',
};

String mimeForName(String name) {
  final dot = name.lastIndexOf('.');
  if (dot < 0 || dot == name.length - 1) return 'application/octet-stream';
  return _types[name.substring(dot + 1).toLowerCase()] ?? 'application/octet-stream';
}

/// `1.4 MB`, `820 KB`, `12 B`.
String formatBytes(int n) {
  if (n < 1024) return '$n B';
  if (n < 1024 * 1024) return '${(n / 1024).round()} KB';
  if (n < 1024 * 1024 * 1024) return '${(n / (1024 * 1024)).toStringAsFixed(1)} MB';
  return '${(n / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
}
