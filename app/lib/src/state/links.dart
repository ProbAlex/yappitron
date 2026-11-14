// Finding links in message text. Only http(s) links are ever made tappable.

class TextPart {
  const TextPart(this.text, [this.url]);

  /// What is shown.
  final String text;

  /// Set when this part is a link.
  final Uri? url;

  bool get isLink => url != null;

  @override
  bool operator ==(Object other) => other is TextPart && other.text == text && other.url == url;

  @override
  int get hashCode => Object.hash(text, url);

  @override
  String toString() => isLink ? 'Link($text)' : 'Text($text)';
}

final _candidate = RegExp(r'https?://[^\s<>"]+', caseSensitive: false);
const _maxUrlLength = 2048;

/// Cut punctuation that belongs to the sentence, not the link: `see https://a.com/x.` and
/// `(https://a.com)` but keep the parenthesis in `https://en.wikipedia.org/wiki/Dart_(language)`.
String _trimTrailing(String s) {
  var end = s.length;
  while (end > 0) {
    final c = s[end - 1];
    if ('.,;:!?\'"*_~'.contains(c)) {
      end--;
    } else if (c == ')' || c == ']' || c == '}') {
      final open = c == ')' ? '(' : c == ']' ? '[' : '{';
      final body = s.substring(0, end);
      if (open.allMatches(body).length < c.allMatches(body).length) {
        end--;
      } else {
        break;
      }
    } else {
      break;
    }
  }
  return s.substring(0, end);
}

Uri? _validUrl(String s) {
  if (s.length > _maxUrlLength) return null;
  final u = Uri.tryParse(s);
  if (u == null || !u.hasAuthority || u.host.isEmpty) return null;
  if (u.scheme != 'http' && u.scheme != 'https') return null;
  // Credentials in a link (https://bank.com@evil.com) are a classic disguise.
  if (u.userInfo.isNotEmpty) return null;
  return u;
}

/// Split [text] into plain and link parts, in order. Joining the parts gives back [text].
List<TextPart> splitLinks(String text) {
  final parts = <TextPart>[];
  var last = 0;
  for (final m in _candidate.allMatches(text)) {
    final raw = _trimTrailing(m.group(0)!);
    final url = _validUrl(raw);
    if (url == null) continue;
    if (m.start > last) parts.add(TextPart(text.substring(last, m.start)));
    parts.add(TextPart(raw, url));
    last = m.start + raw.length;
  }
  if (last < text.length) parts.add(TextPart(text.substring(last)));
  return parts;
}

/// The distinct links in [text], in order of first appearance.
List<Uri> extractUrls(String text) {
  final seen = <String>{};
  return [
    for (final p in splitLinks(text))
      if (p.url != null && seen.add(p.url.toString())) p.url!,
  ];
}
