import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:yappitron/src/state/links.dart';
import 'package:yappitron/src/state/mime.dart';
import 'package:yappitron/src/state/models.dart';

List<String> links(String s) => [for (final p in splitLinks(s)) if (p.isLink) p.text];

void main() {
  group('splitLinks', () {
    test('finds links and keeps the text around them', () {
      final parts = splitLinks('look at https://example.com/a?b=1 now');
      expect(parts.map((p) => p.text).join(), 'look at https://example.com/a?b=1 now');
      expect(links('look at https://example.com/a?b=1 now'), ['https://example.com/a?b=1']);
    });

    test('drops punctuation that ends the sentence', () {
      expect(links('see https://example.com.'), ['https://example.com']);
      expect(links('really? https://example.com/x!'), ['https://example.com/x']);
      expect(links('(https://example.com)'), ['https://example.com']);
      expect(links('"https://example.com/q",'), ['https://example.com/q']);
    });

    test('keeps balanced parentheses that are part of the address', () {
      expect(links('https://en.wikipedia.org/wiki/Dart_(language)'), ['https://en.wikipedia.org/wiki/Dart_(language)']);
      expect(links('(see https://en.wikipedia.org/wiki/Dart_(language))'), ['https://en.wikipedia.org/wiki/Dart_(language)']);
    });

    test('only http and https, and never with credentials', () {
      expect(links('javascript:alert(1) file:///etc/passwd ftp://x.com data:text/html,hi'), isEmpty);
      expect(links('https://bank.com@evil.example/login'), isEmpty);
      expect(links('https:// nothing'), isEmpty);
    });

    test('several links, case-insensitive scheme, unicode text', () {
      expect(links('HTTPS://A.com и http://b.org/ü'), ['HTTPS://A.com', 'http://b.org/ü']);
    });

    test('plain text has no links and a huge address is ignored', () {
      expect(links('no links here, just words.com'), isEmpty);
      expect(links('https://example.com/${'a' * 3000}'), isEmpty);
    });

    test('extractUrls de-duplicates in order', () {
      expect(extractUrls('https://a.com https://b.com https://a.com').map((u) => u.host), ['a.com', 'b.com']);
    });
  });

  group('mime and sizes', () {
    test('mimeForName', () {
      expect(mimeForName('Cat.PNG'), 'image/png');
      expect(mimeForName('clip.mov'), 'video/quicktime');
      expect(mimeForName('noext'), 'application/octet-stream');
      expect(mimeForName('trailingdot.'), 'application/octet-stream');
      expect(mimeForName('archive.tar.gz'), 'application/octet-stream');
    });

    test('formatBytes', () {
      expect(formatBytes(12), '12 B');
      expect(formatBytes(2048), '2 KB');
      expect(formatBytes(1536 * 1024), '1.5 MB');
    });
  });

  group('message content in storage', () {
    final att = Attachment(id: 'b1', key: Uint8List.fromList(List<int>.filled(32, 7)), name: 'cat.png', mime: 'image/png', size: 123, width: 4, height: 3);

    test('attachments and previews survive a save and load', () {
      final m = ChatMessage(
        seq: 3,
        mine: true,
        time: DateTime.fromMillisecondsSinceEpoch(1000),
        text: 'hi',
        attachments: [att],
        previews: [LinkPreview(url: 'https://a.com', title: 'A', image: att)],
      );
      final back = ChatMessage.fromJson(m.toJson());
      expect(back.attachments.single.name, 'cat.png');
      expect(back.attachments.single.key, att.key);
      expect(back.attachments.single.kind, AttachmentKind.image);
      expect(back.previews.single.title, 'A');
      expect(back.previews.single.image!.id, 'b1');
    });

    test('old text-only messages still load', () {
      final m = ChatMessage.fromJson({'s': 1, 'm': false, 't': 5, 'x': 'old'});
      expect(m.text, 'old');
      expect(m.attachments, isEmpty);
    });

    test('malformed attachments from a peer are dropped, not crashed on', () {
      expect(Attachment.listFromJson('nope'), isEmpty);
      expect(Attachment.listFromJson([
        {'id': 1},
        {'id': 'x', 'k': 'AAAA', 'n': 'n', 'm': 'm', 's': 1}, // key too short
        {'id': 'x', 'k': '!!!', 'n': 'n', 'm': 'm', 's': 1},
        null,
        att.toJson(),
      ]).map((a) => a.id), ['b1']);
    });

    test('summary describes attachment-only messages', () {
      ChatMessage m(List<Attachment> a, [String t = '']) =>
          ChatMessage(seq: 1, mine: true, time: DateTime.now(), text: t, attachments: a);
      expect(m([att]).summary, 'Photo');
      expect(m([att, att]).summary, 'Photo +1');
      expect(m([att], 'caption').summary, 'caption');
    });
  });
}
