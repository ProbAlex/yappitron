import 'dart:convert';
import 'dart:typed_data';

/// What kind of thing an attachment is, from its MIME type (the sender's claim: never trusted
/// for anything but choosing how to display it).
enum AttachmentKind { image, video, audio, file }

/// A file sent in a message. The bytes live on the server, encrypted under [key]; this record
/// (with the key) only ever exists inside end-to-end encrypted messages and in local storage.
class Attachment {
  Attachment({
    required this.id,
    required this.key,
    required this.name,
    required this.mime,
    required this.size,
    this.width,
    this.height,
  });

  /// Server-side blob id.
  final String id;

  /// 32-byte file key.
  final Uint8List key;
  final String name;
  final String mime;

  /// Size of the original file in bytes.
  final int size;
  final int? width;
  final int? height;

  AttachmentKind get kind {
    final m = mime.toLowerCase();
    if (m.startsWith('image/') && m != 'image/svg+xml') return AttachmentKind.image;
    if (m.startsWith('video/')) return AttachmentKind.video;
    if (m.startsWith('audio/')) return AttachmentKind.audio;
    return AttachmentKind.file;
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'k': base64Url.encode(key).replaceAll('=', ''),
        'n': name,
        'm': mime,
        's': size,
        if (width != null) 'w': width,
        if (height != null) 'h': height,
      };

  /// Returns null for a malformed entry (a peer's message is untrusted input).
  static Attachment? tryFromJson(Object? j) {
    if (j is! Map) return null;
    final id = j['id'], k = j['k'], n = j['n'], m = j['m'], sz = j['s'];
    if (id is! String || k is! String || n is! String || m is! String || sz is! int) return null;
    try {
      final key = base64Url.decode(base64Url.normalize(k));
      if (key.length != 32 || sz < 0) return null;
      return Attachment(
        id: id,
        key: Uint8List.fromList(key),
        name: n,
        mime: m,
        size: sz,
        width: j['w'] is int ? j['w'] as int : null,
        height: j['h'] is int ? j['h'] as int : null,
      );
    } on FormatException {
      return null;
    }
  }

  static List<Attachment> listFromJson(Object? j) =>
      j is List ? [for (final a in j) ?tryFromJson(a)] : const [];
}

/// A link card shown under a message. The sender's app builds it; the recipient never contacts
/// the linked site (that would reveal their address to it).
class LinkPreview {
  LinkPreview({required this.url, this.title, this.description, this.site, this.image});
  final String url;
  final String? title;
  final String? description;
  final String? site;

  /// Preview picture, stored as an encrypted attachment like any other file.
  final Attachment? image;

  Map<String, dynamic> toJson() => {
        'u': url,
        if (title != null) 't': title,
        if (description != null) 'd': description,
        if (site != null) 's': site,
        if (image != null) 'i': image!.toJson(),
      };

  static LinkPreview? tryFromJson(Object? j) {
    if (j is! Map || j['u'] is! String) return null;
    return LinkPreview(
      url: j['u'] as String,
      title: j['t'] is String ? j['t'] as String : null,
      description: j['d'] is String ? j['d'] as String : null,
      site: j['s'] is String ? j['s'] as String : null,
      image: Attachment.tryFromJson(j['i']),
    );
  }

  static List<LinkPreview> listFromJson(Object? j) =>
      j is List ? [for (final p in j) ?tryFromJson(p)] : const [];
}

class ChatMessage {
  ChatMessage({
    required this.seq,
    required this.mine,
    required this.time,
    required this.text,
    this.attachments = const [],
    this.previews = const [],
  });

  /// Server sequence number (the order of the conversation's log).
  final int seq;

  /// Written by this account (on this device or another of its devices).
  final bool mine;
  final DateTime time;
  final String text;
  final List<Attachment> attachments;
  final List<LinkPreview> previews;

  /// Short description for the chat list and notifications.
  String get summary {
    if (text.isNotEmpty) return text;
    if (attachments.isEmpty) return '';
    final a = attachments.first;
    final what = switch (a.kind) {
      AttachmentKind.image => 'Photo',
      AttachmentKind.video => 'Video',
      AttachmentKind.audio => 'Audio',
      AttachmentKind.file => a.name,
    };
    return attachments.length > 1 ? '$what +${attachments.length - 1}' : what;
  }

  Map<String, dynamic> toJson() => {
        's': seq,
        'm': mine,
        't': time.millisecondsSinceEpoch,
        'x': text,
        if (attachments.isNotEmpty) 'a': [for (final a in attachments) a.toJson()],
        if (previews.isNotEmpty) 'p': [for (final p in previews) p.toJson()],
      };

  factory ChatMessage.fromJson(Map<String, dynamic> j) => ChatMessage(
        seq: j['s'] as int,
        mine: j['m'] as bool,
        time: DateTime.fromMillisecondsSinceEpoch(j['t'] as int),
        text: j['x'] as String,
        attachments: Attachment.listFromJson(j['a']),
        previews: LinkPreview.listFromJson(j['p']),
      );
}

/// `invited`: a request waiting for this account to accept. `declined`: the other person said no.
enum ConversationState { joined, invited, declined }

class Conversation {
  Conversation({
    required this.id,
    required this.peer,
    required this.state,
    this.lastSeq = 0,
    this.liveTyping = true,
    this.stale = false,
    this.archiveUntil = 0,
    this.archiveSeq = 0,
    Set<int>? sentSeqs,
    List<ChatMessage>? messages,
  })  : sentSeqs = sentSeqs ?? {},
        messages = [] {
    for (final m in messages ?? const <ChatMessage>[]) {
      addMessage(m);
    }
  }

  final String id;
  final String peer;
  ConversationState state;

  /// Highest log sequence number processed on this device.
  int lastSeq;

  /// Whether this device sends live-typing frames for this chat.
  bool liveTyping;

  /// This device is not (or no longer) a member of the conversation's encryption group, for
  /// example after the account's keys were reset with the recovery key. The history stays
  /// readable (from the archive) but nothing new can be sent or received here.
  bool stale;

  /// Messages up to this sequence number were written before this device joined; they come
  /// from the history archive instead of being decrypted.
  int archiveUntil;

  /// Highest archive entry already imported.
  int archiveSeq;

  /// Sequence numbers this device wrote itself and has not yet moved `lastSeq` past. The server
  /// replays them to us; MLS cannot decrypt them, so they are skipped.
  final Set<int> sentSeqs;

  final List<ChatMessage> messages;
  final Set<int> _seqs = {};

  /// What the other person is typing right now (live, never stored).
  String? liveDraft;
  DateTime? liveDraftAt;
  int unread = 0;

  /// Highest typing-frame sequence seen (frames can arrive out of order).
  int typingSeqIn = -1;

  ChatMessage? get last => messages.isEmpty ? null : messages.last;

  bool hasSeq(int seq) => _seqs.contains(seq);

  /// Insert in sequence order; ignores a message whose sequence number is already present
  /// (the same message can arrive both through the archive and through the log).
  void addMessage(ChatMessage m) {
    if (!_seqs.add(m.seq)) return;
    if (messages.isEmpty || m.seq > messages.last.seq) {
      messages.add(m);
      return;
    }
    final at = messages.indexWhere((x) => x.seq > m.seq);
    messages.insert(at < 0 ? messages.length : at, m);
  }

  Map<String, dynamic> metaJson() => {
        'id': id,
        'peer': peer,
        'state': state.name,
        'lastSeq': lastSeq,
        'liveTyping': liveTyping,
        'unread': unread,
        'stale': stale,
        'archiveUntil': archiveUntil,
        'archiveSeq': archiveSeq,
        'sent': sentSeqs.toList(),
      };

  factory Conversation.fromMeta(Map<String, dynamic> j) => Conversation(
        id: j['id'] as String,
        peer: j['peer'] as String,
        state: ConversationState.values.byName(j['state'] as String),
        lastSeq: j['lastSeq'] as int,
        liveTyping: (j['liveTyping'] as bool?) ?? true,
        stale: (j['stale'] as bool?) ?? false,
        archiveUntil: (j['archiveUntil'] as int?) ?? 0,
        archiveSeq: (j['archiveSeq'] as int?) ?? 0,
        sentSeqs: {...((j['sent'] as List?) ?? const []).cast<int>()},
      )..unread = (j['unread'] as int?) ?? 0;
}
