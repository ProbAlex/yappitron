class ChatMessage {
  ChatMessage({required this.seq, required this.mine, required this.time, required this.text});

  /// Server sequence number (the order of the conversation's log).
  final int seq;

  /// Written by this account (on this device or another of its devices).
  final bool mine;
  final DateTime time;
  final String text;

  Map<String, dynamic> toJson() => {'s': seq, 'm': mine, 't': time.millisecondsSinceEpoch, 'x': text};

  factory ChatMessage.fromJson(Map<String, dynamic> j) => ChatMessage(
        seq: j['s'] as int,
        mine: j['m'] as bool,
        time: DateTime.fromMillisecondsSinceEpoch(j['t'] as int),
        text: j['x'] as String,
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
