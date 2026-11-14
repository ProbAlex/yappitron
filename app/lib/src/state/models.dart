class ChatMessage {
  ChatMessage({required this.seq, required this.mine, required this.time, required this.text});

  /// Server sequence number (the order of the conversation's log).
  final int seq;
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
    List<ChatMessage>? messages,
  }) : messages = messages ?? [];

  final String id;
  final String peer;
  ConversationState state;

  /// Highest log sequence number processed on this device.
  int lastSeq;

  /// Whether this device sends live-typing frames for this chat.
  bool liveTyping;
  final List<ChatMessage> messages;

  /// What the other person is typing right now (live, never stored).
  String? liveDraft;
  DateTime? liveDraftAt;
  int unread = 0;

  /// Highest typing-frame sequence seen (frames can arrive out of order).
  int typingSeqIn = -1;

  /// Sequence numbers of messages this device sent (they are skipped, not decrypted, on replay).
  Set<int> get ownSeqs => {for (final m in messages) if (m.mine) m.seq};

  ChatMessage? get last => messages.isEmpty ? null : messages.last;

  Map<String, dynamic> metaJson() => {
        'id': id,
        'peer': peer,
        'state': state.name,
        'lastSeq': lastSeq,
        'liveTyping': liveTyping,
        'unread': unread,
      };

  factory Conversation.fromMeta(Map<String, dynamic> j) => Conversation(
        id: j['id'] as String,
        peer: j['peer'] as String,
        state: ConversationState.values.byName(j['state'] as String),
        lastSeq: j['lastSeq'] as int,
        liveTyping: (j['liveTyping'] as bool?) ?? true,
      )..unread = (j['unread'] as int?) ?? 0;
}
