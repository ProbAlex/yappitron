import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import '../api/api_client.dart';
import '../state/app_state.dart';
import '../state/models.dart';
import 'format.dart';
import 'home_screen.dart' show isTouchPlatform;

class ChatScreen extends StatefulWidget {
  const ChatScreen({super.key, required this.app, required this.conversationId, this.embedded = false});
  final YapApp app;
  final String conversationId;

  /// Shown inside the wide two-pane layout (no back button).
  final bool embedded;

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final _text = TextEditingController();
  final _scroll = ScrollController();
  final _focus = FocusNode();
  String? _error;

  YapApp get app => widget.app;

  @override
  void initState() {
    super.initState();
    app.openConversationId = widget.conversationId;
    final c = app.conversation(widget.conversationId);
    if (c != null) app.markRead(c);
  }

  @override
  void dispose() {
    if (app.openConversationId == widget.conversationId) app.openConversationId = null;
    _text.dispose();
    _scroll.dispose();
    _focus.dispose();
    super.dispose();
  }

  Future<void> _send(Conversation c) async {
    final text = _text.text;
    if (text.trim().isEmpty) return;
    _text.clear();
    try {
      await app.send(c, text);
      setState(() => _error = null);
    } on ApiException catch (e) {
      _text.text = text; // give the message back so nothing is lost
      setState(() => _error = e.message);
    }
    _focus.requestFocus();
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: app,
      builder: (context, _) {
        final c = app.conversation(widget.conversationId);
        if (c == null) {
          return const Scaffold(body: Center(child: Text('This conversation is no longer available')));
        }
        if (app.openConversationId == c.id && c.unread > 0) {
          WidgetsBinding.instance.addPostFrameCallback((_) => app.markRead(c));
        }
        return Scaffold(
          appBar: AppBar(
            automaticallyImplyLeading: !widget.embedded,
            title: Text(c.peer),
            actions: [
              Tooltip(
                message: c.liveTyping
                    ? 'Live typing is on: ${c.peer} sees your draft as you type'
                    : 'Live typing is off: ${c.peer} only sees sent messages',
                child: Row(
                  children: [
                    const Icon(Icons.keyboard_alt_outlined, size: 18),
                    Switch(value: c.liveTyping, onChanged: (v) => app.setLiveTyping(c, v)),
                  ],
                ),
              ),
            ],
          ),
          body: Column(
            children: [
              if (c.state == ConversationState.invited) _RequestBanner(app: app, conversation: c),
              if (c.stale) _StaleBanner(app: app, conversation: c),
              if (c.state == ConversationState.declined)
                const MaterialBanner(
                  content: Text('This person declined your message request.'),
                  actions: [SizedBox.shrink()],
                ),
              Expanded(child: _Messages(conversation: c, scroll: _scroll)),
              if (_error != null)
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                  child: Semantics(liveRegion: true, child: Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error))),
                ),
              _Composer(
                controller: _text,
                focus: _focus,
                enabled: c.state == ConversationState.joined && !c.stale,
                hint: c.stale
                    ? 'Read-only'
                    : c.state == ConversationState.invited
                        ? 'Accept the request to reply'
                        : 'Message ${c.peer}',
                onChanged: (v) => app.onDraftChanged(c, v),
                onSend: () => _send(c),
              ),
            ],
          ),
        );
      },
    );
  }
}

/// This device is not part of the chat's encryption any more (the account's keys were reset).
class _StaleBanner extends StatelessWidget {
  const _StaleBanner({required this.app, required this.conversation});
  final YapApp app;
  final Conversation conversation;

  @override
  Widget build(BuildContext context) => MaterialBanner(
        content: Text('Your encryption keys were reset, so this chat is read-only here. '
            'Start a new chat with ${conversation.peer} to talk again.'),
        actions: [
          FilledButton(
            onPressed: () async {
              try {
                await app.startConversation(conversation.peer);
              } on ApiException catch (e) {
                if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.message)));
              }
            },
            child: const Text('Start a new chat'),
          ),
        ],
      );
}

class _RequestBanner extends StatelessWidget {
  const _RequestBanner({required this.app, required this.conversation});
  final YapApp app;
  final Conversation conversation;

  @override
  Widget build(BuildContext context) => MaterialBanner(
        content: Text('${conversation.peer} wants to chat. They cannot see when you read this, and live typing is off until you accept.'),
        actions: [
          TextButton(onPressed: () => app.decline(conversation), child: const Text('Decline')),
          FilledButton(onPressed: () => app.accept(conversation), child: const Text('Accept')),
        ],
      );
}

class _Messages extends StatelessWidget {
  const _Messages({required this.conversation, required this.scroll});
  final Conversation conversation;
  final ScrollController scroll;

  @override
  Widget build(BuildContext context) {
    final c = conversation;
    final draft = c.liveDraft;
    final msgs = c.messages;
    // Newest at the bottom: the list is reversed so the viewport stays anchored there.
    final extra = draft == null ? 0 : 1;
    return ListView.builder(
      controller: scroll,
      reverse: true,
      padding: const EdgeInsets.all(12),
      itemCount: msgs.length + extra,
      itemBuilder: (context, i) {
        if (draft != null && i == 0) return _LiveDraft(peer: c.peer, text: draft);
        final m = msgs[msgs.length - 1 - (i - extra)];
        final prev = (msgs.length - 2 - (i - extra)) >= 0 ? msgs[msgs.length - 2 - (i - extra)] : null;
        return _Bubble(message: m, showTime: prev == null || m.time.difference(prev.time).inMinutes >= 5);
      },
    );
  }
}

class _Bubble extends StatelessWidget {
  const _Bubble({required this.message, required this.showTime});
  final ChatMessage message;
  final bool showTime;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final mine = message.mine;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (showTime)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 8),
            child: Text(shortTime(message.time), textAlign: TextAlign.center, style: Theme.of(context).textTheme.labelSmall),
          ),
        Align(
          alignment: mine ? Alignment.centerRight : Alignment.centerLeft,
          child: Semantics(
            label: '${mine ? 'You' : 'They'} said: ${message.text}',
            child: Container(
              margin: const EdgeInsets.symmetric(vertical: 2),
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 9),
              constraints: BoxConstraints(maxWidth: MediaQuery.sizeOf(context).width * 0.75),
              decoration: BoxDecoration(
                color: mine ? scheme.primaryContainer : scheme.surfaceContainerHighest,
                borderRadius: BorderRadius.only(
                  topLeft: const Radius.circular(18),
                  topRight: const Radius.circular(18),
                  bottomLeft: Radius.circular(mine ? 18 : 4),
                  bottomRight: Radius.circular(mine ? 4 : 18),
                ),
              ),
              child: SelectableText(message.text),
            ),
          ),
        ),
      ],
    );
  }
}

/// What the other person is typing right now. It appears as they type and vanishes when they
/// send, clear it, or stop for a few seconds. It is never saved.
class _LiveDraft extends StatelessWidget {
  const _LiveDraft({required this.peer, required this.text});
  final String peer;
  final String text;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Align(
      alignment: Alignment.centerLeft,
      child: Semantics(
        label: '$peer is typing: $text',
        liveRegion: true,
        child: Container(
          margin: const EdgeInsets.symmetric(vertical: 2),
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 9),
          constraints: BoxConstraints(maxWidth: MediaQuery.sizeOf(context).width * 0.75),
          decoration: BoxDecoration(
            borderRadius: const BorderRadius.only(
              topLeft: Radius.circular(18),
              topRight: Radius.circular(18),
              bottomRight: Radius.circular(18),
              bottomLeft: Radius.circular(4),
            ),
            border: Border.all(color: scheme.primary.withValues(alpha: 0.6)),
          ),
          // The cursor is drawn, not a glyph: a special character would make the web build
          // fetch a fallback font (from a third party) just to render it.
          child: Text.rich(TextSpan(children: [
            TextSpan(text: text, style: TextStyle(color: scheme.onSurface.withValues(alpha: 0.75))),
            WidgetSpan(
              alignment: PlaceholderAlignment.middle,
              child: Container(
                margin: const EdgeInsets.only(left: 3),
                width: 2,
                height: 16,
                color: scheme.primary,
              ),
            ),
          ])),
        ),
      ),
    );
  }
}

class _Composer extends StatelessWidget {
  const _Composer({
    required this.controller,
    required this.focus,
    required this.enabled,
    required this.hint,
    required this.onChanged,
    required this.onSend,
  });
  final TextEditingController controller;
  final FocusNode focus;
  final bool enabled;
  final String hint;
  final ValueChanged<String> onChanged;
  final VoidCallback onSend;

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(12, 4, 12, 12),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.end,
          children: [
            Expanded(
              child: Focus(
                // On desktop and web, Enter sends and Shift+Enter adds a line. On phones Enter
                // is a newline and the send button sends.
                onKeyEvent: (node, event) {
                  if (!isTouchPlatform &&
                      event is KeyDownEvent &&
                      event.logicalKey == LogicalKeyboardKey.enter &&
                      !HardwareKeyboard.instance.isShiftPressed) {
                    onSend();
                    return KeyEventResult.handled;
                  }
                  return KeyEventResult.ignored;
                },
                child: TextField(
                  controller: controller,
                  focusNode: focus,
                  enabled: enabled,
                  minLines: 1,
                  maxLines: 5,
                  textCapitalization: TextCapitalization.sentences,
                  onChanged: onChanged,
                  decoration: InputDecoration(
                    labelText: hint,
                    border: const OutlineInputBorder(borderRadius: BorderRadius.all(Radius.circular(24))),
                    contentPadding: const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
                  ),
                ),
              ),
            ),
            const SizedBox(width: 8),
            IconButton.filled(
              tooltip: 'Send',
              onPressed: enabled ? onSend : null,
              icon: const Icon(Icons.send),
            ),
          ],
        ),
      ),
    );
  }
}
