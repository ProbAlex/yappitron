import 'package:flutter/foundation.dart';
import 'package:material_ui/material_ui.dart';

import '../api/api_client.dart';
import '../api/realtime.dart';
import '../state/app_state.dart';
import '../state/models.dart';
import 'chat_screen.dart';
import 'format.dart';

const _wideBreakpoint = 820.0;

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key, required this.app});
  final YapApp app;

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  String? _selected;

  YapApp get app => widget.app;

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: app,
      builder: (context, _) {
        final wide = MediaQuery.sizeOf(context).width >= _wideBreakpoint;
        final list = _ConversationList(
          app: app,
          selectedId: wide ? _selected : null,
          onOpen: (c) => _open(c, wide),
          onNew: _newChat,
        );
        if (!wide) return list;
        final selected = _selected == null ? null : app.conversation(_selected!);
        return Scaffold(
          body: Row(
            children: [
              SizedBox(width: 360, child: list),
              const VerticalDivider(width: 1),
              Expanded(
                child: selected == null
                    ? const Center(child: Text('Select a conversation or start a new one'))
                    : ChatScreen(key: ValueKey(selected.id), app: app, conversationId: selected.id, embedded: true),
              ),
            ],
          ),
        );
      },
    );
  }

  void _open(Conversation c, bool wide) {
    if (wide) {
      setState(() => _selected = c.id);
    } else {
      Navigator.of(context).push(MaterialPageRoute<void>(
        builder: (_) => ChatScreen(app: app, conversationId: c.id),
      ));
    }
  }

  Future<void> _newChat() async {
    final controller = TextEditingController();
    final peer = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('New chat'),
        content: TextField(
          controller: controller,
          autofocus: true,
          autocorrect: false,
          decoration: const InputDecoration(labelText: 'Their username'),
          onSubmitted: (v) => Navigator.pop(context, v),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(context, controller.text), child: const Text('Start chat')),
        ],
      ),
    );
    if (peer == null || peer.trim().isEmpty || !mounted) return;
    try {
      final id = await app.startConversation(peer);
      if (!mounted) return;
      _open(app.conversation(id)!, MediaQuery.sizeOf(context).width >= _wideBreakpoint);
    } on ApiException catch (e) {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.message)));
    }
  }
}

class _ConversationList extends StatelessWidget {
  const _ConversationList({required this.app, required this.selectedId, required this.onOpen, required this.onNew});
  final YapApp app;
  final String? selectedId;
  final ValueChanged<Conversation> onOpen;
  final VoidCallback onNew;

  @override
  Widget build(BuildContext context) {
    final items = app.conversations;
    final requests = items.where((c) => c.state == ConversationState.invited).toList();
    final chats = items.where((c) => c.state != ConversationState.invited).toList();
    return Scaffold(
      appBar: AppBar(
        title: Text(app.username ?? 'Yappitron'),
        actions: [
          _LinkDot(status: app.link),
          PopupMenuButton<String>(
            tooltip: 'Account',
            onSelected: (v) async {
              if (v == 'logout') await app.logout();
            },
            itemBuilder: (_) => const [PopupMenuItem(value: 'logout', child: Text('Log out'))],
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: onNew,
        icon: const Icon(Icons.add_comment_outlined),
        label: const Text('New chat'),
      ),
      body: items.isEmpty
          ? const _EmptyState()
          : ListView(
              padding: const EdgeInsets.only(bottom: 88),
              children: [
                if (requests.isNotEmpty) ...[
                  const _SectionHeader('Message requests'),
                  for (final c in requests) _RequestTile(app: app, conversation: c, onOpen: () => onOpen(c)),
                  const Divider(),
                ],
                for (final c in chats)
                  _ChatTile(conversation: c, selected: c.id == selectedId, onTap: () => onOpen(c)),
              ],
            ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState();

  @override
  Widget build(BuildContext context) => Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.forum_outlined, size: 64, color: Theme.of(context).colorScheme.outline),
              const SizedBox(height: 16),
              Text('No conversations yet', style: Theme.of(context).textTheme.titleMedium),
              const SizedBox(height: 8),
              const Text('Start one with a friend\'s username. Everything is end-to-end encrypted.',
                  textAlign: TextAlign.center),
            ],
          ),
        ),
      );
}

class _SectionHeader extends StatelessWidget {
  const _SectionHeader(this.text);
  final String text;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
        child: Text(text, style: Theme.of(context).textTheme.labelLarge?.copyWith(color: Theme.of(context).colorScheme.primary)),
      );
}

class _Avatar extends StatelessWidget {
  const _Avatar(this.name);
  final String name;

  @override
  Widget build(BuildContext context) => CircleAvatar(
        child: Text(name.isEmpty ? '?' : name.characters.first.toUpperCase()),
      );
}

class _ChatTile extends StatelessWidget {
  const _ChatTile({required this.conversation, required this.selected, required this.onTap});
  final Conversation conversation;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final c = conversation;
    final typing = c.liveDraft != null;
    final preview = typing
        ? 'typing: ${c.liveDraft}'
        : c.state == ConversationState.declined
            ? 'Declined'
            : (c.last == null ? 'No messages yet' : '${c.last!.mine ? 'You: ' : ''}${c.last!.text}');
    return ListTile(
      selected: selected,
      leading: _Avatar(c.peer),
      title: Text(c.peer),
      subtitle: Text(preview, maxLines: 1, overflow: TextOverflow.ellipsis,
          style: typing ? TextStyle(color: Theme.of(context).colorScheme.primary, fontStyle: FontStyle.italic) : null),
      trailing: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          if (c.last != null) Text(shortTime(c.last!.time), style: Theme.of(context).textTheme.labelSmall),
          if (c.unread > 0)
            Badge(label: Text('${c.unread}'), backgroundColor: Theme.of(context).colorScheme.primary),
        ],
      ),
      onTap: onTap,
    );
  }
}

class _RequestTile extends StatelessWidget {
  const _RequestTile({required this.app, required this.conversation, required this.onOpen});
  final YapApp app;
  final Conversation conversation;
  final VoidCallback onOpen;

  @override
  Widget build(BuildContext context) {
    final c = conversation;
    return ListTile(
      leading: _Avatar(c.peer),
      title: Text(c.peer),
      subtitle: Text(c.last?.text ?? 'wants to chat with you', maxLines: 1, overflow: TextOverflow.ellipsis),
      onTap: onOpen,
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          IconButton(
            tooltip: 'Decline ${c.peer}',
            icon: const Icon(Icons.close),
            onPressed: () => _run(context, () => app.decline(c)),
          ),
          IconButton(
            tooltip: 'Accept ${c.peer}',
            icon: Icon(Icons.check, color: Theme.of(context).colorScheme.primary),
            onPressed: () => _run(context, () => app.accept(c)),
          ),
        ],
      ),
    );
  }

  Future<void> _run(BuildContext context, Future<void> Function() action) async {
    try {
      await action();
    } on ApiException catch (e) {
      if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.message)));
    }
  }
}

class _LinkDot extends StatelessWidget {
  const _LinkDot({required this.status});
  final RealtimeStatus status;

  @override
  Widget build(BuildContext context) {
    final (color, label) = switch (status) {
      RealtimeStatus.online => (Colors.green, 'Connected'),
      RealtimeStatus.connecting => (Colors.amber, 'Connecting'),
      RealtimeStatus.offline => (Colors.red, 'Offline'),
    };
    return Semantics(
      label: label,
      child: Tooltip(
        message: label,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 8),
          child: Icon(Icons.circle, size: 12, color: color),
        ),
      ),
    );
  }
}

/// Whether this build runs on a touch-first platform (used for composer behaviour).
bool get isTouchPlatform =>
    !kIsWeb && (defaultTargetPlatform == TargetPlatform.android || defaultTargetPlatform == TargetPlatform.iOS);
