import 'package:flutter/foundation.dart';
import 'package:material_ui/material_ui.dart';

import '../api/api_client.dart';
import '../api/realtime.dart';
import '../state/app_state.dart';
import '../state/models.dart';
import 'chat_screen.dart';
import 'devices_screen.dart';
import 'link_screen.dart';
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
  bool _recoveryDialogOpen = false;

  YapApp get app => widget.app;

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: app,
      builder: (context, _) {
        // The recovery key is shown exactly once, right after it is created.
        final key = app.recoveryKeyToShow;
        if (key != null && !_recoveryDialogOpen) {
          _recoveryDialogOpen = true;
          WidgetsBinding.instance.addPostFrameCallback((_) async {
            if (mounted) await showRecoveryKeyDialog(context, app, key);
            _recoveryDialogOpen = false;
          });
        }
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
            icon: Badge(isLabelVisible: app.pendingLinks.isNotEmpty, child: const Icon(Icons.more_vert)),
            onSelected: (v) {
              if (v == 'logout') app.logout();
              if (v == 'previews') _toggleLinkPreviews(context, app);
              if (v == 'devices') {
                Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => DevicesScreen(app: app)));
              }
            },
            itemBuilder: (_) => [
              PopupMenuItem(
                value: 'devices',
                child: Text(app.pendingLinks.isEmpty ? 'Devices' : 'Devices (${app.pendingLinks.length} waiting)'),
              ),
              PopupMenuItem(value: 'previews', child: Text(app.linkPreviews ? 'Link previews: on' : 'Link previews: off')),
              const PopupMenuItem(value: 'logout', child: Text('Log out')),
            ],
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: onNew,
        icon: const Icon(Icons.add_comment_outlined),
        label: const Text('New chat'),
      ),
      body: items.isEmpty
          ? ListView(children: [
              for (final l in app.pendingLinks) _NewDeviceBanner(app: app, link: l),
              const SizedBox(height: 40),
              const _EmptyState(),
            ])
          : ListView(
              padding: const EdgeInsets.only(bottom: 88),
              children: [
                for (final l in app.pendingLinks) _NewDeviceBanner(app: app, link: l),
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

/// A new device of this account is waiting to be approved.
class _NewDeviceBanner extends StatelessWidget {
  const _NewDeviceBanner({required this.app, required this.link});
  final YapApp app;
  final PendingLink link;

  @override
  Widget build(BuildContext context) => Card(
        margin: const EdgeInsets.fromLTRB(12, 10, 12, 0),
        color: Theme.of(context).colorScheme.primaryContainer,
        child: ListTile(
          leading: const Icon(Icons.devices_other),
          title: Text('New device: "${link.name}"'),
          subtitle: const Text('Wants to join your account'),
          trailing: FilledButton(onPressed: () => showApprovalDialog(context, app, link), child: const Text('Review')),
        ),
      );
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
            : c.stale && c.last == null
                ? 'Read-only'
                : (c.last == null ? 'No messages yet' : '${c.last!.mine ? 'You: ' : ''}${c.last!.summary}');
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
      subtitle: Text(c.last?.summary ?? 'wants to chat with you', maxLines: 1, overflow: TextOverflow.ellipsis),
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

/// Turning link previews on needs an informed yes: the server fetches the page for the card.
Future<void> _toggleLinkPreviews(BuildContext context, YapApp app) async {
  if (app.linkPreviews) {
    await app.setLinkPreviews(false);
    return;
  }
  final ok = await showDialog<bool>(
    context: context,
    builder: (context) => AlertDialog(
      title: const Text('Show link previews?'),
      content: const Text(
        'When you send a link, your app asks the Yappitron server to load that page so a preview '
        'card (title, summary, picture) can be added to your message.\n\n'
        '• The server sees the link you are previewing, but not who you send it to. It stores nothing.\n'
        '• The card is end-to-end encrypted like the rest of the message.\n'
        '• The person you send it to never contacts the website, so it cannot see their address.\n\n'
        'If you leave this off, links are still tappable and nothing about them reaches the server.',
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Keep off')),
        FilledButton(onPressed: () => Navigator.pop(context, true), child: const Text('Turn on')),
      ],
    ),
  );
  if (ok == true) await app.setLinkPreviews(true);
}
