import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import '../api/api_client.dart';
import '../state/app_state.dart';

/// Shown when this device is signed in but cannot read anything yet: it is waiting for another
/// of the account's devices to approve it, or it needs the recovery key to get the history key.
class LinkScreen extends StatelessWidget {
  const LinkScreen({super.key, required this.app});
  final YapApp app;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final restoring = app.needsHistoryKey;
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 460),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Icon(restoring ? Icons.key : Icons.devices_other, size: 56, color: scheme.primary),
                  const SizedBox(height: 12),
                  Text(restoring ? 'Restore your history key' : 'Approve this device',
                      textAlign: TextAlign.center, style: Theme.of(context).textTheme.headlineSmall),
                  const SizedBox(height: 12),
                  if (restoring)
                    const Text(
                      'This device is signed in but is missing the key that unlocks your message history. '
                      'Enter your recovery key to restore it.',
                      textAlign: TextAlign.center,
                    )
                  else ...[
                    const Text(
                      'You are signed in as a new device. For your safety it cannot read any messages '
                      'until a device you already use approves it.',
                      textAlign: TextAlign.center,
                    ),
                    const SizedBox(height: 20),
                    const Text('1. Open Yappitron on one of your other devices.\n'
                        '2. Tap the notice about a new device and compare this code:'),
                    const SizedBox(height: 12),
                    _Code(code: app.linkFingerprint ?? '...'),
                    const SizedBox(height: 12),
                    Text('Approve only if the codes are exactly the same.',
                        textAlign: TextAlign.center, style: Theme.of(context).textTheme.bodySmall),
                    const SizedBox(height: 16),
                    const Center(child: SizedBox(height: 22, width: 22, child: CircularProgressIndicator(strokeWidth: 2))),
                    const SizedBox(height: 6),
                    Text('Waiting for approval...', textAlign: TextAlign.center, style: Theme.of(context).textTheme.bodySmall),
                  ],
                  const SizedBox(height: 28),
                  OutlinedButton.icon(
                    icon: const Icon(Icons.key),
                    label: Text(restoring ? 'Enter recovery key' : 'I lost my other devices'),
                    onPressed: () => showRecoveryEntryDialog(context, app),
                  ),
                  TextButton(onPressed: app.logout, child: const Text('Log out')),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// A fingerprint, big and selectable so it can be compared at a glance.
class _Code extends StatelessWidget {
  const _Code({required this.code});
  final String code;

  @override
  Widget build(BuildContext context) => Semantics(
        label: 'Device code $code',
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 16, horizontal: 12),
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(12),
          ),
          child: SelectableText(
            code,
            textAlign: TextAlign.center,
            style: const TextStyle(fontFamily: 'monospace', fontSize: 22, fontWeight: FontWeight.w600, letterSpacing: 1.5),
          ),
        ),
      );
}

Future<void> showRecoveryEntryDialog(BuildContext context, YapApp app) async {
  final controller = TextEditingController();
  String? error;
  var busy = false;
  await showDialog<void>(
    context: context,
    barrierDismissible: false,
    builder: (context) => StatefulBuilder(
      builder: (context, setState) => AlertDialog(
        title: const Text('Recovery key'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('Enter the recovery key you saved when you created your account.\n\n'
                'This device becomes your only device and your other devices are signed out. '
                'Your old chats stay readable here, but to message someone again you start a new chat with them.'),
            const SizedBox(height: 12),
            TextField(
              controller: controller,
              autofocus: true,
              autocorrect: false,
              enableSuggestions: false,
              minLines: 2,
              maxLines: 3,
              decoration: InputDecoration(labelText: 'Recovery key', hintText: 'ABCD-EFGH-IJKL-...', errorText: error),
            ),
          ],
        ),
        actions: [
          TextButton(onPressed: busy ? null : () => Navigator.pop(context), child: const Text('Cancel')),
          FilledButton(
            onPressed: busy
                ? null
                : () async {
                    setState(() {
                      busy = true;
                      error = null;
                    });
                    try {
                      await app.recoverWithKey(controller.text);
                      if (context.mounted) Navigator.pop(context);
                    } on ApiException catch (e) {
                      setState(() {
                        busy = false;
                        error = e.message;
                      });
                    }
                  },
            child: busy
                ? const SizedBox(height: 18, width: 18, child: CircularProgressIndicator(strokeWidth: 2))
                : const Text('Restore'),
          ),
        ],
      ),
    ),
  );
  controller.dispose();
}

/// The recovery key is shown once; the person must confirm they saved it.
Future<void> showRecoveryKeyDialog(BuildContext context, YapApp app, String key) async {
  var saved = false;
  var copied = false;
  await showDialog<void>(
    context: context,
    barrierDismissible: false,
    builder: (context) => StatefulBuilder(
      builder: (context, setState) => AlertDialog(
        title: const Text('Save your recovery key'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('If you ever lose all your devices, this key is the only way to get your message history back. '
                  'We cannot show it again and nobody can recover it for you.\n\n'
                  'Copy it somewhere safe, like a password manager or a printed page.'),
              const SizedBox(height: 14),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(10),
                ),
                child: SelectableText(key,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 15, fontWeight: FontWeight.w600, height: 1.5)),
              ),
              const SizedBox(height: 8),
              Align(
                alignment: Alignment.centerRight,
                child: TextButton.icon(
                  icon: Icon(copied ? Icons.check : Icons.copy, size: 18),
                  label: Text(copied ? 'Copied' : 'Copy'),
                  onPressed: () async {
                    await Clipboard.setData(ClipboardData(text: key));
                    setState(() => copied = true);
                  },
                ),
              ),
              CheckboxListTile(
                contentPadding: EdgeInsets.zero,
                controlAffinity: ListTileControlAffinity.leading,
                value: saved,
                onChanged: (v) => setState(() => saved = v ?? false),
                title: const Text('I have saved my recovery key'),
              ),
            ],
          ),
        ),
        actions: [
          FilledButton(
            onPressed: saved
                ? () {
                    app.recoveryKeyShown();
                    Navigator.pop(context);
                  }
                : null,
            child: const Text('Continue'),
          ),
        ],
      ),
    ),
  );
}

/// Review a new device that asked to join: compare the code, then approve or reject.
Future<void> showApprovalDialog(BuildContext context, YapApp app, PendingLink link) async {
  final preview = app.prepareApproval(link);
  var busy = false;
  String? error;
  await showDialog<void>(
    context: context,
    barrierDismissible: false,
    builder: (context) => StatefulBuilder(
      builder: (context, setState) => FutureBuilder<ApprovalPreview>(
        future: preview,
        builder: (context, snap) {
          final data = snap.data;
          return AlertDialog(
            title: Text('Approve "${link.name}"?'),
            content: SingleChildScrollView(
              child: snap.hasError
                  ? Text(snap.error is ApiException ? (snap.error! as ApiException).message : '${snap.error}')
                  : data == null
                      ? const Padding(padding: EdgeInsets.all(24), child: Center(child: CircularProgressIndicator()))
                      : Column(
                          mainAxisSize: MainAxisSize.min,
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            const Text('Check that this code is exactly the same on the new device:'),
                            const SizedBox(height: 12),
                            _Code(code: data.fingerprint),
                            const SizedBox(height: 12),
                            const Text('Only approve a device you set up yourself, right now. An approved device can '
                                'read all of your messages and history.'),
                            if (error != null) ...[
                              const SizedBox(height: 10),
                              Text(error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
                            ],
                          ],
                        ),
            ),
            actions: [
              if (data != null)
                TextButton(
                  onPressed: busy
                      ? null
                      : () async {
                          try {
                            await app.rejectLink(link);
                            if (context.mounted) Navigator.pop(context);
                          } on ApiException catch (e) {
                            setState(() => error = e.message);
                          }
                        },
                  child: Text('Reject', style: TextStyle(color: Theme.of(context).colorScheme.error)),
                ),
              TextButton(onPressed: busy ? null : () => Navigator.pop(context), child: const Text('Not now')),
              if (data != null)
                FilledButton(
                  onPressed: busy
                      ? null
                      : () async {
                          setState(() {
                            busy = true;
                            error = null;
                          });
                          try {
                            await app.approve(data);
                            if (context.mounted) Navigator.pop(context);
                          } on ApiException catch (e) {
                            setState(() {
                              busy = false;
                              error = e.message;
                            });
                          }
                        },
                  child: busy
                      ? const SizedBox(height: 18, width: 18, child: CircularProgressIndicator(strokeWidth: 2))
                      : const Text('Codes match: approve'),
                ),
            ],
          );
        },
      ),
    ),
  );
}
