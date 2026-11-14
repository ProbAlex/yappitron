import 'package:material_ui/material_ui.dart';

import '../api/api_client.dart';
import '../state/app_state.dart';
import 'link_screen.dart';

/// The account's devices: approve new ones, remove old ones, replace the recovery key.
class DevicesScreen extends StatefulWidget {
  const DevicesScreen({super.key, required this.app});
  final YapApp app;

  @override
  State<DevicesScreen> createState() => _DevicesScreenState();
}

class _DevicesScreenState extends State<DevicesScreen> {
  late Future<List<DeviceDto>> _devices = widget.app.listDevices();

  YapApp get app => widget.app;

  void _reload() => setState(() => _devices = app.listDevices());

  void _snack(String text) => ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(text)));

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Devices')),
      body: ListenableBuilder(
        listenable: app,
        builder: (context, _) => FutureBuilder<List<DeviceDto>>(
          future: _devices,
          builder: (context, snap) {
            if (snap.hasError) return Center(child: Text(snap.error is ApiException ? (snap.error! as ApiException).message : '${snap.error}'));
            final list = snap.data;
            if (list == null) return const Center(child: CircularProgressIndicator());
            return ListView(
              children: [
                for (final link in app.pendingLinks)
                  Card(
                    margin: const EdgeInsets.fromLTRB(16, 12, 16, 0),
                    color: Theme.of(context).colorScheme.primaryContainer,
                    child: ListTile(
                      leading: const Icon(Icons.devices_other),
                      title: Text('"${link.name}" wants to join'),
                      subtitle: const Text('Compare the code and approve it'),
                      trailing: FilledButton(
                        onPressed: () async {
                          await showApprovalDialog(context, app, link);
                          _reload();
                        },
                        child: const Text('Review'),
                      ),
                    ),
                  ),
                const Padding(
                  padding: EdgeInsets.fromLTRB(16, 20, 16, 4),
                  child: Text('Your devices', style: TextStyle(fontWeight: FontWeight.w600)),
                ),
                for (final d in list)
                  ListTile(
                    leading: Icon(d.status == 'pending' ? Icons.hourglass_top : Icons.devices),
                    title: Text(d.name),
                    subtitle: Text(d.current
                        ? 'This device'
                        : d.status == 'pending'
                            ? 'Waiting for approval'
                            : 'Approved'),
                    trailing: d.current && list.where((x) => x.status == 'approved').length <= 1
                        ? null
                        : IconButton(
                            tooltip: d.current ? 'Remove this device' : 'Remove ${d.name}',
                            icon: const Icon(Icons.delete_outline),
                            onPressed: () => _confirmRemove(d),
                          ),
                  ),
                const Divider(height: 32),
                ListTile(
                  leading: const Icon(Icons.key),
                  title: const Text('Create a new recovery key'),
                  subtitle: const Text('Your old recovery key stops working'),
                  onTap: _newRecoveryKey,
                ),
                const Padding(
                  padding: EdgeInsets.all(16),
                  child: Text(
                    'A removed device is signed out and receives nothing more. It stays a member of existing '
                    'encrypted chats until the other person\'s app removes it.',
                    style: TextStyle(fontSize: 12),
                  ),
                ),
              ],
            );
          },
        ),
      ),
    );
  }

  Future<void> _confirmRemove(DeviceDto d) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(d.current ? 'Remove this device?' : 'Remove "${d.name}"?'),
        content: Text(d.current
            ? 'You will be signed out here and the local messages on this device are deleted.'
            : 'It is signed out and its local data stays on it, but it receives nothing more.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(context, true), child: const Text('Remove')),
        ],
      ),
    );
    if (ok != true) return;
    try {
      await app.removeDevice(d.id);
      if (!d.current && mounted) _reload();
    } on ApiException catch (e) {
      if (mounted) _snack(e.message);
    }
  }

  Future<void> _newRecoveryKey() async {
    try {
      await app.createNewRecoveryKey();
      if (mounted && app.recoveryKeyToShow != null) await showRecoveryKeyDialog(context, app, app.recoveryKeyToShow!);
    } on ApiException catch (e) {
      if (mounted) _snack(e.message);
    }
  }
}
