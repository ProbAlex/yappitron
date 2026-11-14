import 'package:material_ui/material_ui.dart';
import 'package:flutter/semantics.dart';

import 'src/config.dart';
import 'src/core/backend.dart';
import 'src/core/yap_core.dart';
import 'src/data/local_store.dart';
import 'src/state/app_state.dart';
import 'src/ui/app.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  // Accessibility tree on from the start: screen readers work, and so do the end-to-end tests.
  // (On web this logs one harmless "Null check operator" error from Flutter's own text-editing
  // layer at startup; switching it on later breaks text-field focus, so it stays here.)
  SemanticsBinding.instance.ensureSemantics();
  Object? failure;
  YapApp? app;
  try {
    final core = YapCore(await openBackend());
    final store = await PlatformStore.open();
    app = YapApp(core: core, store: store, serverUrl: defaultServerUrl(), deviceLabel: deviceLabel());
    await app.boot();
  } catch (e) {
    failure = e;
  }
  runApp(YapRoot(app: app, startupError: failure));
}
