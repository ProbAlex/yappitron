import 'package:material_ui/material_ui.dart';

import '../state/app_state.dart';
import 'auth_screen.dart';
import 'home_screen.dart';
import 'link_screen.dart';

class YapRoot extends StatelessWidget {
  const YapRoot({super.key, required this.app, this.startupError});

  final YapApp? app;
  final Object? startupError;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Yappitron',
      debugShowCheckedModeBanner: false,
      themeMode: ThemeMode.system,
      theme: _theme(Brightness.light),
      darkTheme: _theme(Brightness.dark),
      home: app == null
          ? _StartupFailure(error: startupError)
          : ListenableBuilder(
              listenable: app!,
              builder: (context, _) => switch (app!.phase) {
                Phase.booting => const Scaffold(body: Center(child: CircularProgressIndicator())),
                Phase.signedOut => AuthScreen(app: app!),
                Phase.awaitingApproval => LinkScreen(app: app!),
                Phase.signedIn => HomeScreen(app: app!),
              },
            ),
    );
  }

  ThemeData _theme(Brightness b) => ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF0F766E), brightness: b),
        inputDecorationTheme: const InputDecorationTheme(border: OutlineInputBorder()),
      );
}

class _StartupFailure extends StatelessWidget {
  const _StartupFailure({this.error});
  final Object? error;

  @override
  Widget build(BuildContext context) => Scaffold(
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.error_outline, size: 48),
                const SizedBox(height: 16),
                Text('Yappitron could not start', style: Theme.of(context).textTheme.titleLarge),
                const SizedBox(height: 8),
                Text('$error', textAlign: TextAlign.center),
              ],
            ),
          ),
        ),
      );
}
