import 'package:material_ui/material_ui.dart';

import '../api/api_client.dart';
import '../state/app_state.dart';

enum _Step { login, signupEmail, signupCode, signupAccount, resetEmail, resetCode, resetPassword }

class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key, required this.app});
  final YapApp app;

  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  _Step _step = _Step.login;
  final _email = TextEditingController();
  final _code = TextEditingController();
  final _username = TextEditingController();
  final _password = TextEditingController();
  final _password2 = TextEditingController();
  String? _ticket;
  String? _error;
  String? _notice;
  bool _busy = false;
  bool _showPassword = false;

  YapApp get app => widget.app;

  @override
  void dispose() {
    for (final c in [_email, _code, _username, _password, _password2]) {
      c.dispose();
    }
    super.dispose();
  }

  void _go(_Step step, {String? notice}) => setState(() {
        _step = step;
        _error = null;
        _notice = notice;
      });

  /// Run an async action with a spinner and turn failures into an inline message.
  Future<void> _run(Future<void> Function() action) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await action();
    } on ApiException catch (e) {
      if (mounted) setState(() => _error = e.message);
    } catch (e) {
      if (mounted) setState(() => _error = 'Something went wrong: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  String? _passwordProblem() {
    final p = _password.text;
    if (p.length < 10) return 'Use at least 10 characters';
    if (p != _password2.text) return 'The passwords do not match';
    return null;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Icon(Icons.forum_rounded, size: 56, color: Theme.of(context).colorScheme.primary),
                  const SizedBox(height: 8),
                  Text('Yappitron',
                      textAlign: TextAlign.center, style: Theme.of(context).textTheme.headlineMedium),
                  Text('Private chat. See what they type, as they type it.',
                      textAlign: TextAlign.center, style: Theme.of(context).textTheme.bodyMedium),
                  const SizedBox(height: 24),
                  if (app.notice != null) ...[
                    Container(
                      padding: const EdgeInsets.all(12),
                      margin: const EdgeInsets.only(bottom: 16),
                      decoration: BoxDecoration(
                        color: Theme.of(context).colorScheme.secondaryContainer,
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: Text(app.notice!, textAlign: TextAlign.center),
                    ),
                  ],
                  ..._form(),
                  if (_notice != null) ...[
                    const SizedBox(height: 12),
                    Text(_notice!, textAlign: TextAlign.center, style: TextStyle(color: Theme.of(context).colorScheme.primary)),
                  ],
                  if (_error != null) ...[
                    const SizedBox(height: 12),
                    Semantics(
                      liveRegion: true,
                      child: Text(_error!, textAlign: TextAlign.center, style: TextStyle(color: Theme.of(context).colorScheme.error)),
                    ),
                  ],
                  const SizedBox(height: 24),
                  _ServerRow(app: app),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _button(String label, VoidCallback? onPressed) => FilledButton(
        onPressed: _busy ? null : onPressed,
        child: _busy
            ? const SizedBox(height: 20, width: 20, child: CircularProgressIndicator(strokeWidth: 2))
            : Text(label),
      );

  Widget _link(String label, VoidCallback onPressed) => TextButton(onPressed: _busy ? null : onPressed, child: Text(label));

  Widget _field(TextEditingController c, String label,
          {bool obscure = false, TextInputType? type, ValueChanged<String>? onSubmitted, bool autofocus = false, String? helper}) =>
      Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: TextField(
          controller: c,
          autofocus: autofocus,
          obscureText: obscure && !_showPassword,
          keyboardType: type,
          onSubmitted: onSubmitted,
          autocorrect: false,
          enableSuggestions: false,
          decoration: InputDecoration(
            labelText: label,
            helperText: helper,
            suffixIcon: obscure
                ? IconButton(
                    tooltip: _showPassword ? 'Hide password' : 'Show password',
                    icon: Icon(_showPassword ? Icons.visibility_off : Icons.visibility),
                    onPressed: () => setState(() => _showPassword = !_showPassword),
                  )
                : null,
          ),
        ),
      );

  List<Widget> _form() {
    switch (_step) {
      case _Step.login:
        return [
          _field(_username, 'Username', autofocus: true),
          _field(_password, 'Password', obscure: true, onSubmitted: (_) => _login()),
          _button('Log in', _login),
          _link('Forgot password?', () => _go(_Step.resetEmail)),
          _link('Create an account', () => _go(_Step.signupEmail)),
        ];
      case _Step.signupEmail:
        return [
          Text('Create your account', style: Theme.of(context).textTheme.titleMedium, textAlign: TextAlign.center),
          const SizedBox(height: 12),
          _field(_email, 'Email address',
              type: TextInputType.emailAddress,
              autofocus: true,
              helper: 'Only used to verify you and reset your password. The server never stores it.',
              onSubmitted: (_) => _sendCode('signup', _Step.signupCode)),
          _button('Send me a code', () => _sendCode('signup', _Step.signupCode)),
          _link('I already have an account', () => _go(_Step.login)),
        ];
      case _Step.resetEmail:
        return [
          Text('Reset your password', style: Theme.of(context).textTheme.titleMedium, textAlign: TextAlign.center),
          const SizedBox(height: 12),
          _field(_email, 'Email address',
              type: TextInputType.emailAddress,
              autofocus: true,
              onSubmitted: (_) => _sendCode('reset', _Step.resetCode)),
          _button('Send me a code', () => _sendCode('reset', _Step.resetCode)),
          _link('Back to log in', () => _go(_Step.login)),
        ];
      case _Step.signupCode:
      case _Step.resetCode:
        final purpose = _step == _Step.signupCode ? 'signup' : 'reset';
        return [
          Text('Check your email', style: Theme.of(context).textTheme.titleMedium, textAlign: TextAlign.center),
          const SizedBox(height: 4),
          Text('We sent a 6-digit code to ${_email.text.trim()}.', textAlign: TextAlign.center),
          const SizedBox(height: 12),
          _field(_code, 'Verification code',
              type: TextInputType.number, autofocus: true, onSubmitted: (_) => _verify(purpose)),
          _button('Verify', () => _verify(purpose)),
          _link('Use a different email', () => _go(purpose == 'signup' ? _Step.signupEmail : _Step.resetEmail)),
        ];
      case _Step.signupAccount:
        return [
          Text('Choose a username and password', style: Theme.of(context).textTheme.titleMedium, textAlign: TextAlign.center),
          const SizedBox(height: 12),
          _field(_username, 'Username',
              autofocus: true, helper: '3-24 letters, digits or underscores. Others find you by this.'),
          _field(_password, 'Password', obscure: true, helper: 'At least 10 characters. It never leaves this device.'),
          _field(_password2, 'Repeat password', obscure: true, onSubmitted: (_) => _signup()),
          _button('Create account', _signup),
        ];
      case _Step.resetPassword:
        return [
          Text('Choose a new password', style: Theme.of(context).textTheme.titleMedium, textAlign: TextAlign.center),
          const SizedBox(height: 4),
          const Text('Your messages and keys are not affected.', textAlign: TextAlign.center),
          const SizedBox(height: 12),
          _field(_password, 'New password', obscure: true, autofocus: true, helper: 'At least 10 characters.'),
          _field(_password2, 'Repeat new password', obscure: true, onSubmitted: (_) => _reset()),
          _button('Set new password', _reset),
        ];
    }
  }

  Future<void> _login() => _run(() => app.login(_username.text, _password.text));

  Future<void> _sendCode(String purpose, _Step next) => _run(() async {
        if (!_email.text.contains('@')) throw ApiException(0, 'Enter a valid email address');
        await app.requestCode(purpose, _email.text);
        _code.clear();
        _go(next);
      });

  Future<void> _verify(String purpose) => _run(() async {
        _ticket = await app.verifyCode(purpose, _email.text, _code.text);
        _password.clear();
        _password2.clear();
        _go(purpose == 'signup' ? _Step.signupAccount : _Step.resetPassword);
      });

  Future<void> _signup() => _run(() async {
        final problem = _passwordProblem();
        if (problem != null) throw ApiException(0, problem);
        await app.finishSignup(ticket: _ticket!, username: _username.text, password: _password.text);
      });

  Future<void> _reset() => _run(() async {
        final problem = _passwordProblem();
        if (problem != null) throw ApiException(0, problem);
        final name = await app.finishReset(ticket: _ticket!, password: _password.text);
        _username.text = name;
        _password.clear();
        _go(_Step.login, notice: 'Password changed. Log in with your new password.');
      });
}

/// Lets people point the app at a self-hosted server.
class _ServerRow extends StatelessWidget {
  const _ServerRow({required this.app});
  final YapApp app;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: TextButton.icon(
        icon: const Icon(Icons.dns_outlined, size: 18),
        label: Text(Uri.parse(app.serverUrl).host),
        onPressed: () async {
          final controller = TextEditingController(text: app.serverUrl);
          final url = await showDialog<String>(
            context: context,
            builder: (context) => AlertDialog(
              title: const Text('Server'),
              content: TextField(
                controller: controller,
                decoration: const InputDecoration(labelText: 'Server address', hintText: 'https://chat.example.com'),
              ),
              actions: [
                TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
                FilledButton(onPressed: () => Navigator.pop(context, controller.text), child: const Text('Use this server')),
              ],
            ),
          );
          if (url == null) return;
          try {
            await app.setServerUrl(url);
          } on ApiException catch (e) {
            if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.message)));
          }
        },
      ),
    );
  }
}
