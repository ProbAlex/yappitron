// Typed, synchronous wrapper over the Rust core's byte API.

import 'dart:convert';
import 'dart:typed_data';

import 'backend.dart';
import 'codec.dart';

/// Method ids; keep in sync with crates/yap-core/src/api.rs and docs/CORE_API.md.
abstract final class _M {
  static const deviceNew = 1;
  static const deviceImport = 2;
  static const deviceExport = 3;
  static const deviceFree = 4;
  static const keyPackage = 5;
  static const convCreate = 6;
  static const convAddMembers = 7;
  static const convJoin = 8;
  static const convEncrypt = 9;
  static const convDecrypt = 10;
  static const convApplyCommit = 11;
  static const convEpoch = 12;
  static const convAddMembersStaged = 15;
  static const convCommitConfirm = 16;
  static const convCommitDiscard = 17;
  static const keyPackageSigner = 18;
  static const deviceSigner = 19;
  static const typingSeal = 13;
  static const typingOpen = 14;
  static const authRegisterStart = 20;
  static const authRegisterFinish = 21;
  static const authLoginStart = 22;
  static const authLoginFinish = 23;
  static const usernameCanonicalize = 30;
  static const linkKeypair = 42;
  static const linkSeal = 43;
  static const linkOpen = 44;
  static const fingerprint = 45;
  static const deriveKey = 46;
  static const vaultSeal = 40;
  static const vaultOpen = 41;
  static const blobSeal = 50;
  static const blobOpen = 51;
}

Uint8List _s(String s) => Uint8List.fromList(utf8.encode(s));

class YapCore {
  YapCore(this._backend);
  final CoreBackend _backend;

  List<Uint8List> _call(int method, List<Uint8List> args) =>
      decodeResponse(_backend.call(encodeRequest(method, args)));

  // ----- devices -----

  int deviceNew(String name) => readU32(_call(_M.deviceNew, [_s(name)]).first);

  int deviceImport(Uint8List blob, Uint8List key) =>
      readU32(_call(_M.deviceImport, [blob, key]).first);

  Uint8List deviceExport(int device, Uint8List key) =>
      _call(_M.deviceExport, [u32le(device), key]).first;

  void deviceFree(int device) => _call(_M.deviceFree, [u32le(device)]);

  Uint8List keyPackage(int device) => _call(_M.keyPackage, [u32le(device)]).first;

  // ----- conversations (addressed by group id = server conversation id) -----

  void convCreate(int device, Uint8List groupId) =>
      _call(_M.convCreate, [u32le(device), groupId]);

  ({Uint8List commit, Uint8List welcome}) convAddMembers(
      int device, Uint8List groupId, List<Uint8List> keyPackages) {
    final r = _call(_M.convAddMembers, [u32le(device), groupId, ...keyPackages]);
    return (commit: r[0], welcome: r[1]);
  }

  /// Join from a Welcome; returns the group id.
  Uint8List convJoin(int device, Uint8List welcome) =>
      _call(_M.convJoin, [u32le(device), welcome]).first;

  Uint8List convEncrypt(int device, Uint8List groupId, Uint8List plaintext) =>
      _call(_M.convEncrypt, [u32le(device), groupId, plaintext]).first;

  /// The decrypted message and its sender's MLS identity (`username/device-id`), which MLS
  /// authenticates. Throws a [CoreException] with `isOwnMessage` for this device's own echo.
  ({Uint8List plaintext, String sender}) convDecrypt(int device, Uint8List groupId, Uint8List ciphertext) {
    final r = _call(_M.convDecrypt, [u32le(device), groupId, ciphertext]);
    return (plaintext: r[0], sender: utf8.decode(r[1]));
  }

  void convApplyCommit(int device, Uint8List groupId, Uint8List commit) =>
      _call(_M.convApplyCommit, [u32le(device), groupId, commit]);

  int convEpoch(int device, Uint8List groupId) =>
      readU64(_call(_M.convEpoch, [u32le(device), groupId]).first);

  /// Build a commit adding devices WITHOUT applying it. Post it, then [convCommitConfirm] if the
  /// server accepted it or [convCommitDiscard] if not.
  ({Uint8List commit, Uint8List welcome}) convAddMembersStaged(
      int device, Uint8List groupId, List<Uint8List> keyPackages) {
    final r = _call(_M.convAddMembersStaged, [u32le(device), groupId, ...keyPackages]);
    return (commit: r[0], welcome: r[1]);
  }

  void convCommitConfirm(int device, Uint8List groupId) =>
      _call(_M.convCommitConfirm, [u32le(device), groupId]);

  void convCommitDiscard(int device, Uint8List groupId) =>
      _call(_M.convCommitDiscard, [u32le(device), groupId]);

  // ----- linking devices -----

  /// The signature public key a key package claims (the device's identity inside groups).
  Uint8List keyPackageSigner(Uint8List keyPackage) => _call(_M.keyPackageSigner, [keyPackage]).first;

  Uint8List deviceSigner(int device) => _call(_M.deviceSigner, [u32le(device)]).first;

  ({Uint8List secret, Uint8List public}) linkKeypair() {
    final r = _call(_M.linkKeypair, []);
    return (secret: r[0], public: r[1]);
  }

  Uint8List linkSeal(Uint8List recipientPublic, Uint8List data) =>
      _call(_M.linkSeal, [recipientPublic, data]).first;

  Uint8List linkOpen(Uint8List secret, Uint8List sealed) => _call(_M.linkOpen, [secret, sealed]).first;

  /// The short code both devices show while approving (`A1B2-C3D4-E5F6-0718-293A`).
  String fingerprint(Uint8List signaturePublic, Uint8List linkPublic) =>
      utf8.decode(_call(_M.fingerprint, [signaturePublic, linkPublic]).first);

  /// A key derived from [secret] for one purpose; different labels give unrelated keys.
  Uint8List deriveKey(Uint8List secret, String label) => _call(_M.deriveKey, [secret, _s(label)]).first;

  // ----- live typing -----

  Uint8List typingSeal(int device, Uint8List groupId, int seq, String text) =>
      _call(_M.typingSeal, [u32le(device), groupId, u64le(seq), _s(text)]).first;

  ({int seq, String text}) typingOpen(int device, Uint8List groupId, Uint8List frame) {
    final r = _call(_M.typingOpen, [u32le(device), groupId, frame]);
    return (seq: readU64(r[0]), text: utf8.decode(r[1]));
  }

  // ----- OPAQUE password exchange (the password never leaves the device) -----

  ({int state, Uint8List request}) authRegisterStart(String password) {
    final r = _call(_M.authRegisterStart, [_s(password)]);
    return (state: readU32(r[0]), request: r[1]);
  }

  Uint8List authRegisterFinish(
          int state, String password, String username, String serverId, Uint8List response) =>
      _call(_M.authRegisterFinish,
          [u32le(state), _s(password), _s(username), _s(serverId), response]).first;

  ({int state, Uint8List request}) authLoginStart(String password) {
    final r = _call(_M.authLoginStart, [_s(password)]);
    return (state: readU32(r[0]), request: r[1]);
  }

  /// Throws a [CoreException] for a wrong password.
  ({Uint8List finalization, Uint8List sessionKey}) authLoginFinish(
      int state, String password, String username, String serverId, Uint8List response) {
    final r = _call(_M.authLoginFinish,
        [u32le(state), _s(password), _s(username), _s(serverId), response]);
    return (finalization: r[0], sessionKey: r[1]);
  }

  /// Validate and lowercase a username; throws [CoreException] with the reason if invalid.
  String usernameCanonicalize(String username) =>
      utf8.decode(_call(_M.usernameCanonicalize, [_s(username)]).first);

  // ----- local data protection -----

  Uint8List vaultSeal(Uint8List key, String context, Uint8List data) =>
      _call(_M.vaultSeal, [key, _s(context), data]).first;

  Uint8List vaultOpen(Uint8List key, String context, Uint8List sealed) =>
      _call(_M.vaultOpen, [key, _s(context), sealed]).first;

  /// Encrypt a file under a fresh random [key] (see `yap_core::blob`); the result is what gets
  /// uploaded. [blobOpen] reverses it and throws [CoreException] if the key is wrong or the data
  /// was changed.
  Uint8List blobSeal(Uint8List key, Uint8List file) => _call(_M.blobSeal, [key, file]).first;

  Uint8List blobOpen(Uint8List key, Uint8List sealed) => _call(_M.blobOpen, [key, sealed]).first;
}
