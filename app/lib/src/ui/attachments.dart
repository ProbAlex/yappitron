// Showing and sending files, and tappable links with preview cards, inside chat bubbles.

import 'dart:async';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/gestures.dart';
import 'package:material_ui/material_ui.dart';
import 'package:url_launcher/url_launcher.dart';

import '../api/api_client.dart';
import '../state/app_state.dart';
import '../state/image_size.dart';
import '../state/links.dart';
import '../state/mime.dart';
import '../state/models.dart';

/// Images up to this size load by themselves; bigger ones wait for a tap (data and memory).
const _autoLoadImageBytes = 10 * 1024 * 1024;

// ---------------------------------------------------------------- picking

/// Let the person choose files. Returns an empty list if they cancel.
Future<List<OutgoingFile>> pickOutgoingFiles() async {
  final picked = await FilePicker.pickFiles();
  final out = <OutgoingFile>[];
  for (final f in picked) {
    final length = await f.length() ?? 0;
    if (length > maxAttachmentBytes) {
      throw ApiException(0, '"${f.name}" is too large (the limit is ${maxAttachmentBytes ~/ (1024 * 1024)} MB).');
    }
    final bytes = await f.readAsBytes();
    final mime = mimeForName(f.name);
    int? w, h;
    if (mime.startsWith('image/') && mime != 'image/svg+xml' && bytes.length <= _autoLoadImageBytes) {
      final size = await imageSize(bytes);
      w = size?.$1;
      h = size?.$2;
    }
    out.add(OutgoingFile(name: f.name, mime: mime, bytes: bytes, width: w, height: h));
  }
  return out;
}

/// Ask for a caption and confirmation before sending [files]. Returns the caption, or null.
Future<String?> confirmSend(BuildContext context, List<OutgoingFile> files, String peer, String initialCaption) {
  final caption = TextEditingController(text: initialCaption);
  return showDialog<String>(
    context: context,
    builder: (context) => AlertDialog(
      title: Text('Send to $peer'),
      content: SizedBox(
        width: 420,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            for (final f in files.take(6))
              ListTile(
                dense: true,
                contentPadding: EdgeInsets.zero,
                leading: Icon(_iconFor(f.mime)),
                title: Text(f.name, maxLines: 1, overflow: TextOverflow.ellipsis),
                subtitle: Text(formatBytes(f.bytes.length)),
              ),
            if (files.length > 6) Text('and ${files.length - 6} more'),
            const SizedBox(height: 8),
            TextField(
              controller: caption,
              decoration: const InputDecoration(labelText: 'Caption (optional)'),
              maxLines: 3,
              minLines: 1,
            ),
          ],
        ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
        FilledButton(onPressed: () => Navigator.pop(context, caption.text), child: const Text('Send')),
      ],
    ),
  );
}

IconData _iconFor(String mime) {
  if (mime.startsWith('image/')) return Icons.image_outlined;
  if (mime.startsWith('video/')) return Icons.movie_outlined;
  if (mime.startsWith('audio/')) return Icons.audiotrack_outlined;
  if (mime == 'application/pdf') return Icons.picture_as_pdf_outlined;
  return Icons.insert_drive_file_outlined;
}

// ---------------------------------------------------------------- saving

Future<void> saveAttachment(BuildContext context, YapApp app, Attachment a) async {
  final messenger = ScaffoldMessenger.of(context);
  try {
    final bytes = await app.loadAttachment(a);
    await FilePicker.saveFile(fileName: a.name, bytes: bytes, mimeType: a.mime);
  } on ApiException catch (e) {
    messenger.showSnackBar(SnackBar(content: Text(e.message)));
  } catch (_) {
    messenger.showSnackBar(const SnackBar(content: Text('Could not save the file')));
  }
}

// ---------------------------------------------------------------- display

/// All attachments of one message.
class AttachmentList extends StatelessWidget {
  const AttachmentList({super.key, required this.app, required this.attachments});
  final YapApp app;
  final List<Attachment> attachments;

  @override
  Widget build(BuildContext context) => Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        mainAxisSize: MainAxisSize.min,
        children: [
          for (final a in attachments)
            Padding(
              padding: const EdgeInsets.only(bottom: 4),
              child: a.kind == AttachmentKind.image
                  ? ImageAttachment(app: app, attachment: a)
                  : FileAttachment(app: app, attachment: a),
            ),
        ],
      );
}

class ImageAttachment extends StatefulWidget {
  const ImageAttachment({super.key, required this.app, required this.attachment, this.maxHeight = 320});
  final YapApp app;
  final Attachment attachment;
  final double maxHeight;

  @override
  State<ImageAttachment> createState() => _ImageAttachmentState();
}

class _ImageAttachmentState extends State<ImageAttachment> {
  Future<Uint8List>? _bytes;

  Attachment get a => widget.attachment;

  @override
  void initState() {
    super.initState();
    if (a.size <= _autoLoadImageBytes) _load();
  }

  void _load() => setState(() => _bytes = widget.app.loadAttachment(a));

  @override
  Widget build(BuildContext context) {
    final ratio = (a.width != null && a.height != null && a.height! > 0) ? a.width! / a.height! : 4 / 3;
    final scheme = Theme.of(context).colorScheme;
    Widget placeholder(Widget child) => Container(color: scheme.surfaceContainerHigh, alignment: Alignment.center, child: child);
    final future = _bytes;
    final Widget content;
    if (future == null) {
      content = placeholder(TextButton.icon(
        onPressed: _load,
        icon: const Icon(Icons.download),
        label: Text('Load image (${formatBytes(a.size)})'),
      ));
    } else {
      content = FutureBuilder<Uint8List>(
        future: future,
        builder: (context, snap) {
          if (snap.hasError) {
            final msg = snap.error is ApiException ? (snap.error as ApiException).message : 'Could not load the image';
            return placeholder(Padding(
              padding: const EdgeInsets.all(8),
              child: Column(mainAxisSize: MainAxisSize.min, children: [
                Text(msg, textAlign: TextAlign.center),
                TextButton(onPressed: _load, child: const Text('Try again')),
              ]),
            ));
          }
          final bytes = snap.data;
          if (bytes == null) return placeholder(const SizedBox(width: 24, height: 24, child: CircularProgressIndicator(strokeWidth: 2)));
          return GestureDetector(
            onTap: () => showImageViewer(context, widget.app, a, bytes),
            child: Semantics(
              label: 'Photo ${a.name}',
              image: true,
              child: Image.memory(
                bytes,
                fit: BoxFit.cover,
                cacheWidth: 960,
                gaplessPlayback: true,
                errorBuilder: (context, _, _) => placeholder(FileAttachment(app: widget.app, attachment: a)),
              ),
            ),
          );
        },
      );
    }
    return ConstrainedBox(
      constraints: BoxConstraints(maxHeight: widget.maxHeight, maxWidth: 360),
      child: ClipRRect(borderRadius: BorderRadius.circular(12), child: AspectRatio(aspectRatio: ratio, child: content)),
    );
  }
}

Future<void> showImageViewer(BuildContext context, YapApp app, Attachment a, Uint8List bytes) {
  return showDialog<void>(
    context: context,
    builder: (context) => Dialog.fullscreen(
      backgroundColor: Colors.black,
      child: Stack(
        children: [
          Positioned.fill(child: InteractiveViewer(maxScale: 6, child: Center(child: Image.memory(bytes, fit: BoxFit.contain)))),
          Positioned(
            top: 8,
            right: 8,
            child: Row(children: [
              IconButton(
                tooltip: 'Save',
                color: Colors.white,
                icon: const Icon(Icons.download),
                onPressed: () => saveAttachment(context, app, a),
              ),
              IconButton(
                tooltip: 'Close',
                color: Colors.white,
                icon: const Icon(Icons.close),
                onPressed: () => Navigator.pop(context),
              ),
            ]),
          ),
        ],
      ),
    ),
  );
}

/// Anything that is not shown inline: videos, audio, documents. Saved to the device on request.
class FileAttachment extends StatelessWidget {
  const FileAttachment({super.key, required this.app, required this.attachment});
  final YapApp app;
  final Attachment attachment;

  @override
  Widget build(BuildContext context) {
    final a = attachment;
    final scheme = Theme.of(context).colorScheme;
    return Semantics(
      button: true,
      label: 'File ${a.name}, ${formatBytes(a.size)}. Save',
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: () => saveAttachment(context, app, a),
        child: Container(
          constraints: const BoxConstraints(maxWidth: 320),
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(
            color: scheme.surface.withValues(alpha: 0.6),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: scheme.outlineVariant),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(_iconFor(a.mime), size: 32, color: scheme.primary),
              const SizedBox(width: 10),
              Flexible(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(a.name, maxLines: 2, overflow: TextOverflow.ellipsis, style: const TextStyle(fontWeight: FontWeight.w600)),
                    Text(formatBytes(a.size), style: Theme.of(context).textTheme.bodySmall),
                  ],
                ),
              ),
              const SizedBox(width: 6),
              const Icon(Icons.download, size: 20),
            ],
          ),
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------- links

/// Open a link the person tapped, after showing where it really goes. Links in messages can
/// come from strangers, and the visible text of a link is not always its destination.
Future<void> openLink(BuildContext context, Uri url) async {
  final go = await showDialog<bool>(
    context: context,
    builder: (context) => AlertDialog(
      title: const Text('Open this link?'),
      content: SelectableText(url.toString()),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
        FilledButton(onPressed: () => Navigator.pop(context, true), child: Text('Open ${url.host}')),
      ],
    ),
  );
  if (go == true) await launchUrl(url, mode: LaunchMode.externalApplication);
}

/// Message text with its links made tappable.
class LinkText extends StatefulWidget {
  const LinkText(this.text, {super.key});
  final String text;

  @override
  State<LinkText> createState() => _LinkTextState();
}

class _LinkTextState extends State<LinkText> {
  final _recognizers = <TapGestureRecognizer>[];

  @override
  void dispose() {
    for (final r in _recognizers) {
      r.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    for (final r in _recognizers) {
      r.dispose();
    }
    _recognizers.clear();
    final parts = splitLinks(widget.text);
    if (parts.every((p) => !p.isLink)) return SelectableText(widget.text);
    final linkColor = Theme.of(context).colorScheme.primary;
    return SelectableText.rich(TextSpan(children: [
      for (final p in parts)
        if (p.url == null)
          TextSpan(text: p.text)
        else
          TextSpan(
            text: p.text,
            style: TextStyle(color: linkColor, decoration: TextDecoration.underline),
            recognizer: (TapGestureRecognizer()..onTap = () => openLink(context, p.url!)).also(_recognizers.add),
          ),
    ]));
  }
}

extension<T> on T {
  T also(void Function(T) f) {
    f(this);
    return this;
  }
}

/// A card under a message summarising a link. Built by the sender; opening it asks first.
class LinkPreviewCard extends StatelessWidget {
  const LinkPreviewCard({super.key, required this.app, required this.preview});
  final YapApp app;
  final LinkPreview preview;

  @override
  Widget build(BuildContext context) {
    final p = preview;
    final scheme = Theme.of(context).colorScheme;
    final uri = Uri.tryParse(p.url);
    final site = p.site ?? uri?.host ?? '';
    return Semantics(
      link: true,
      label: 'Link preview: ${p.title ?? site}',
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: uri == null ? null : () => openLink(context, uri),
        child: Container(
          constraints: const BoxConstraints(maxWidth: 340),
          decoration: BoxDecoration(
            color: scheme.surface.withValues(alpha: 0.6),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: scheme.outlineVariant),
          ),
          clipBehavior: Clip.antiAlias,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            mainAxisSize: MainAxisSize.min,
            children: [
              if (p.image != null) ImageAttachment(app: app, attachment: p.image!, maxHeight: 180),
              Padding(
                padding: const EdgeInsets.all(10),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(site, style: Theme.of(context).textTheme.labelSmall?.copyWith(color: scheme.primary)),
                    if (p.title != null)
                      Text(p.title!, maxLines: 2, overflow: TextOverflow.ellipsis, style: const TextStyle(fontWeight: FontWeight.w600)),
                    if (p.description != null)
                      Text(p.description!, maxLines: 3, overflow: TextOverflow.ellipsis, style: Theme.of(context).textTheme.bodySmall),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
