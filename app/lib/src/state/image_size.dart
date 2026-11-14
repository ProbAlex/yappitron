import 'dart:typed_data';
import 'dart:ui' as ui;

/// Pixel size of an encoded image, or null if this platform cannot decode the format.
Future<(int, int)?> imageSize(Uint8List bytes) async {
  try {
    final codec = await ui.instantiateImageCodec(bytes);
    final frame = await codec.getNextFrame();
    final size = (frame.image.width, frame.image.height);
    frame.image.dispose();
    codec.dispose();
    return size;
  } catch (_) {
    return null;
  }
}
