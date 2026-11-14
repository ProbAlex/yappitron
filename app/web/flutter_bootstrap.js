{{flutter_js}}
{{flutter_build_config}}

// The engine fetches fonts for emoji and non-Latin scripts on demand, a small slice at a time.
// By default it asks fonts.gstatic.com (Google), which would tell Google every visitor's IP and
// is blocked by this app's Content-Security-Policy anyway. Point it at our own server instead:
// `scripts/fetch-web-fonts.sh` mirrors the files into <web root>/fonts/s/.
_flutter.loader.load({
  config: {
    fontFallbackBaseUrl: new URL('fonts/s/', document.baseURI).href,
  },
});
