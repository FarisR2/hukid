enum ReceiptState { idle, preview, pending, unavailable }

class OfferPreview {
  const OfferPreview({required this.issuer, required this.title});
  final String issuer;
  final String title;
}

// Implementations must obtain previews from configured trust, not URL syntax.
abstract interface class OfferAdapter {
  OfferPreview? preview(String link);
  Future<ReceiptState> request(OfferPreview offer);
}

class UnavailableIssuer implements OfferAdapter {
  const UnavailableIssuer();
  @override
  OfferPreview? preview(String link) => null;
  @override
  Future<ReceiptState> request(OfferPreview offer) async =>
      ReceiptState.unavailable;
}

class Issuance {
  Issuance(this._adapter);
  final OfferAdapter _adapter;
  OfferPreview? _offer;
  ReceiptState _state = ReceiptState.idle;
  int _generation = 0;
  OfferPreview? get offer => _offer;
  ReceiptState get state => _state;

  void preview(String link) {
    if (_state == ReceiptState.pending) return;
    cancel();
    try {
      _offer = _adapter.preview(link.trim());
    } catch (_) {
      _offer = null;
    }
    _state = _offer == null ? ReceiptState.unavailable : ReceiptState.preview;
  }

  void cancel() {
    _generation++;
    _offer = null;
    _state = ReceiptState.idle;
  }

  Future<void> receive({required bool consent}) async {
    if (!consent || _state != ReceiptState.preview || _offer == null) return;
    final generation = _generation;
    _state = ReceiptState.pending;
    var result = ReceiptState.unavailable;
    try {
      final response = await _adapter.request(_offer!);
      // This unit deliberately cannot represent a verified or stored credential.
      if (response == ReceiptState.pending) result = ReceiptState.pending;
    } catch (_) {
      // Never expose adapter errors or offer data in messages/logs.
    }
    if (_generation == generation) _state = result;
  }
}
