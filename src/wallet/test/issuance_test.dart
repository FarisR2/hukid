import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:hukid_wallet/issuance.dart';

// Exact test-only trust mapping; never exported into the runtime application.
class TestIssuer implements OfferAdapter {
  int requests = 0;
  final response = Completer<ReceiptState>();
  @override
  OfferPreview? preview(String link) => link == 'test:offer'
      ? const OfferPreview(issuer: 'Emisor de prueba', title: 'Taller ficticio')
      : null;
  @override
  Future<ReceiptState> request(OfferPreview offer) {
    requests++;
    return response.future;
  }
}

void main() {
  test('preview is not a request; arbitrary URL is not trusted', () {
    final adapter = TestIssuer();
    final flow = Issuance(adapter);
    flow.preview('test:offer');
    expect(flow.offer?.issuer, 'Emisor de prueba');
    expect(adapter.requests, 0);
    flow.preview('https://untrusted.example/offer');
    expect(flow.offer, isNull);
    expect(flow.state, ReceiptState.unavailable);
    expect(adapter.requests, 0);
  });
  test('cancel clears preview and cannot request', () async {
    final adapter = TestIssuer();
    final flow = Issuance(adapter)..preview('test:offer');
    flow.cancel();
    await flow.receive(consent: true);
    expect(flow.offer, isNull);
    expect(flow.state, ReceiptState.idle);
    expect(adapter.requests, 0);
  });
  test('no consent has no side effects', () async {
    final adapter = TestIssuer();
    final flow = Issuance(adapter)..preview('test:offer');
    await flow.receive(consent: false);
    expect(flow.offer?.title, 'Taller ficticio');
    expect(flow.state, ReceiptState.preview);
    expect(adapter.requests, 0);
  });
  test(
    'explicit consent requests once including double tap and failure',
    () async {
      final adapter = TestIssuer();
      final flow = Issuance(adapter)..preview('test:offer');
      final first = flow.receive(consent: true);
      await flow.receive(consent: true);
      expect(flow.state, ReceiptState.pending);
      expect(adapter.requests, 1);
      adapter.response.completeError(StateError('unavailable'));
      await first;
      await flow.receive(consent: true);
      expect(flow.state, ReceiptState.unavailable);
      expect(adapter.requests, 1);
    },
  );
  test('runtime backend has no trusted preview or success state', () async {
    final flow = Issuance(const UnavailableIssuer());
    for (final link in ['', 'test:offer', 'https://issuer.example/offer']) {
      flow.preview(link);
      await flow.receive(consent: true);
      expect(flow.offer, isNull);
      expect(flow.state, ReceiptState.unavailable);
    }
    expect(ReceiptState.values.map((s) => s.name), [
      'idle',
      'preview',
      'pending',
      'unavailable',
    ]);
  });
}
