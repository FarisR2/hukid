import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hukid_wallet/main.dart';

import 'issuance_test.dart' show TestIssuer;

Future<void> openOffer(WidgetTester tester, TestIssuer adapter) async {
  await tester.pumpWidget(WalletApp(adapter: adapter));
  await tester.tap(find.text('Recibir credencial'));
  await tester.pumpAndSettle();
  await tester.enterText(find.byType(TextField), 'test:offer');
  await tester.tap(find.text('Revisar oferta'));
  await tester.pumpAndSettle();
}

Finder pageListScrollable(Finder page) {
  expect(page, findsOneWidget);
  final list = find.descendant(of: page, matching: find.byType(ListView));
  expect(list, findsOneWidget);
  final scrollable = find.descendant(
    of: list,
    matching: find.byWidgetPredicate(
      (widget) =>
          widget is Scrollable && widget.axisDirection == AxisDirection.down,
    ),
  );
  expect(scrollable, findsOneWidget);
  return scrollable;
}

void main() {
  testWidgets('preview, consent and repeated tap never fake storage', (
    tester,
  ) async {
    final adapter = TestIssuer();
    await openOffer(tester, adapter);
    expect(find.text('Emisor de prueba'), findsOneWidget);
    expect(adapter.requests, 0);
    await tester.tap(find.text('Solicitar recepción'));
    await tester.pump();
    expect(adapter.requests, 0);
    await tester.tap(find.byType(CheckboxListTile));
    await tester.pump();
    await tester.tap(find.text('Solicitar recepción'));
    await tester.pump();
    expect(adapter.requests, 1);
    expect(find.text('Recepción pendiente'), findsOneWidget);
    adapter.response.completeError(StateError('offline'));
    await tester.pumpAndSettle();
    expect(find.text('Recepción no disponible'), findsOneWidget);
    expect(find.text('No se guardó ninguna credencial.'), findsOneWidget);
  });
  testWidgets('cancel and Android back have no request side effects', (
    tester,
  ) async {
    final adapter = TestIssuer();
    await openOffer(tester, adapter);
    await tester.tap(find.text('Cancelar'));
    await tester.pumpAndSettle();
    expect(find.text('Mi wallet'), findsOneWidget);
    expect(adapter.requests, 0);
    await tester.tap(find.text('Recibir credencial'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'test:offer');
    await tester.tap(find.text('Revisar oferta'));
    await tester.pumpAndSettle();
    await tester.binding.handlePopRoute();
    await tester.pumpAndSettle();
    expect(find.text('Mi wallet'), findsOneWidget);
    expect(adapter.requests, 0);
  });
  testWidgets('runtime is empty and explains missing issuer at large text', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(640, 1200);
    tester.view.devicePixelRatio = 2;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(
      MaterialApp(
        builder: (context, child) => MediaQuery(
          data: MediaQuery.of(context)
              .copyWith(textScaler: TextScaler.linear(2)),
          child: child!,
        ),
        home: const WalletHome(),
      ),
    );
    expect(find.text('0 credenciales'), findsOneWidget);
    await tester.scrollUntilVisible(
      find.text('Recibir credencial'),
      200,
      scrollable: pageListScrollable(find.byType(WalletHome)),
    );
    await tester.tap(find.text('Recibir credencial'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'https://unknown.example');
    await tester.scrollUntilVisible(
      find.text('Revisar oferta'),
      200,
      scrollable: pageListScrollable(find.byType(ReceivePage)),
    );
    await tester.tap(find.text('Revisar oferta'));
    await tester.pumpAndSettle();
    await tester.scrollUntilVisible(
      find.text('No se guardó ninguna credencial.'),
      200,
      scrollable: pageListScrollable(find.byType(ReceivePage)),
    );
    expect(
      find.text('Sin emisor configurado. Integración no disponible.'),
      findsOneWidget,
    );
    expect(find.text('No se guardó ninguna credencial.'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}
