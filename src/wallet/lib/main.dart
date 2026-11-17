import 'package:material_ui/material_ui.dart';

import 'issuance.dart';

void main() => runApp(const WalletApp());

class WalletApp extends StatelessWidget {
  const WalletApp({super.key, this.adapter = const UnavailableIssuer()});
  final OfferAdapter adapter;

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'HukID Wallet',
    debugShowCheckedModeBanner: false,
    theme: ThemeData(
      colorScheme: ColorScheme.fromSeed(
        seedColor: const Color(0xff5027bc),
        primary: const Color(0xff5027bc),
        surface: Colors.white,
        onSurface: const Color(0xff24173d),
      ),
      scaffoldBackgroundColor: Colors.white,
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          minimumSize: const Size(48, 48),
          padding: const EdgeInsets.all(16),
        ),
      ),
    ),
    home: WalletHome(adapter: adapter),
  );
}

class WalletHome extends StatelessWidget {
  const WalletHome({super.key, this.adapter = const UnavailableIssuer()});
  final OfferAdapter adapter;

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('hukid.')),
    body: SafeArea(
      child: ListView(
        padding: const EdgeInsets.all(24),
        children: [
          Text('Mi wallet', style: Theme.of(context).textTheme.headlineLarge),
          const Text('Tus credenciales. Tú decides.'),
          const SizedBox(height: 32),
          const Text('0 credenciales'),
          const Card(
            color: Color(0xfff3effb),
            child: Padding(
              padding: EdgeInsets.all(24),
              child: Column(
                children: [
                  Icon(Icons.wallet_outlined, size: 48),
                  SizedBox(height: 16),
                  Text('Este espacio es tuyo.'),
                  Text('Todavía no hay credenciales en tu wallet.'),
                ],
              ),
            ),
          ),
          const SizedBox(height: 24),
          FilledButton.icon(
            icon: const Icon(Icons.add),
            label: const Text('Recibir credencial'),
            onPressed: () => Navigator.of(context).push<void>(
              MaterialPageRoute(builder: (_) => ReceivePage(adapter: adapter)),
            ),
          ),
          const SizedBox(height: 24),
          const Text('Laboratorio Android · Sin emisor configurado.'),
          const Text('Sin cámara, recepción real ni almacenamiento todavía.'),
        ],
      ),
    ),
  );
}

class ReceivePage extends StatefulWidget {
  const ReceivePage({super.key, required this.adapter});
  final OfferAdapter adapter;
  @override
  State<ReceivePage> createState() => _ReceivePageState();
}

class _ReceivePageState extends State<ReceivePage> {
  late final flow = Issuance(widget.adapter);
  final input = TextEditingController();
  bool consent = false;

  @override
  void dispose() {
    flow.cancel();
    input.dispose();
    super.dispose();
  }

  Future<void> receive() async {
    final result = flow.receive(consent: consent);
    setState(() {});
    await result;
    if (mounted) setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    final offer = flow.offer;
    final reviewing = flow.state == ReceiptState.preview;
    return Scaffold(
      appBar: AppBar(title: const Text('Recibir credencial')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(24),
          children: [
            if (offer == null) ...[
              const Text('Usar enlace'),
              const Text(
                'No pegues datos personales ni códigos reales. '
                'No se abrirán enlaces externos.',
              ),
              const SizedBox(height: 16),
              TextField(
                controller: input,
                autocorrect: false,
                enableSuggestions: false,
                decoration: const InputDecoration(
                  labelText: 'Enlace de oferta',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 16),
              FilledButton(
                onPressed: () => setState(() {
                  consent = false;
                  flow.preview(input.text);
                }),
                child: const Text('Revisar oferta'),
              ),
            ] else ...[
              Text(
                'Una credencial para ti',
                style: Theme.of(context).textTheme.headlineMedium,
              ),
              const SizedBox(height: 16),
              Text(offer.issuer),
              Text(offer.title),
              const Text(
                'Vista previa. No acredita firma, estado ni validez. '
                'Revisa qué recibirás antes de solicitarlo.',
              ),
              CheckboxListTile(
                contentPadding: EdgeInsets.zero,
                title: const Text(
                  'Consiento solicitar esta credencial al emisor.',
                ),
                value: consent,
                onChanged: reviewing
                    ? (value) => setState(() => consent = value == true)
                    : null,
              ),
              FilledButton(
                onPressed: reviewing && consent ? receive : null,
                child: const Text('Solicitar recepción'),
              ),
            ],
            if (flow.state == ReceiptState.pending)
              Semantics(
                liveRegion: true,
                child: const Text('Recepción pendiente'),
              ),
            if (flow.state == ReceiptState.unavailable)
              Semantics(
                liveRegion: true,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Recepción no disponible'),
                    if (offer == null)
                      const Text(
                        'Sin emisor configurado. Integración no disponible.',
                      ),
                    const Text('No se guardó ninguna credencial.'),
                  ],
                ),
              ),
            const SizedBox(height: 16),
            TextButton(
              onPressed: () {
                flow.cancel();
                Navigator.of(context).pop();
              },
              child: const Text('Cancelar'),
            ),
          ],
        ),
      ),
    );
  }
}
