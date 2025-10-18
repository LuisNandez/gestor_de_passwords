// test/widget_test.dart
// Reemplaza el contenido de tu archivo test/widget_test.dart con este código.

import 'package:flutter_test/flutter_test.dart';
import 'package:gestor_de_passwords/main.dart'; // Asegúrate de que el nombre del paquete sea correcto

void main() {
  testWidgets('App starts without crashing', (WidgetTester tester) async {
    // Build our app and trigger a frame.
    // Se ha cambiado MyApp por PasswordManagerApp para que coincida con nuestro código.
    await tester.pumpWidget(const PasswordManagerApp());

    // En este punto, la prueba es muy simple y solo verifica que la app se inicie.
    // No busca ningún texto específico, ya que la primera pantalla es de carga
    // y luego la de bloqueo, que no tienen el texto '0' o '1'.
    // Esta prueba ahora es más robusta y solo confirma el arranque.
    expect(find.byType(PasswordManagerApp), findsOneWidget);
  });
}
