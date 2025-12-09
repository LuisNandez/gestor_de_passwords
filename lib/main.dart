import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:pointycastle/export.dart' as pc;
import 'package:file_picker/file_picker.dart';
import 'package:csv/csv.dart';
import 'package:excel/excel.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:provider/provider.dart';
import 'package:flutter/foundation.dart';

// --- GESTOR DE TEMA ---
class ThemeNotifier with ChangeNotifier {
  final String key = "theme";
  SharedPreferences? _prefs;
  ThemeMode _themeMode;

  ThemeMode get themeMode => _themeMode;

  ThemeNotifier() : _themeMode = ThemeMode.system {
    _loadFromPrefs();
  }

  Future<void> _initPrefs() async {
    _prefs ??= await SharedPreferences.getInstance();
  }

  Future<void> _loadFromPrefs() async {
    await _initPrefs();
    String? themeStr = _prefs!.getString(key);
    if (themeStr == 'light') {
      _themeMode = ThemeMode.light;
    } else if (themeStr == 'dark') {
      _themeMode = ThemeMode.dark;
    } else {
      _themeMode = ThemeMode.system;
    }
    notifyListeners();
  }

  Future<void> setTheme(ThemeMode themeMode) async {
    _themeMode = themeMode;
    await _initPrefs();
    if (themeMode == ThemeMode.light) {
      await _prefs!.setString(key, 'light');
    } else if (themeMode == ThemeMode.dark) {
      await _prefs!.setString(key, 'dark');
    } else {
      await _prefs!.setString(key, 'system');
    }
    notifyListeners();
  }
}

// --- MODELO DE CAMPO PERSONALIZADO ---
class CustomField {
  String name;
  String value;

  CustomField({this.name = '', this.value = ''});

  Map<String, dynamic> toJson() => {'name': name, 'value': value};

  factory CustomField.fromJson(Map<String, dynamic> json) =>
      CustomField(name: json['name'], value: json['value']);
}


// --- MODELOS DE DATOS ---
class Credencial {
  String id;
  String nombre;
  String email;
  String usuario;
  String contrasena;
  String numeroTelefono;
  String notas;
  DateTime fechaModificacion;
  List<CustomField> customFields;

  Credencial({
    required this.id,
    required this.nombre,
    this.email = '',
    this.usuario = '',
    this.contrasena = '',
    this.numeroTelefono = '',
    this.notas = '',
    required this.fechaModificacion,
    List<CustomField>? customFields,
  }) : this.customFields = customFields ?? [];

  Map<String, dynamic> toJson() => {
        'id': id,
        'nombre': nombre,
        'email': email,
        'usuario': usuario,
        'contrasena': contrasena,
        'numeroTelefono': numeroTelefono,
        'notas': notas,
        'fechaModificacion': fechaModificacion.toIso8601String(),
        'customFields': customFields.map((cf) => cf.toJson()).toList(),
      };

  factory Credencial.fromJson(Map<String, dynamic> json) => Credencial(
        id: json['id'],
        nombre: json['nombre'],
        email: json['email'],
        usuario: json['usuario'],
        contrasena: json['contrasena'],
        numeroTelefono: json['numeroTelefono'],
        notas: json['notas'],
        fechaModificacion: DateTime.parse(json['fechaModificacion']),
        customFields: (json['customFields'] as List<dynamic>?)
            ?.map((cf) => CustomField.fromJson(cf))
            .toList() ?? [],
      );
}

class Boveda {
  final String saltBase64;
  final String ciphertextBase64;

  Boveda({required this.saltBase64, required this.ciphertextBase64});

  Map<String, dynamic> toJson() => {
        'saltBase64': saltBase64,
        'ciphertextBase64': ciphertextBase64,
      };

  factory Boveda.fromJson(Map<String, dynamic> json) => Boveda(
        saltBase64: json['saltBase64'],
        ciphertextBase64: json['ciphertextBase64'],
      );
}

Future<Boveda> _encryptVaultIsolate(Map<String, String> params) async {
  final cryptoService = CryptoService(); // Creamos una instancia aquí dentro
  final plainJson = params['plainJson']!;
  final masterPassword = params['masterPassword']!;
  
  // La lógica de cifrado original se ejecuta aquí
  final salt = encrypt.SecureRandom(16).bytes;
  final key = cryptoService._deriveKey(masterPassword, salt);
  final iv = encrypt.IV.fromSecureRandom(16);
  final encrypter = encrypt.Encrypter(encrypt.AES(key, mode: encrypt.AESMode.cbc));
  final encrypted = encrypter.encrypt(plainJson, iv: iv);
  final combinedPayload = iv.bytes + encrypted.bytes;
  
  return Boveda(
    saltBase64: base64.encode(salt),
    ciphertextBase64: base64.encode(combinedPayload),
  );
}

// Esta función se encarga del descifrado en segundo plano.
Future<String> _decryptVaultIsolate(Map<String, dynamic> params) async {
  final cryptoService = CryptoService(); // Creamos una instancia aquí dentro
  final boveda = Boveda.fromJson(params['boveda']);
  final masterPassword = params['masterPassword'] as String;

  // La lógica de descifrado original se ejecuta aquí
  try {
    final salt = base64.decode(boveda.saltBase64);
    final key = cryptoService._deriveKey(masterPassword, salt);
    final encrypter = encrypt.Encrypter(encrypt.AES(key, mode: encrypt.AESMode.cbc));
    final combinedPayload = base64.decode(boveda.ciphertextBase64);
    final iv = encrypt.IV(combinedPayload.sublist(0, 16));
    final encryptedData = combinedPayload.sublist(16);
    final decrypted = encrypter.decrypt(encrypt.Encrypted(encryptedData), iv: iv);
    return decrypted;
  } catch (e) {
    // Es importante relanzar la excepción para que el hilo principal la capture.
    throw Exception('Contraseña maestra incorrecta o datos corruptos.');
  }
}


// --- SERVICIOS (LÓGICA DE NEGOCIO) ---

class CryptoService {
  encrypt.Key _deriveKey(String masterPassword, Uint8List salt) {
    final derivator = pc.PBKDF2KeyDerivator(pc.HMac(pc.SHA256Digest(), 64));
    derivator.init(pc.Pbkdf2Parameters(salt, 100000, 32));
    final keyBytes = derivator.process(Uint8List.fromList(utf8.encode(masterPassword)));
    return encrypt.Key(keyBytes);
  }

  Future<Boveda> encryptVault(String plainJson, String masterPassword) async {
    return compute(_encryptVaultIsolate, {
      'plainJson': plainJson,
      'masterPassword': masterPassword,
    });
  }

  Future<String> decryptVault(Boveda boveda, String masterPassword) async {
    return compute(_decryptVaultIsolate, {
      'boveda': boveda.toJson(), // Pasamos la bóveda como un mapa JSON
      'masterPassword': masterPassword,
    });
  }
}

class StorageService {
  Future<String> get _localPath async {
    final directory = await getApplicationDocumentsDirectory();
    return directory.path;
  }

  Future<File> get _localFile async {
    final path = await _localPath;
    return File('$path/boveda_segura.dat');
  }

  Future<Boveda?> readVault() async {
    try {
      final file = await _localFile;
      if (!await file.exists()) return null;
      final contents = await file.readAsString();
      return Boveda.fromJson(json.decode(contents));
    } catch (e) {
      return null;
    }
  }

  Future<File> writeVault(Boveda boveda) async {
    final file = await _localFile;
    return file.writeAsString(json.encode(boveda.toJson()));
  }
}

class ImportExportService {
  // Función para exportar a Excel con formato bonito
  Future<String?> exportToExcel(List<Credencial> credentials) async {
    var excel = Excel.createExcel();
    
    String sheetName = 'Mis Credenciales';
    Sheet sheet = excel[sheetName];
    excel.delete('Sheet1'); 

    // CORRECCIÓN 1: Usar ExcelColor.fromHexString en lugar de Strings simples
    CellStyle headerStyle = CellStyle(
      backgroundColorHex: ExcelColor.fromHexString('#0000FF'), // Azul
      fontFamily: getFontFamily(FontFamily.Calibri),
      fontColorHex: ExcelColor.fromHexString('#FFFFFF'),       // Blanco
      bold: true,
      horizontalAlign: HorizontalAlign.Center,
      verticalAlign: VerticalAlign.Center,
    );

    // Encabezados
    List<String> headers = ['Nombre', 'Email', 'Usuario', 'Contraseña', 'Teléfono', 'Notas'];
    
    for (var i = 0; i < headers.length; i++) {
      var cell = sheet.cell(CellIndex.indexByColumnRow(columnIndex: i, rowIndex: 0));
      cell.value = TextCellValue(headers[i]); 
      cell.cellStyle = headerStyle;
    }

    // Datos
    for (var i = 0; i < credentials.length; i++) {
      var cred = credentials[i];
      int rowIndex = i + 1;

      _addCell(sheet, 0, rowIndex, cred.nombre);
      _addCell(sheet, 1, rowIndex, cred.email);
      _addCell(sheet, 2, rowIndex, cred.usuario);
      _addCell(sheet, 3, rowIndex, cred.contrasena);
      _addCell(sheet, 4, rowIndex, cred.numeroTelefono);
      _addCell(sheet, 5, rowIndex, cred.notas);
    }

    // CORRECCIÓN 2: setColWidth -> setColumnWidth
    sheet.setColumnWidth(0, 25.0);
    sheet.setColumnWidth(1, 30.0);
    sheet.setColumnWidth(2, 20.0);
    sheet.setColumnWidth(3, 20.0);
    sheet.setColumnWidth(4, 20.0);
    sheet.setColumnWidth(5, 40.0);

    var fileBytes = excel.save();

    if (fileBytes != null) {
      String? outputFile = await FilePicker.platform.saveFile(
        dialogTitle: 'Guardar archivo Excel',
        fileName: 'mis_credenciales.xlsx',
        type: FileType.custom,
        allowedExtensions: ['xlsx'],
      );

      if (outputFile != null) {
        final file = File(outputFile);
        await file.writeAsBytes(fileBytes);
        return outputFile;
      }
    }
    return null;
  }

  void _addCell(Sheet sheet, int col, int row, String value) {
    var cell = sheet.cell(CellIndex.indexByColumnRow(columnIndex: col, rowIndex: row));
    cell.value = TextCellValue(value); // Clase nativa de excel v4
    // cell.cellStyle = CellStyle(textWrapping: TextWrapping.WrapText);
  }
  // Helper para añadir celdas de forma segura

  // --- IMPORTACIÓN (Se mantiene compatible con CSV y XLSX) ---
  Future<List<Credencial>> importFromFile() async {
    FilePickerResult? result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['csv', 'xlsx'],
    );

    if (result != null && result.files.single.path != null) {
      final path = result.files.single.path!;
      List<List<dynamic>> rows;
      
      try {
        if (path.endsWith('.csv')) {
          final content = await File(path).readAsString();
          rows = const CsvToListConverter(shouldParseNumbers: false).convert(content);
        } else if (path.endsWith('.xlsx')) {
          var bytes = File(path).readAsBytesSync();
          var excel = Excel.decodeBytes(bytes);
          // Tomamos la primera hoja disponible
          var sheetName = excel.tables.keys.first;
          var table = excel.tables[sheetName];
          
          if (table == null) return [];

          rows = [];
          // Convertimos las filas de Excel a lista de listas para procesarlas igual que el CSV
          for (var row in table.rows) {
            rows.add(row.map((e) => e?.value?.toString() ?? '').toList());
          }
        } else {
          return [];
        }
        return _processRows(rows);
      } catch (e) {
        print("Error importando: $e");
        rethrow;
      }
    }
    return [];
  }

  List<Credencial> _processRows(List<List<dynamic>> rows) {
    if (rows.isEmpty) return [];
    
    String getCellValue(dynamic cell) {
        return cell?.toString() ?? '';
    }

    final headers = rows.first.map((h) => getCellValue(h).trim().toLowerCase()).toList();
    
    final columnMap = <String, int>{};
    const headerAliases = {
      'nombre': ['nombre', 'name', 'sitio', 'website'],
      'email': ['email', 'correo'],
      'usuario': ['usuario', 'user', 'username'],
      'contrasena': ['contraseña', 'password', 'clave', 'contrasena'],
      'numeroTelefono': ['telefono', 'teléfono', 'phone', 'numero'],
      'notas': ['notas', 'notes', 'nota'],
    };

    for (int i = 0; i < headers.length; i++) {
      for (var entry in headerAliases.entries) {
        if (entry.value.contains(headers[i])) {
          columnMap[entry.key] = i;
          break;
        }
      }
    }

    if (!columnMap.containsKey('nombre')) {
      // Si no encuentra columnas exactas, intentamos asumir el orden estándar si es un archivo creado por nosotros
      if (headers.isNotEmpty && headers[0].contains('nombre')) {
         // Parece correcto, seguimos
      } else {
         // Fallback simple: si no hay headers claros, asumimos orden por índice (peligroso pero útil)
         columnMap['nombre'] = 0;
         columnMap['email'] = 1;
         columnMap['usuario'] = 2;
         columnMap['contrasena'] = 3;
         columnMap['numeroTelefono'] = 4;
         columnMap['notas'] = 5;
      }
    }

    List<Credencial> importedCredentials = [];
    // Empezamos en 1 para saltar el header
    for (int i = 1; i < rows.length; i++) {
      var row = rows[i];
      // Protección por si hay filas vacías al final
      if (row.every((element) => element.toString().trim().isEmpty)) continue;

      String getValue(String key) {
        if (columnMap.containsKey(key) && columnMap[key]! < row.length) {
          return getCellValue(row[columnMap[key]!]);
        }
        return '';
      }
      
      final nombre = getValue('nombre');
      if (nombre.isNotEmpty) {
        importedCredentials.add(Credencial(
          id: DateTime.now().millisecondsSinceEpoch.toString() + '_$i',
          nombre: nombre,
          email: getValue('email'),
          usuario: getValue('usuario'),
          contrasena: getValue('contrasena'),
          numeroTelefono: getValue('numeroTelefono'),
          notas: getValue('notas'),
          fechaModificacion: DateTime.now(),
        ));
      }
    }
    return importedCredentials;
  }
}

// <<< MEJORA: SERVICIO PARA GUARDAR PREFERENCIAS >>>
class AppSettingsService {
  static const String _sortKey = 'sort_option';
  static SharedPreferences? _prefs;

  static Future<void> _init() async {
    _prefs ??= await SharedPreferences.getInstance();
  }

  static Future<void> saveSortOption(SortOption option) async {
    await _init();
    await _prefs!.setString(_sortKey, option.name);
  }

  static Future<SortOption> loadSortOption() async {
    await _init();
    final sortName = _prefs!.getString(_sortKey);
    return SortOption.values.firstWhere(
      (e) => e.name == sortName,
      orElse: () => SortOption.nameAsc, // Valor por defecto
    );
  }
}


// --- PUNTO DE ENTRADA DE LA APP ---
void main() {
  runApp(
    ChangeNotifierProvider(
      create: (_) => ThemeNotifier(),
      child: const PasswordManagerApp(),
    ),
  );
}

class PasswordManagerApp extends StatelessWidget {
  const PasswordManagerApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Consumer<ThemeNotifier>(
      builder: (context, themeNotifier, child) {
        return MaterialApp(
          title: 'Gestor de Contraseñas',
          theme: ThemeData(primarySwatch: Colors.blue, brightness: Brightness.light, visualDensity: VisualDensity.adaptivePlatformDensity),
          darkTheme: ThemeData(primarySwatch: Colors.blue, brightness: Brightness.dark, visualDensity: VisualDensity.adaptivePlatformDensity),
          themeMode: themeNotifier.themeMode,
          debugShowCheckedModeBanner: false,
          home: const AuthWrapper(),
        );
      },
    );
  }
}

class AuthWrapper extends StatefulWidget {
  const AuthWrapper({Key? key}) : super(key: key);
  @override
  _AuthWrapperState createState() => _AuthWrapperState();
}

class _AuthWrapperState extends State<AuthWrapper> {
  final StorageService _storage = StorageService();
  bool _vaultExists = false;
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _checkIfVaultExists();
  }

  void _checkIfVaultExists() async {
    final vault = await _storage.readVault();
    setState(() {
      _vaultExists = vault != null;
      _isLoading = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    if (_isLoading) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    return LockScreen(
      isNewVault: !_vaultExists,
      onUnlock: (credentials, masterPassword) {
        Navigator.of(context).pushReplacement(
          MaterialPageRoute(builder: (context) => HomeScreen(initialCredentials: credentials, masterPassword: masterPassword)),
        );
      },
    );
  }
}


// --- PANTALLAS (VISTAS) ---

class LockScreen extends StatefulWidget {
  final bool isNewVault;
  final Function(List<Credencial>, String) onUnlock;
  const LockScreen({Key? key, required this.isNewVault, required this.onUnlock}) : super(key: key);
  @override
  _LockScreenState createState() => _LockScreenState();
}

class _LockScreenState extends State<LockScreen> {
  final _masterPasswordController = TextEditingController();
  final _confirmPasswordController = TextEditingController();
  final _formKey = GlobalKey<FormState>();
  bool _isLoading = false;
  String? _errorText;
  final _crypto = CryptoService();
  final _storage = StorageService();

  Future<void> _submit() async {
    if (_isLoading) return;
    if (!_formKey.currentState!.validate()) return;
    
    setState(() { _isLoading = true; _errorText = null; });
    final masterPassword = _masterPasswordController.text;
    try {
      if (widget.isNewVault) {
        final emptyListJson = json.encode([]);
        final newBoveda = await _crypto.encryptVault(emptyListJson, masterPassword);
        await _storage.writeVault(newBoveda);
        widget.onUnlock([], masterPassword);
      } else {
        final boveda = await _storage.readVault();
        if (boveda != null) {
          final decryptedJson = await _crypto.decryptVault(boveda, masterPassword);
          final List<dynamic> decodedList = json.decode(decryptedJson);
          final credentials = decodedList.map((item) => Credencial.fromJson(item)).toList();
          widget.onUnlock(credentials, masterPassword);
        }
      }
    } catch (e) {
      setState(() { _errorText = e.toString().replaceFirst('Exception: ', ''); });
    } finally {
      if (mounted) {
        setState(() { _isLoading = false; });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(32.0),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 400),
            child: Form(
              key: _formKey,
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text(widget.isNewVault ? 'Crear Bóveda' : 'Desbloquear Bóveda', style: Theme.of(context).textTheme.headlineSmall, textAlign: TextAlign.center),
                  const SizedBox(height: 24),
                  TextFormField(
                    controller: _masterPasswordController,
                    obscureText: true,
                    autofocus: true,
                    onFieldSubmitted: (_) => _submit(),
                    decoration: const InputDecoration(labelText: 'Contraseña Maestra', border: OutlineInputBorder()),
                    validator: (value) => (value?.isEmpty ?? true) ? 'La contraseña no puede estar vacía' : null,
                  ),
                  if (widget.isNewVault) ...[
                    const SizedBox(height: 16),
                    TextFormField(
                      controller: _confirmPasswordController,
                      obscureText: true,
                      onFieldSubmitted: (_) => _submit(),
                      decoration: const InputDecoration(labelText: 'Confirmar Contraseña', border: OutlineInputBorder()),
                      validator: (value) => (value != _masterPasswordController.text) ? 'Las contraseñas no coinciden' : null,
                    ),
                  ],
                  const SizedBox(height: 24),
                  if (_errorText != null)
                    Padding(
                      padding: const EdgeInsets.only(bottom: 16.0),
                      child: Text(_errorText!, style: TextStyle(color: Theme.of(context).colorScheme.error), textAlign: TextAlign.center),
                    ),
                  ElevatedButton(
                    onPressed: _isLoading ? null : _submit,
                    style: ElevatedButton.styleFrom(padding: const EdgeInsets.symmetric(vertical: 16)),
                    child: _isLoading
                        ? const SizedBox(height: 20, width: 20, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                        : Text(widget.isNewVault ? 'Crear' : 'Desbloquear'),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

enum SortOption { nameAsc, nameDesc, dateDesc, dateAsc }

class HomeScreen extends StatefulWidget {
  final List<Credencial> initialCredentials;
  final String masterPassword;
  const HomeScreen({Key? key, required this.initialCredentials, required this.masterPassword}) : super(key: key);
  @override
  _HomeScreenState createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  late List<Credencial> _credentials;
  List<Credencial> _filteredCredentials = [];
  final _searchController = TextEditingController();
  final _crypto = CryptoService();
  final _storage = StorageService();
  final _importExport = ImportExportService();

  bool _isSelectionMode = false;
  final Set<String> _selectedCredentialIds = {};
  bool _showClearButton = false;
  SortOption _currentSortOption = SortOption.nameAsc;

  @override
  void initState() {
    super.initState();
    _credentials = widget.initialCredentials;
    _loadSettingsAndSort(); // <<< MEJORA: Cargar preferencias al inicio
    _searchController.addListener(() {
      _sortAndFilterCredentials();
      if (_searchController.text.isNotEmpty != _showClearButton) {
        setState(() {
          _showClearButton = _searchController.text.isNotEmpty;
        });
      }
    });
  }

  Future<void> _loadSettingsAndSort() async {
    _currentSortOption = await AppSettingsService.loadSortOption();
    _sortAndFilterCredentials();
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  void _sortAndFilterCredentials() {
    _credentials.sort((a, b) {
      switch (_currentSortOption) {
        case SortOption.nameAsc:
          return a.nombre.toLowerCase().compareTo(b.nombre.toLowerCase());
        case SortOption.nameDesc:
          return b.nombre.toLowerCase().compareTo(a.nombre.toLowerCase());
        case SortOption.dateDesc:
          return b.fechaModificacion.compareTo(a.fechaModificacion);
        case SortOption.dateAsc:
          return a.fechaModificacion.compareTo(b.fechaModificacion);
      }
    });

    final query = _searchController.text.toLowerCase();
    setState(() {
      if (query.isEmpty) {
        _filteredCredentials = List.from(_credentials);
      } else {
        _filteredCredentials = _credentials.where((c) {
          return c.nombre.toLowerCase().contains(query) ||
                 c.email.toLowerCase().contains(query) ||
                 c.usuario.toLowerCase().contains(query);
        }).toList();
      }
    });
  }

  Future<void> _saveChanges() async {
    final jsonToEncrypt = json.encode(_credentials.map((c) => c.toJson()).toList());
    final newBoveda = await _crypto.encryptVault(jsonToEncrypt, widget.masterPassword);
    await _storage.writeVault(newBoveda);
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Bóveda guardada.'), duration: Duration(seconds: 2)),
      );
    }
  }
  
  void _showSnackbar(String message, {bool isError = false}) {
     if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(message),
          backgroundColor: isError ? Theme.of(context).colorScheme.error : null,
        ),
      );
    }
  }

  Future<void> _importCredentials() async {
    try {
      final newCredentials = await _importExport.importFromFile();
      if (newCredentials.isNotEmpty) {
        final confirm = await showDialog<bool>(
          context: context,
          builder: (context) => AlertDialog(
            title: const Text('Confirmar Importación'),
            content: Text('Se encontraron ${newCredentials.length} credenciales. ¿Desea agregarlas a su bóveda?'),
            actions: [
              TextButton(onPressed: () => Navigator.of(context).pop(false), child: const Text('Cancelar')),
              TextButton(onPressed: () => Navigator.of(context).pop(true), child: const Text('Importar')),
            ],
          ),
        );

        if (confirm == true) {
          setState(() { _credentials.addAll(newCredentials); });
          _sortAndFilterCredentials();
          await _saveChanges();
          _showSnackbar('${newCredentials.length} credenciales importadas con éxito.');
        }
      } else {
        _showSnackbar('No se importaron credenciales.');
      }
    } catch (e) {
      _showSnackbar('Error al importar el archivo: ${e.toString().replaceFirst("Exception: ", "")}', isError: true);
    }
  }

  Future<void> _exportCredentials() async {
    if (_credentials.isEmpty) {
      _showSnackbar('No hay credenciales para exportar.');
      return;
    }
    try {
      // CAMBIO: Ahora llamamos a exportToExcel
      final path = await _importExport.exportToExcel(_credentials);
      
      if (path != null) {
        _showSnackbar('Credenciales exportadas a Excel en: $path');
      } else {
        _showSnackbar('Exportación cancelada.');
      }
    } catch (e) {
      _showSnackbar('Error al exportar: $e', isError: true);
    }
  }

  void _addOrUpdateCredential(Credencial credential) {
    final index = _credentials.indexWhere((c) => c.id == credential.id);
    setState(() {
      if (index != -1) _credentials[index] = credential;
      else _credentials.add(credential);
    });
    _sortAndFilterCredentials();
    _saveChanges();
  }
  
  void _showCredentialForm([Credencial? credential]) {
    Navigator.of(context).push(MaterialPageRoute(
      builder: (context) => CredentialFormScreen(credential: credential, onSave: _addOrUpdateCredential),
      fullscreenDialog: true,
    ));
  }
  
  void _showCredentialDetails(Credencial credential) {
    showDialog(
        context: context,
        builder: (context) => AlertDialog(
              contentPadding: const EdgeInsets.fromLTRB(24.0, 20.0, 24.0, 0),
              title: Text(credential.nombre),
              content: SingleChildScrollView(
                child: ListBody(
                  children: <Widget>[
                    _buildDetailRow(context, 'Email', credential.email),
                    _buildDetailRow(context, 'Usuario', credential.usuario),
                    _buildDetailRow(context, 'Contraseña', credential.contrasena, obscure: false),
                    _buildDetailRow(context, 'Teléfono', credential.numeroTelefono),
                    _buildDetailRow(context, 'Notas', credential.notas),
                    ...credential.customFields.map((cf) => _buildDetailRow(context, cf.name, cf.value)),
                  ],
                ),
              ),
              actions: <Widget>[TextButton(child: const Text('Cerrar'), onPressed: () => Navigator.of(context).pop())],
            ));
  }
  
  Widget _buildDetailRow(BuildContext context, String label, String value, {bool obscure = false}) {
    if (value.isEmpty) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          SizedBox(
            width: 90,
            child: Text('$label: ', style: const TextStyle(fontWeight: FontWeight.bold))
          ),
          Expanded(child: Text(obscure ? '•' * value.length : value)),
          const SizedBox(width: 8),
          IconButton(
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(),
            icon: const Icon(Icons.copy, size: 18),
            onPressed: () {
              Clipboard.setData(ClipboardData(text: value));
              ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('¡$label copiado al portapapeles!'), duration: const Duration(seconds: 1)));
            },
          )
        ],
      ),
    );
  }

  void _toggleSelectionMode({String? initialSelectionId}) {
    setState(() {
      _isSelectionMode = !_isSelectionMode;
      _selectedCredentialIds.clear();
      if (_isSelectionMode && initialSelectionId != null) {
        _selectedCredentialIds.add(initialSelectionId);
      }
    });
  }

  void _onItemTap(Credencial credential) {
    if (_isSelectionMode) {
      setState(() {
        if (_selectedCredentialIds.contains(credential.id)) {
          _selectedCredentialIds.remove(credential.id);
        } else {
          _selectedCredentialIds.add(credential.id);
        }
      });
    } else {
      _showCredentialDetails(credential);
    }
  }

  void _selectAll() {
    setState(() {
      if (_selectedCredentialIds.length == _filteredCredentials.length) {
        _selectedCredentialIds.clear();
      } else {
        _selectedCredentialIds.addAll(_filteredCredentials.map((c) => c.id));
      }
    });
  }

  Future<void> _deleteSelected() async {
    final count = _selectedCredentialIds.length;
    if (count == 0) return;

    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text('Eliminar $count Credenciales'),
        content: const Text('Esta acción no se puede deshacer. ¿Estás seguro?'),
        actions: [
          TextButton(onPressed: () => Navigator.of(context).pop(false), child: const Text('Cancelar')),
          TextButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Eliminar'),
            style: TextButton.styleFrom(foregroundColor: Theme.of(context).colorScheme.error),
          ),
        ],
      ),
    );

    if (confirm == true) {
      setState(() {
        _credentials.removeWhere((c) => _selectedCredentialIds.contains(c.id));
        _toggleSelectionMode();
      });
      _sortAndFilterCredentials();
      await _saveChanges();
      _showSnackbar('$count credenciales eliminadas.');
    }
  }

  AppBar _buildDefaultAppBar() {
    return AppBar(
      title: const Text('Mi Bóveda'),
      actions: [
        if (_credentials.isNotEmpty)
          IconButton(
            icon: const Icon(Icons.checklist_rtl),
            tooltip: 'Seleccionar múltiples',
            onPressed: () => _toggleSelectionMode(),
          ),
        PopupMenuButton<SortOption>(
          icon: const Icon(Icons.sort),
          tooltip: 'Ordenar',
          onSelected: (SortOption result) {
            setState(() {
              _currentSortOption = result;
              AppSettingsService.saveSortOption(result); // <<< MEJORA: Guardar preferencia
              _sortAndFilterCredentials();
            });
          },
          // <<< MEJORA: Usar CheckedPopupMenuItem para mostrar la selección actual >>>
          itemBuilder: (BuildContext context) => <PopupMenuEntry<SortOption>>[
            CheckedPopupMenuItem<SortOption>(
              value: SortOption.nameAsc,
              checked: _currentSortOption == SortOption.nameAsc,
              child: const Text('Nombre (A-Z)'),
            ),
            CheckedPopupMenuItem<SortOption>(
              value: SortOption.nameDesc,
              checked: _currentSortOption == SortOption.nameDesc,
              child: const Text('Nombre (Z-A)'),
            ),
             CheckedPopupMenuItem<SortOption>(
              value: SortOption.dateDesc,
              checked: _currentSortOption == SortOption.dateDesc,
              child: const Text('Fecha (Más recientes)'),
            ),
             CheckedPopupMenuItem<SortOption>(
              value: SortOption.dateAsc,
              checked: _currentSortOption == SortOption.dateAsc,
              child: const Text('Fecha (Más antiguos)'),
            ),
          ],
        ),
        PopupMenuButton<String>(
          onSelected: (value) {
            if (value == 'import') _importCredentials();
            if (value == 'export') _exportCredentials();
            if (value == 'settings') {
              Navigator.of(context).push(MaterialPageRoute(builder: (context) => const SettingsScreen()));
            }
          },
          itemBuilder: (BuildContext context) => <PopupMenuEntry<String>>[
            const PopupMenuItem<String>(
              value: 'import',
              child: ListTile(
                leading: Icon(Icons.upload_file), 
                title: Text('Importar archivo'),
                contentPadding: EdgeInsets.zero
              ),
            ),
            const PopupMenuItem<String>(
              value: 'export',
              child: ListTile(
                // CAMBIO AQUÍ: Icono de tabla y texto Excel
                leading: Icon(Icons.table_view, color: Colors.green), 
                title: Text('Exportar a Excel (.xlsx)'),
                contentPadding: EdgeInsets.zero
              ),
            ),
            const PopupMenuDivider(),
            const PopupMenuItem<String>(
              value: 'settings',
              child: ListTile(
                leading: Icon(Icons.settings), 
                title: Text('Ajustes'),
                contentPadding: EdgeInsets.zero
              ),
            ),
          ],
        ),
      ],
      bottom: PreferredSize(
        preferredSize: const Size.fromHeight(kToolbarHeight),
        child: Padding(
          padding: const EdgeInsets.all(8.0),
          child: TextField(
            controller: _searchController,
            decoration: InputDecoration(
              hintText: 'Buscar...',
              prefixIcon: const Icon(Icons.search),
              suffixIcon: _showClearButton
                  ? IconButton(
                      icon: const Icon(Icons.clear),
                      onPressed: () {
                        _searchController.clear();
                      },
                    )
                  : null,
              border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: BorderSide.none),
              filled: true,
              contentPadding: EdgeInsets.zero,
            ),
          ),
        ),
      ),
    );
  }

  AppBar _buildSelectionAppBar() {
    final allSelected = _selectedCredentialIds.length == _filteredCredentials.length;
    return AppBar(
      leading: IconButton(
        icon: const Icon(Icons.close),
        onPressed: _toggleSelectionMode,
      ),
      title: Text('${_selectedCredentialIds.length} seleccionados'),
      actions: [
        IconButton(
          icon: Icon(allSelected ? Icons.deselect : Icons.select_all),
          tooltip: allSelected ? 'Deseleccionar todo' : 'Seleccionar todo',
          onPressed: _selectAll,
        ),
        IconButton(
          icon: const Icon(Icons.delete_sweep_outlined),
          tooltip: 'Eliminar seleccionados',
          onPressed: _deleteSelected,
        ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: _isSelectionMode ? _buildSelectionAppBar() : _buildDefaultAppBar(),
      body: _filteredCredentials.isEmpty
          ? Center(
              child: Text(
                _credentials.isEmpty ? 'Tu bóveda está vacía.\nPresiona + para agregar una credencial.' : 'No se encontraron resultados.',
                textAlign: TextAlign.center,
              ),
            )
          : ListView.builder(
              itemCount: _filteredCredentials.length,
              itemBuilder: (context, index) {
                final credential = _filteredCredentials[index];
                final isSelected = _selectedCredentialIds.contains(credential.id);

                return ListTile(
                  onTap: () => _onItemTap(credential),
                  onLongPress: () {
                    if (!_isSelectionMode) {
                      _toggleSelectionMode(initialSelectionId: credential.id);
                    }
                  },
                  leading: _isSelectionMode
                      ? Checkbox(
                          value: isSelected,
                          onChanged: (bool? value) => _onItemTap(credential),
                        )
                      : const Icon(Icons.vpn_key_outlined),
                  title: Text(credential.nombre),
                  subtitle: Text(credential.email.isNotEmpty ? credential.email : credential.usuario),
                  trailing: _isSelectionMode
                      ? null
                      : Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            IconButton(icon: const Icon(Icons.edit_outlined), onPressed: () => _showCredentialForm(credential)),
                            IconButton(
                              icon: Icon(Icons.delete_outline, color: Theme.of(context).colorScheme.error),
                              onPressed: () {
                                 showDialog(
                                  context: context,
                                  builder: (ctx) => AlertDialog(
                                    title: const Text('Confirmar Eliminación'),
                                    content: Text('¿Estás seguro de que quieres eliminar "${credential.nombre}"?'),
                                    actions: [
                                      TextButton(onPressed: () => Navigator.of(ctx).pop(), child: const Text('Cancelar')),
                                      TextButton(
                                        onPressed: () {
                                          _deleteSelectedSingle(credential.id);
                                          Navigator.of(ctx).pop();
                                        },
                                        child: const Text('Eliminar'),
                                        style: TextButton.styleFrom(foregroundColor: Theme.of(context).colorScheme.error),
                                      ),
                                    ],
                                  ),
                                );
                              },
                            ),
                          ],
                        ),
                );
              },
            ),
      floatingActionButton: _isSelectionMode
          ? null
          : FloatingActionButton(
              onPressed: () => _showCredentialForm(),
              tooltip: 'Agregar Credencial',
              child: const Icon(Icons.add),
            ),
    );
  }
  
  void _deleteSelectedSingle(String id) {
    setState(() {
      _credentials.removeWhere((c) => c.id == id);
    });
    _sortAndFilterCredentials();
    _saveChanges();
    _showSnackbar('Credencial eliminada.');
  }
}

class CredentialFormScreen extends StatefulWidget {
  final Credencial? credential;
  final Function(Credencial) onSave;
  const CredentialFormScreen({Key? key, this.credential, required this.onSave}) : super(key: key);
  @override
  _CredentialFormScreenState createState() => _CredentialFormScreenState();
}

class _CredentialFormScreenState extends State<CredentialFormScreen> {
  final _formKey = GlobalKey<FormState>();
  late TextEditingController _nombreController;
  late TextEditingController _emailController;
  late TextEditingController _usuarioController;
  late TextEditingController _contrasenaController;
  late TextEditingController _telefonoController;
  late TextEditingController _notasController;
  bool _isNew = true;
  bool _obscurePassword = true;

  List<CustomField> _customFields = [];
  List<TextEditingController> _customFieldNameControllers = [];
  List<TextEditingController> _customFieldValueControllers = [];

  @override
  void initState() {
    super.initState();
    _isNew = widget.credential == null;
    _nombreController = TextEditingController(text: widget.credential?.nombre ?? '');
    _emailController = TextEditingController(text: widget.credential?.email ?? '');
    _usuarioController = TextEditingController(text: widget.credential?.usuario ?? '');
    _contrasenaController = TextEditingController(text: widget.credential?.contrasena ?? '');
    _telefonoController = TextEditingController(text: widget.credential?.numeroTelefono ?? '');
    _notasController = TextEditingController(text: widget.credential?.notas ?? '');
    
    if (widget.credential?.customFields != null) {
      _customFields = List.from(widget.credential!.customFields.map((cf) => CustomField(name: cf.name, value: cf.value)));
      for (var field in _customFields) {
        _customFieldNameControllers.add(TextEditingController(text: field.name));
        _customFieldValueControllers.add(TextEditingController(text: field.value));
      }
    }
  }

  @override
  void dispose() {
    _nombreController.dispose();
    _emailController.dispose();
    _usuarioController.dispose();
    _contrasenaController.dispose();
    _telefonoController.dispose();
    _notasController.dispose();
    for (var controller in _customFieldNameControllers) {
      controller.dispose();
    }
    for (var controller in _customFieldValueControllers) {
      controller.dispose();
    }
    super.dispose();
  }

  void _addCustomField() {
    setState(() {
      _customFields.add(CustomField());
      _customFieldNameControllers.add(TextEditingController());
      _customFieldValueControllers.add(TextEditingController());
    });
  }

  void _removeCustomField(int index) {
    setState(() {
      _customFields.removeAt(index);
      _customFieldNameControllers[index].dispose();
      _customFieldValueControllers[index].dispose();
      _customFieldNameControllers.removeAt(index);
      _customFieldValueControllers.removeAt(index);
    });
  }

  void _saveForm() {
    if (_formKey.currentState!.validate()) {
      for (int i = 0; i < _customFields.length; i++) {
        _customFields[i].name = _customFieldNameControllers[i].text;
        _customFields[i].value = _customFieldValueControllers[i].text;
      }

      final newCredential = Credencial(
        id: widget.credential?.id ?? DateTime.now().millisecondsSinceEpoch.toString(),
        nombre: _nombreController.text,
        email: _emailController.text,
        usuario: _usuarioController.text,
        contrasena: _contrasenaController.text,
        numeroTelefono: _telefonoController.text,
        notas: _notasController.text,
        fechaModificacion: DateTime.now(),
        customFields: _customFields.where((cf) => cf.name.isNotEmpty).toList(),
      );
      widget.onSave(newCredential);
      Navigator.of(context).pop();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(_isNew ? 'Nueva Credencial' : 'Editar Credencial'),
        actions: [IconButton(icon: const Icon(Icons.save), onPressed: _saveForm)],
      ),
      body: Form(
        key: _formKey,
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              TextFormField(
                controller: _nombreController,
                decoration: const InputDecoration(labelText: 'Nombre (ej: Google, Facebook)'),
                validator: (value) => (value?.isEmpty ?? true) ? 'El nombre es obligatorio' : null,
              ),
              const SizedBox(height: 16),
              TextFormField(controller: _emailController, decoration: const InputDecoration(labelText: 'Email'), keyboardType: TextInputType.emailAddress),
              const SizedBox(height: 16),
              TextFormField(controller: _usuarioController, decoration: const InputDecoration(labelText: 'Usuario')),
              const SizedBox(height: 16),
              TextFormField(
                controller: _contrasenaController,
                obscureText: _obscurePassword,
                decoration: InputDecoration(
                  labelText: 'Contraseña',
                  suffixIcon: IconButton(
                    icon: Icon(_obscurePassword ? Icons.visibility_off : Icons.visibility),
                    onPressed: () => setState(() => _obscurePassword = !_obscurePassword),
                  ),
                ),
              ),
              const SizedBox(height: 16),
              TextFormField(controller: _telefonoController, decoration: const InputDecoration(labelText: 'Número de Teléfono'), keyboardType: TextInputType.phone),
              const SizedBox(height: 16),
              TextFormField(controller: _notasController, decoration: const InputDecoration(labelText: 'Notas', alignLabelWithHint: true), maxLines: 4),
              const Divider(height: 40),
              ..._buildCustomFields(),
              const SizedBox(height: 16),
              TextButton.icon(
                icon: const Icon(Icons.add),
                label: const Text('Añadir campo personalizado'),
                onPressed: _addCustomField,
              ),
              const SizedBox(height: 24),
              ElevatedButton(onPressed: _saveForm, child: const Text('Guardar')),
            ],
          ),
        ),
      ),
    );
  }

  List<Widget> _buildCustomFields() {
    List<Widget> fields = [];
    for (int i = 0; i < _customFields.length; i++) {
      fields.add(
        Row(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            Expanded(
              flex: 2,
              child: TextFormField(
                controller: _customFieldNameControllers[i],
                decoration: const InputDecoration(labelText: 'Nombre del Campo'),
              ),
            ),
            const SizedBox(width: 16),
            Expanded(
              flex: 3,
              child: TextFormField(
                controller: _customFieldValueControllers[i],
                decoration: const InputDecoration(labelText: 'Valor'),
              ),
            ),
            IconButton(
              icon: const Icon(Icons.remove_circle_outline),
              onPressed: () => _removeCustomField(i),
            ),
          ],
        ),
      );
      fields.add(const SizedBox(height: 16));
    }
    return fields;
  }
}

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Ajustes'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Consumer<ThemeNotifier>(
          builder: (context, themeNotifier, child) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Tema de la Aplicación', style: Theme.of(context).textTheme.titleLarge),
                RadioListTile<ThemeMode>(
                  title: const Text('Claro'),
                  value: ThemeMode.light,
                  groupValue: themeNotifier.themeMode,
                  onChanged: (ThemeMode? value) {
                    if (value != null) themeNotifier.setTheme(value);
                  },
                ),
                RadioListTile<ThemeMode>(
                  title: const Text('Oscuro'),
                  value: ThemeMode.dark,
                  groupValue: themeNotifier.themeMode,
                  onChanged: (ThemeMode? value) {
                     if (value != null) themeNotifier.setTheme(value);
                  },
                ),
                RadioListTile<ThemeMode>(
                  title: const Text('Seguir configuración del sistema'),
                  value: ThemeMode.system,
                  groupValue: themeNotifier.themeMode,
                  onChanged: (ThemeMode? value) {
                     if (value != null) themeNotifier.setTheme(value);
                  },
                ),
              ],
            );
          },
        ),
      ),
    );
  }
}
