import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:path_provider/path_provider.dart';

import '../amnezia_flutter_platform_interface.dart';

typedef LinuxProcessStarter = Future<Process> Function(
  String executable,
  List<String> arguments,
);

class AmneziaFlutterLinux extends AmneziaFlutterPlatformInterface {
  AmneziaFlutterLinux({
    LinuxProcessStarter? processStarter,
    Future<Directory> Function()? temporaryDirectory,
    this.commandTimeout = const Duration(seconds: 10),
  }) : _processStarter = processStarter ?? _startProcess,
       _temporaryDirectory = temporaryDirectory ?? getTemporaryDirectory;

  static Future<Process> _startProcess(String executable, List<String> args) =>
      Process.start(executable, args, runInShell: false);

  final LinuxProcessStarter _processStarter;
  final Future<Directory> Function() _temporaryDirectory;
  final Duration commandTimeout;
  String? name;
  File? configFile;
  int _generation = 0;
  int _lastStartGeneration = 0;
  Process? _startingProcess;
  Future<void>? _startInFlight;
  Future<void>? _stopInFlight;
  VpnStage _stage = VpnStage.noConnection;
  final _stageController = StreamController<VpnStage>.broadcast();

  void _setStage(VpnStage stage) {
    if (_stage == stage) return;
    _stage = stage;
    _stageController.add(stage);
  }

  @override
  Future<void> initialize({
    required String interfaceName,
    String? providerBundleIdentifier,
  }) async {
    final normalized = interfaceName.replaceAll(' ', '_');
    if (!RegExp(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$').hasMatch(normalized)) {
      throw ArgumentError.value(
        interfaceName,
        'interfaceName',
        'Expected a Linux interface name of at most 15 characters',
      );
    }
    if (_startInFlight != null || _stopInFlight != null) {
      throw StateError('A VPN operation is in progress');
    }
    name = normalized;
    await refreshStage();
  }

  Future<String> get filePath async {
    final interface = _interfaceName;
    final tempDir = await _temporaryDirectory().timeout(commandTimeout);
    return '${tempDir.path}${Platform.pathSeparator}$interface.conf';
  }

  String get _interfaceName =>
      name ?? (throw StateError('Initialize the VPN interface first'));

  @override
  Future<void> startVpn({
    required String serverAddress,
    required String wgQuickConfig,
    required String providerBundleIdentifier,
    bool onDemand = false,
    bool includeAllNetworks = false,
  }) {
    if (_stopInFlight != null) {
      return Future.error(StateError('VPN stop is in progress'));
    }
    final pending = _startInFlight;
    if (pending != null) return pending;
    final generation = ++_generation;
    _lastStartGeneration = generation;
    return _startInFlight = _start(
      wgQuickConfig,
      generation,
    ).whenComplete(() => _startInFlight = null);
  }

  void _checkCurrent(int generation) {
    if (generation != _generation) throw StateError('VPN start was cancelled');
  }

  Future<void> _start(String config, int generation) async {
    try {
      if (await isConnected()) return _setStage(VpnStage.connected);
      _checkCurrent(generation);
      _setStage(VpnStage.preparing);
      final path = await filePath;
      _checkCurrent(generation);
      configFile = File(path);
      await configFile!.writeAsString(config).timeout(commandTimeout);
      _checkCurrent(generation);
      _setStage(VpnStage.connecting);
      await _run(['awg-quick', 'up', path], startGeneration: generation);
      _checkCurrent(generation);
      if (!await isConnected()) {
        throw StateError('VPN interface did not become active');
      }
      _checkCurrent(generation);
      _setStage(VpnStage.connected);
    } catch (_) {
      if (generation == _generation) _setStage(VpnStage.denied);
      rethrow;
    }
  }

  @override
  Future<void> stopVpn() {
    return _stopInFlight ??= _stop().whenComplete(() => _stopInFlight = null);
  }

  Future<void> _stop() async {
    ++_generation;
    _setStage(VpnStage.disconnecting);
    _startingProcess?.kill();
    // Join the cancelled start before down, so it cannot recreate the
    // interface after this stop returns. Each process/IO step is bounded.
    try {
      await _startInFlight;
    } catch (_) {}
    try {
      if (await isConnected()) {
        final path = configFile?.path ?? await filePath;
        final target = await File(path).exists() ? path : _interfaceName;
        await _run(['awg-quick', 'down', target]);
      }
      await refreshStage();
      if (_stage == VpnStage.connected) {
        throw StateError('VPN interface is still active');
      }
    } catch (_) {
      await refreshStage();
      rethrow;
    }
  }

  @override
  Future<VpnStage> stage() async {
    await refreshStage();
    return _stage;
  }

  @override
  Stream<VpnStage> get vpnStageSnapshot => _stageController.stream;

  @override
  Future<void> refreshStage() async {
    if (name == null) return _setStage(VpnStage.waitingConnection);
    if (await isConnected()) return _setStage(VpnStage.connected);
    if (_startInFlight != null && _stage != VpnStage.connected) return;
    _setStage(
      configFile == null ? VpnStage.noConnection : VpnStage.disconnected,
    );
  }

  @override
  Future<bool> isConnected() async {
    final interface = _interfaceName;
    final result = await _run(['awg', 'show', 'interfaces']);
    return result.stdout.toString().split(RegExp(r'\s+')).contains(interface);
  }

  Future<ProcessResult> _run(
    List<String> arguments, {
    int? startGeneration,
  }) async {
    // No interactive password prompt and no shell parsing of paths or names.
    final args = ['-n', '--', ...arguments];
    var launchExpired = false;
    final launching = _processStarter('sudo', args);
    unawaited(
      launching.then<void>((process) {
        if (launchExpired) {
          unawaited(_cleanupLateProcess(process, startGeneration));
        }
      }, onError: (Object _, StackTrace __) {}),
    );
    final process = await launching.timeout(
      commandTimeout,
      onTimeout: () {
        launchExpired = true;
        throw TimeoutException('VPN command launch timed out', commandTimeout);
      },
    );
    final stdout = process.stdout.transform(utf8.decoder).join();
    final stderr = process.stderr.transform(utf8.decoder).join();
    if (startGeneration != null) {
      _startingProcess = process;
      if (startGeneration != _generation) process.kill();
    }
    try {
      final values =
          await Future.wait<Object>([process.exitCode, stdout, stderr]).timeout(
            commandTimeout,
            onTimeout: () {
              process.kill(ProcessSignal.sigkill);
              throw TimeoutException('VPN command timed out', commandTimeout);
            },
          );
      if (startGeneration != null) _checkCurrent(startGeneration);
      final result = ProcessResult(
        process.pid,
        values[0] as int,
        values[1] as String,
        values[2] as String,
      );
      if (result.exitCode != 0) {
        throw ProcessException('sudo', args, result.stderr, result.exitCode);
      }
      return result;
    } finally {
      if (identical(_startingProcess, process)) _startingProcess = null;
    }
  }

  Future<void> _cleanupLateProcess(Process process, int? generation) async {
    process.kill(ProcessSignal.sigkill);
    unawaited(process.stdout.drain<void>().catchError((Object _) {}));
    unawaited(process.stderr.drain<void>().catchError((Object _) {}));
    try {
      await process.exitCode.timeout(commandTimeout);
    } catch (_) {}
    if (generation == null) return;
    try {
      await _stopInFlight;
      // A later start owns its own interface; old cleanup must leave it alone.
      if (_lastStartGeneration == generation && _startInFlight == null) {
        await stopVpn();
      }
    } catch (_) {}
  }
}
