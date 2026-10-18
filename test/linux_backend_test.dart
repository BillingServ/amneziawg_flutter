import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import '../lib/linux/amnezia_flutter_linux.dart';
import '../lib/amnezia_flutter_platform_interface.dart';

void main() {
  late Directory directory;
  late _Backend backend;
  late AmneziaFlutterLinux plugin;

  setUp(() async {
    directory = await Directory.systemTemp.createTemp('vpn linux path ');
    backend = _Backend();
    plugin = AmneziaFlutterLinux(
      processStarter: backend.start,
      temporaryDirectory: () async => directory,
      commandTimeout: const Duration(milliseconds: 100),
    );
  });
  tearDown(() => directory.delete(recursive: true));

  test('stage queries backend after external interface removal', () async {
    backend.up = true;
    await plugin.initialize(interfaceName: 'awg0');
    expect(await plugin.stage(), VpnStage.connected);
    backend.up = false;
    expect(await plugin.stage(), VpnStage.noConnection);
    expect(backend.commands.where((args) => args[2] == 'awg').length, 3);
  });

  test('backend query errors cannot return cached connected stage', () async {
    backend.up = true;
    await plugin.initialize(interfaceName: 'awg0');
    backend.queryExitCode = 1;
    await expectLater(plugin.stage(), throwsA(isA<ProcessException>()));
  });

  test(
    'paths with spaces remain one argv entry and sudo is noninteractive',
    () async {
      await plugin.initialize(interfaceName: 'awg0');
      await plugin.startVpn(
        serverAddress: 'example.invalid',
        wgQuickConfig: '[Interface]\nPrivateKey = fixture\n',
        providerBundleIdentifier: '',
      );
      final up = backend.commands.singleWhere((args) => args[3] == 'up');
      expect(up, [
        '-n',
        '--',
        'awg-quick',
        'up',
        '${directory.path}/awg0.conf',
      ]);
      expect(await plugin.stage(), VpnStage.connected);
      await plugin.stopVpn();
      expect(await plugin.stage(), VpnStage.disconnected);
      await plugin.stopVpn(); // A repeated stop is safe after external removal.
    },
  );

  test(
    'invalid interface names are rejected before executing anything',
    () async {
      await expectLater(
        plugin.initialize(interfaceName: 'awg0;touch bad'),
        throwsArgumentError,
      );
      await expectLater(
        plugin.initialize(interfaceName: '../awg0'),
        throwsArgumentError,
      );
      expect(backend.commands, isEmpty);
    },
  );

  test(
    'stop cancels a pending up and removes an interface already created',
    () async {
      await plugin.initialize(interfaceName: 'awg0');
      backend.holdUp = true;
      final starting = plugin.startVpn(
        serverAddress: 'example.invalid',
        wgQuickConfig: '[Interface]\n',
        providerBundleIdentifier: '',
      );
      final failedStart = expectLater(starting, throwsStateError);
      await backend.upEntered.future;
      await plugin.stopVpn();
      await failedStart;
      expect(backend.upProcess!.killed, true);
      expect(backend.commands.where((args) => args[3] == 'down'), hasLength(1));
      expect(await plugin.stage(), VpnStage.disconnected);
    },
  );

  test('stop during config preparation prevents any late up command', () async {
    final tempDirectory = Completer<Directory>();
    plugin = AmneziaFlutterLinux(
      processStarter: backend.start,
      temporaryDirectory: () => tempDirectory.future,
      commandTimeout: const Duration(milliseconds: 100),
    );
    await plugin.initialize(interfaceName: 'awg0');
    final starting = plugin.startVpn(
      serverAddress: 'example.invalid',
      wgQuickConfig: '[Interface]\n',
      providerBundleIdentifier: '',
    );
    final failedStart = expectLater(starting, throwsStateError);
    await Future<void>.delayed(Duration.zero);
    final stopping = plugin.stopVpn();
    tempDirectory.complete(directory);
    await stopping;
    await failedStart;
    expect(backend.commands.where((args) => args[3] == 'up'), isEmpty);
  });

  test('hung backend query times out and terminates its process', () async {
    await plugin.initialize(interfaceName: 'awg0');
    backend.holdQuery = true;
    await expectLater(plugin.stage(), throwsA(isA<TimeoutException>()));
    expect(backend.queryProcess!.killed, true);
  });

  test(
    'a process returned after launch timeout is killed and cleaned up',
    () async {
      await plugin.initialize(interfaceName: 'awg0');
      backend.upLaunchGate = Completer<Process>();
      await expectLater(
        plugin.startVpn(
          serverAddress: 'example.invalid',
          wgQuickConfig: '[Interface]\n',
          providerBundleIdentifier: '',
        ),
        throwsA(isA<TimeoutException>()),
      );
      await plugin.stopVpn();
      backend.up = true;
      final late = _Process(held: true);
      backend.upLaunchGate!.complete(late);
      final deadline = DateTime.now().add(const Duration(seconds: 1));
      while (backend.up && DateTime.now().isBefore(deadline)) {
        await Future<void>.delayed(const Duration(milliseconds: 5));
      }
      expect(late.killed, true);
      expect(backend.up, false);
    },
  );
}

class _Backend {
  bool up = false;
  bool holdUp = false;
  bool holdQuery = false;
  int queryExitCode = 0;
  final commands = <List<String>>[];
  final upEntered = Completer<void>();
  _Process? upProcess;
  _Process? queryProcess;
  Completer<Process>? upLaunchGate;

  Future<Process> start(String executable, List<String> args) async {
    expect(executable, 'sudo');
    expect(args.take(2), ['-n', '--']);
    commands.add(List.of(args));
    if (args[2] == 'awg') {
      expect(args.sublist(3), ['show', 'interfaces']);
      queryProcess = _Process(
        output: up ? 'awg0\n' : '',
        code: queryExitCode,
        held: holdQuery,
      );
      return queryProcess!;
    }
    expect(args[2], 'awg-quick');
    if (args[3] == 'up') {
      if (upLaunchGate != null) return upLaunchGate!.future;
      up = true;
      upProcess = _Process(held: holdUp);
      if (!upEntered.isCompleted) upEntered.complete();
      return upProcess!;
    }
    expect(args[3], 'down');
    up = false;
    return _Process();
  }
}

class _Process implements Process {
  _Process({String output = '', int code = 0, bool held = false})
    : stdout = Stream.value(utf8.encode(output)),
      stderr = Stream.value(<int>[]) {
    if (!held) completed.complete(code);
  }

  final completed = Completer<int>();
  bool killed = false;
  @override
  final Stream<List<int>> stdout;
  @override
  final Stream<List<int>> stderr;
  @override
  int get pid => 123;
  @override
  Future<int> get exitCode => completed.future;
  @override
  bool kill([ProcessSignal signal = ProcessSignal.sigterm]) {
    killed = true;
    if (!completed.isCompleted) completed.complete(143);
    return true;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}
