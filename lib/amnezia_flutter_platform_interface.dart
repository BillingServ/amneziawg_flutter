abstract class AmneziaFlutterPlatformInterface {
  Stream<VpnStage> get vpnStageSnapshot;

  Future<void> initialize({required String interfaceName, String? providerBundleIdentifier});

  /// [onDemand] and [includeAllNetworks] apply on Apple platforms only: the
  /// system keeps the tunnel up and restarts it whenever it drops, and sends
  /// all traffic but the local network's through the tunnel, blocking it
  /// whenever the tunnel isn't passing traffic.
  Future<void> startVpn({
    required String serverAddress,
    required String wgQuickConfig,
    required String providerBundleIdentifier,
    bool onDemand = false,
    bool includeAllNetworks = false,
  });

  Future<void> stopVpn();

  Future<void> refreshStage();
  Future<VpnStage> stage();
  Future<bool> isConnected() =>
      stage().then((stage) => stage == VpnStage.connected);
}

enum VpnStage {
  connected('connected'),
  connecting('connecting'),
  disconnecting('disconnecting'),
  disconnected('disconnected'),
  waitingConnection('wait_connection'),
  authenticating('authenticating'),
  reconnect('reconnect'),
  noConnection('no_connection'),
  preparing('prepare'),
  denied('denied'),
  exiting('exiting');

  final String code;

  const VpnStage(this.code);
}
