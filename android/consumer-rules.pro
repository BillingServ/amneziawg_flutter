# Rules applied to apps that depend on this plugin.
# AmneziaRuntime reads these private members by reflection to stop a tunnel that is owned
# by another backend instance in the same process. The amneziawg AAR only keeps
# AbstractBackend$VpnService and SocketProtector.
-keep class org.amnezia.awg.backend.** { *; }
-keep class org.amnezia.awg.config.** { *; }
-keep class org.amnezia.awg.crypto.** { *; }
-keep class billion.group.amnezia_flutter.** { *; }
