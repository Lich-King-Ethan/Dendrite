# Dendrite

Ultra lightweight SlimeVR → VMT → PSMSx tracker forwarder.  
It do the beep boop.

## Ports (DON’T TOUCH THESE)

- SlimeVR OSC Out → `127.0.0.1:9002`
- Dendrite listens on → `9002`
- Dendrite → VMT OSC → `127.0.0.1:39570`

## Setup

1. In **SlimeVR Server**:
   - OSC target IP: `127.0.0.1`
   - OSC target port: `9002`

2. Run **Dendrite.exe** once:
   - It creates `dendrite.vrmanifest`
   - Tries to register itself with SteamVR

3. In **SteamVR**:
   - Settings → Startup / Shutdown
   - Find **Dendrite** and toggle it **on**

After that, SteamVR will auto-start Dendrite for you.
