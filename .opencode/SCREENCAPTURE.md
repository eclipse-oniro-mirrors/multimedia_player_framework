# Screen Capture Code Architecture Analysis

## Overall Layered Architecture

```
┌──────────────────────────────────────────────────┐
│ Application Layer (C++ API / C API / JS NAPI)     │
├──────────────────────────────────────────────────┤
│ Framework Layer                                    │
│  ScreenCaptureImpl / ScreenCaptureControllerImpl  │
│  ScreenCaptureMonitorImpl                         │
├─────────────────── IPC Boundary ──────────────────┤
│ Client → Proxy ← Binder → Stub → Server          │
├──────────────────────────────────────────────────┤
│ Server Layer                                       │
│  ScreenCaptureServer + ScreenCaptureMonitorServer │
│  + Observer (InCallObserver, AccountObserver)     │
└──────────────────────────────────────────────────┤
│ System Services (Audio, Display, Window, Telephony│
└──────────────────────────────────────────────────┘
```

## Subsystem Overview

| Subsystem | API Layer | Framework Layer | Server Layer | IPC Channels | Purpose |
|-----------|----------|----------------|-------------|-------------|---------|
| ScreenCapture | `ScreenCapture` (Factory) | `ScreenCaptureImpl` | `ScreenCaptureServer` | 2 (service+callback) | Screen capture core |
| ScreenCaptureMonitor | `ScreenCaptureMonitor` (Singleton) | `ScreenCaptureMonitorImpl` | `ScreenCaptureMonitorServer` (Singleton) | 2 (service+callback) | Capture state monitoring |
| ScreenCaptureController | `ScreenCaptureController` (Factory) | `ScreenCaptureControllerImpl` (Ephemeral Client) | `ScreenCaptureControllerServer` | 1 (service) | Picker control channel |
| Observer | — | — | `InCallObserver` / `AccountObserver` (Singleton) | — (in-process) | System event observation |

## IPC Channels

Each subsystem follows the standard OpenHarmony C/S IPC pattern:

```
Client Process:  Impl → IXxxService → Client(wraps Proxy) → XxxServiceProxy
                                                                  │
                               Binder IPC ←──────────────────────┘
                                                                  │
Server Process:                                             XxxServiceStub → Server
```

Reverse callback (Server→Client) uses ListenerStub created by the client, passing IRemoteObject to the server:

```
Server Process:  Server → Callback Adapter → ListenerProxy
                                              │
                      Binder IPC ←───────────┘
                                              │
Client Process:                           ListenerStub → User Callback
```

5 IPC channels:

| Channel | Direction | Interface | Message Codes |
|---------|----------|-----------|--------------|
| ScreenCaptureService | Client→Server | `IStandardScreenCaptureService` | 39 |
| ScreenCaptureListener | Server→Client | `IStandardScreenCaptureListener` | 8 |
| ScreenCaptureController | Client→Server | `IStandardScreenCaptureController` | 3 |
| ScreenCaptureMonitorService | Client→Server | `IStandardScreenCaptureMonitorService` | 6 |
| ScreenCaptureMonitorListener | Server→Client | `IStandardScreenCaptureMonitorListener` | 3 |

## Inter-Subsystem Relationships

### ScreenCapture → ScreenCaptureMonitor

Direct in-process connection (no IPC). ScreenCaptureServer calls MonitorServer directly on start/stop:

```
ScreenCaptureServer::PostStartScreenCaptureSuccessAction()
  → ScreenCaptureMonitorServer::CallOnScreenCaptureStarted(pid)
  → iterate listener set → IPC callback to each Client

IsScreenCaptureWorking()
  → ScreenCaptureServer::GetRunningScreenCaptureInstancePid() (query static data)
```

### ScreenCapture → ScreenCaptureController

Direct in-process connection. ControllerServer looks up server instance by sessionId in ScreenCaptureServer::serverMap_:

```
ScreenCaptureControllerServer::ReportAVScreenCaptureUserChoice(sessionId, choice)
  → ScreenCaptureServer::GetScreenCaptureServerById(sessionId)
  → call instance method
```

### Observer → ScreenCaptureServer

Bridged via `ScreenCaptureObserverCallBack` (in-process, async TaskQueue forwarding):

```
InCallObserver  ──→ ScreenCaptureObserverCallBack ──→ TaskQueue ──→ ScreenCaptureServer
AccountObserver ──→ ScreenCaptureObserverCallBack ──→ TaskQueue ──→ ScreenCaptureServer
```

`ScreenCaptureObserverCallBack` inherits both `InCallObserverCallBack` + `AccountObserverCallBack` (ifdef SUPPORT_CALL), holds `weak_ptr<ScreenCaptureServer>`.

### ScreenCaptureServer Internal Event Listeners

Registered directly with system services, callback to self:

| Listener Class | Registered With | Event |
|---------------|----------------|-------|
| `SCWindowLifecycleListener` | SessionManagerLite | Window/App lifecycle |
| `SCWindowInfoChangedListener` | WindowManager | Window info change |
| `PrivateWindowListenerInScreenCapture` | DisplayManager | Private window |
| `SCRecordDisplayListener` | ScreenManager | Display record change |
| `ScreenConnectListenerForSC` | ScreenManager | Screen connect/disconnect |
| `ScreenCaptureSubscriber` | CommonEventManager | Language switch |
| `ScreenRendererAudioStateChangeCallback` | AudioStreamManager | Audio renderer state |

## ScreenCaptureServer Core Architecture

```
ScreenCaptureServer
  │
  ├─ State Machine: AVScreenCaptureState
  │   CREATED → POPUP_WINDOW → STARTING → STARTED → PAUSED/RESUMED → STOPPED
  │
  ├─ Global Static Data (shared across instances)
  │   serverMap_: sessionId → weak_ptr<Server>
  │   startedSessionIDList_: started session ID list
  │   systemScreenRecorderPid_: system recorder PID
  │   gIdGenerator_: session ID generator (limits concurrency)
  │
  ├─ Audio Capture
  │   innerAudioCapture_ (AudioCapturerWrapper) ─ inner audio
  │   micAudioCapture_  (MicAudioCapturerWrapper) ─ microphone
  │   audioSource_      (AudioDataSource) ─ mix data source (MIX/MIC/INNER)
  │
  ├─ Video Capture
  │   consumer_ / producerSurface_ ─ Surface
  │   ScreenCapBufferConsumerListener ─ video frame consumer
  │   virtualScreenId_ ─ virtual screen ID
  │
  ├─ Recording (CAPTURE_FILE mode)
  │   recorder_ (IRecorderService) ─ recorder
  │
  ├─ Privacy/Picker
  │   connection_ (UIExtensionAbilityConnection) ─ UI dialog connection
  │
  ├─ Observer Bridge
  │   screenCaptureObserverCb_ (ScreenCaptureObserverCallBack)
  │
  └─ DI
     providers_ (ExternalServiceProviders) ─ external service abstraction
```

## Observer Architecture

| Observer | Singleton | Monitors | Effect | Build Condition |
|----------|----------|---------|--------|----------------|
| `InCallObserver` | static | Call state (`MediaTelephonyListener`→`TelephonyObserverClient`) | Stop capture/mute mic during call | `support_screen_capture_stopbycall` |
| `AccountObserver` | static | Account switch (`AccountListener`→`OsAccountManager`) | Stop capture on account switch | `support_screen_capture` |

## Build Structure

All screen_capture/monitor/observer code is compiled into a single `media_service` shared library. IPC Proxy/Client code is compiled into the client library.

Conditional compilation: `SUPPORT_CALL` (call feature), `PC_STANDARD`/`SUPPORT_PICKER_PHONE_PAD` (picker platform), `UNSUPPORT_SCREEN_CAPTURE` (full no-op stub).

## Key Design Patterns

1. **Global Server Map** — sessionId→weak_ptr shared across instances; Monitor/Controller access in-process without IPC
2. **State Machine** — AVScreenCaptureState controls lifecycle, prevents invalid operations
3. **DI** — `ExternalServiceProviders` abstracts external system services, supports test mocking
4. **Reverse IPC Callback** — ListenerCallback adapter bridges abstract callback→IPC Proxy
5. **Ephemeral Client** — Controller creates/destroys temporary Client per call for short-lived operations
6. **Observer+TaskQueue** — Async forwarding of system events to Server, avoids Observer thread blocking

## Key Paths

| Path | Purpose |
|------|---------|
| `interfaces/inner_api/native/` | ScreenCapture/Controller/Monitor public C++ API |
| `services/include/` | IScreenCaptureService/Controller/MonitorService abstract interfaces |
| `frameworks/native/screen_capture/` | Client Impl |
| `services/services/screen_capture/client/` | IPC Client |
| `services/services/screen_capture/ipc/` | IPC Proxy/Stub/Interface |
| `services/services/screen_capture/server/` | Server core |
| `services/services/screen_capture_monitor/` | Monitor service (client/ipc/server) |
| `services/services/observer/` | InCallObserver, AccountObserver |