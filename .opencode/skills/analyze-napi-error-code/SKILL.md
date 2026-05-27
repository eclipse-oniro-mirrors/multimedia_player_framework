---
name: analyze-napi-error-code
description: Analyze what error codes can be returned by NAPI interfaces, tracing the complete call chain from application layer to system services, showing error code mapping and convergence across layers.
license: Apache-2.0
compatibility: opencode
metadata:
  audience: developers
  language: cpp
  framework: openharmony
---

## What I do

I analyze NAPI (JavaScript-to-C++ binding) interfaces to determine which error codes can actually be returned to JavaScript applications. I trace the complete call chain through all layers, showing how error codes are generated, transformed, and ultimately mapped to the final API9/API14 error codes exposed to JS.

## When to use me

Use this when you need to:
- Understand what error codes a specific NAPI interface can return
- Trace error code flow from service layer to JS layer
- Find out which internal errors are collapsed into which public error codes
- Debug why certain errors are not being surfaced properly
- Document error code behavior for API documentation
- Analyze error handling completeness in NAPI implementations

## Layered Architecture

```
┌──────────────────────────────────────────────────┐
│ Application Layer (C++ API / C API / JS NAPI)     │  ← Errors exposed to JS app
├──────────────────────────────────────────────────┤
│ Framework Layer                                    │  ← Impl handling, param validation
│  XxxImpl / XxxNapi                                 │
├─────────────────── IPC Boundary ──────────────────┤
│ Client → Proxy ← Binder → Stub → Server          │  ← IPC transport, error passthrough
├──────────────────────────────────────────────────┤
│ Server Layer                                       │  ← Business logic, state management
│  XxxServer + Observer                              │
└──────────────────────────────────────────────────┤
│ System Services (Audio, Display, Window, etc.)    │  ← Bottom layer returns raw errors
└──────────────────────────────────────────────────┘
```

### Layer Responsibilities

| Layer | Responsibility | Error Handling |
|-------|----------------|----------------|
| Application Layer | JS API entry, Promise encapsulation | Wrap `MSERR_EXT_API9_*` as BusinessError |
| Framework Layer | Parameter validation, state check, IPC call | Call `MSErrorToExtErrorAPI9()` to convert internal errors |
| IPC Boundary | Cross-process communication | Error codes passed as int32, no conversion |
| Server Layer | Business logic, resource management | Return `MSERR_*` internal error codes |
| System Services | Bottom-level functionality | Return subsystem errors (need conversion to `MSERR_*`) |

## Error Code Types

### Type 1: Subsystem Errors (Bottom Layer)
Raw errors from system services:
- Audio service errors → `AudioStandardErrorToMSError()` conversion
- HDI hardware errors → `HDIErrorToMSError()` conversion
- Display/Window service errors → Direct conversion to `MSERR_*`

**Definition**: `interfaces/inner_api/native/media_lpp_errors.h`

### Type 2: Service Layer Errors (Internal)
`MediaServiceErrCode` enum, ~80+ detailed errors:

| Category | Examples | Count |
|----------|----------|-------|
| Basic errors | `MSERR_OK`, `MSERR_NO_MEMORY`, `MSERR_UNKNOWN` | 5 |
| Parameter errors | `MSERR_INVALID_VAL`, `MSERR_MANDATORY_PARAMETER_UNSPECIFIED` | 4 |
| State errors | `MSERR_INVALID_OPERATION`, `MSERR_INVALID_STATE` | 2 |
| Support errors | `MSERR_UNSUPPORT_*` (format, codec, protocol, etc.) | 15 |
| IO errors | `MSERR_OPEN_FILE_FAILED`, `MSERR_IO_*` | 14 |
| Execution errors | `MSERR_*_FAILED` (encode, decode, start, etc.) | 12 |
| LPP errors | `MSERR_DSS_*`, `MSERR_SHB_*`, `MSERR_RS_*` | 15 |
| Others | DRM, super resolution, data source, etc. | 10+ |

**Definition**: `MSERRCODE_INFOS` in `frameworks/native/common/media_errors.cpp`

### Type 3: Application Layer Errors (Public)
`MediaServiceExtErrCodeAPI9` enum, ~20 public errors:

| Code Value | Name | Category | Convergence Source |
|------------|------|----------|-------------------|
| 0 | `MSERR_EXT_API9_OK` | Success | `MSERR_OK` |
| 201 | `MSERR_EXT_API9_NO_PERMISSION` | Permission | `MSERR_USER_NO_PERMISSION` |
| 202 | `MSERR_EXT_API9_PERMISSION_DENIED` | Permission | Picker permission denied |
| 401 | `MSERR_EXT_API9_INVALID_PARAMETER` | Parameter | 4 parameter errors collapsed |
| 801 | `MSERR_EXT_API9_UNSUPPORT_CAPABILITY` | Capability | `MSERR_UNSUPPORT_WATER_MARK` |
| 5400001 | `MSERR_EXT_API9_NO_MEMORY` | System | `MSERR_NO_MEMORY` and 2 others |
| 5400002 | `MSERR_EXT_API9_OPERATE_NOT_PERMIT` | Operation | State/operation errors collapsed |
| 5400003 | `MSERR_EXT_API9_IO` | IO | IO errors collapsed (15 types) |
| 5400004 | `MSERR_EXT_API9_TIMEOUT` | Network | `MSERR_NETWORK_TIMEOUT` |
| 5400005 | `MSERR_EXT_API9_SERVICE_DIED` | Service | `MSERR_SERVICE_DIED` |
| 5400006 | `MSERR_EXT_API9_UNSUPPORT_FORMAT` | Format | All UNSUPPORT_* collapsed (15 types) |
| 5400007 | `MSERR_EXT_API9_AUDIO_INTERRUPTED` | Audio | `MSERR_AUD_INTERRUPT` |
| 5400101 | `MSERR_EXT_API14_IO_CANNOT_FIND_HOST` | IO | `MSERR_IO_CANNOT_FIND_HOST` |
| 5400102 | `MSERR_EXT_API14_IO_CONNECTION_TIMEOUT` | IO | `MSERR_IO_CONNECTION_TIMEOUT` |
| 5400103 | `MSERR_EXT_API14_IO_NETWORK_ABNORMAL` | IO | `MSERR_IO_NETWORK_ABNORMAL` |
| 5400104 | `MSERR_EXT_API14_IO_NETWORK_UNAVAILABLE` | IO | `MSERR_IO_NETWORK_UNAVAILABLE` |
| 5400105 | `MSERR_EXT_API14_IO_NO_PERMISSION` | IO | `MSERR_IO_NO_PERMISSION` |
| 5400106 | `MSERR_EXT_API14_IO_NETWORK_ACCESS_DENIED` | IO | `MSERR_IO_NETWORK_ACCESS_DENIED` |
| 5400107 | `MSERR_EXT_API14_IO_RESOURE_NOT_FOUND` | IO | `MSERR_IO_RESOURE_NOT_FOUND` |
| 5400108 | `MSERR_EXT_API14_IO_SSL_CLIENT_CERT_NEEDED` | IO | `MSERR_IO_SSL_CLIENT_CERT_NEEDED` |
| 5400109 | `MSERR_EXT_API14_IO_SSL_CONNECT_FAIL` | IO | `MSERR_IO_SSL_CONNECT_FAIL` |
| 5400110 | `MSERR_EXT_API14_IO_SSL_SERVER_CERT_UNTRUSTED` | IO | `MSERR_IO_SSL_SERVER_CERT_UNTRUSTED` |
| 5400111 | `MSERR_EXT_API14_IO_UNSUPPORTTED_REQUEST` | IO | `MSERR_IO_UNSUPPORTTED_REQUEST` |
| 5400200 | `MSERR_EXT_API20_HARDWARE_FAILED` | Hardware | LPP hardware errors collapsed (12 types) |
| 5400201 | `MSERR_EXT_API20_PARAM_ERROR_OUT_OF_RANGE` | Parameter | `MSERR_PARAM_OUT_OF_RANGE` |

**Definition**: `MSEXTERRCODE_API9_INFOS` in `frameworks/native/common/media_errors.cpp`

## Error Code Flow Path

### Synchronous Call Path
```
JS Call → NAPI Entry
          ↓ Parameter validation (may return 401 directly)
          ↓ Call Impl
          ↓ IPC Client → Proxy
          ↓ Binder transport
          ↓ Stub → Server
          ↓ Business logic execution
          ↓ Return MSERR_*
          ↓ IPC passthrough back to Client
          ↓ Impl receives MSERR_*
          ↓ MSErrorToExtErrorAPI9() conversion
          ↓ Wrap BusinessError
JS receives error
```

### Async Callback Path
```
Server execution → Error encountered
                   ↓ OnError(errorCode)
                   ↓ ListenerStub → Binder
                   ↓ Proxy → Client
                   ↓ Callback Adapter
                   ↓ NAPI callback handling
                   ↓ MSErrorToExtErrorAPI9() conversion
                   ↓ Wrap BusinessError
JS receives on('error') callback
```

## Key Files

| File | Purpose |
|------|---------|
| `frameworks/native/common/media_errors.cpp` | Error code definitions, mapping tables, conversion functions |
| `interfaces/inner_api/native/media_errors.h` | Conversion function declarations |
| `interfaces/inner_api/native/media_lpp_errors.h` | Subsystem error conversion functions |
| `frameworks/js/common/common_napi.cpp` | NAPI error wrapping (`CreateError`) |
| `frameworks/js/avplayer/avplayer_napi.cpp` | AVPlayer NAPI implementation example |
| `services/services/player/server/player_server.cpp` | Service layer error return example |

## Core Conversion Functions

### MSErrorToExtErrorAPI9()
Converts internal `MSERR_*` to public `MSERR_EXT_API9_*`:

```cpp
// Defined in media_errors.cpp:498
MediaServiceExtErrCodeAPI9 MSErrorToExtErrorAPI9(MediaServiceErrCode code)
{
    if (MSERRCODE_INFOS.count(code) != 0 && MSERRCODE_TO_EXTERRORCODEAPI9.count(code) != 0) {
        return MSERRCODE_TO_EXTERRORCODEAPI9.at(code);
    }
    // Unmapped errors default to MSERR_EXT_API9_IO
    return MSERR_EXT_API9_IO;
}
```

### Subsystem Error Conversion
```cpp
// Defined in media_lpp_errors.h:63-67
MediaServiceErrCode AVCSErrorToMSError(int32_t code);           // AVCS errors
MediaServiceErrCode AudioStandardStatusToMSError(int32_t code); // Audio status
MediaServiceErrCode AudioStandardErrorToMSError(int32_t code);  // Audio errors
MediaServiceErrCode HDIStatusToMSError(int32_t code);           // HDI status
MediaServiceErrCode HDIErrorToMSError(int32_t code);            // HDI errors
```

## Analysis Workflow

### Step 1: Locate NAPI Entry
```
pattern: "JsXxx|napi_value.*Xxx"
path: "frameworks/js/<module>/"
include: "*.cpp"
```

### Step 2: Trace Impl Call
```
pattern: "XxxImpl|xxx_->"
path: "frameworks/native/<module>/src/"
include: "*.cpp"
```

### Step 3: Find Service Layer Implementation
```
pattern: "XxxServer::|return MSERR_"
path: "services/services/<module>/server/"
include: "*.cpp"
```

### Step 4: Check System Service Dependencies
```
pattern: "AudioCapturer|DisplayManager|WindowManager"
path: "services/services/<module>/"
include: "*.cpp"
```

### Step 5: Build Complete Mapping
1. Collect all `return MSERR_*` in service layer
2. Check if they exist in `MSERRCODE_TO_EXTERRORCODEAPI9` mapping table
3. Confirm the converted public error codes
4. Check if NAPI layer has direct returns (e.g., parameter validation)

## Convergence Analysis Examples

### Example: ScreenCapture.startRecording()

**Service layer possible returns** (screen_capture_server.cpp):
- `MSERR_INVALID_OPERATION` - Wrong state
- `MSERR_INVALID_VAL` - Invalid config
- `MSERR_UNSUPPORT` - Unsupported feature
- `MSERR_OPEN_FILE_FAILED` - File open failed
- `MSERR_NO_MEMORY` - Memory insufficient
- `MSERR_SERVICE_DIED` - Service died
- `MSERR_UNKNOWN` - Other unknown error

**After conversion JS receives**:
| Internal Error | Public Error Code | Value |
|----------------|-------------------|-------|
| `MSERR_INVALID_OPERATION` | `MSERR_EXT_API9_OPERATE_NOT_PERMIT` | 5400002 |
| `MSERR_INVALID_VAL` | `MSERR_EXT_API9_INVALID_PARAMETER` | 401 |
| `MSERR_UNSUPPORT` | `MSERR_EXT_API9_UNSUPPORT_FORMAT` | 5400006 |
| `MSERR_OPEN_FILE_FAILED` | `MSERR_EXT_API9_IO` | 5400003 |
| `MSERR_NO_MEMORY` | `MSERR_EXT_API9_NO_MEMORY` | 5400001 |
| `MSERR_SERVICE_DIED` | `MSERR_EXT_API9_SERVICE_DIED` | 5400005 |
| `MSERR_UNKNOWN` | `MSERR_EXT_API9_IO` | 5400003 |

**Convergence characteristics**:
- `MSERR_UNKNOWN` also collapses to `MSERR_EXT_API9_IO` (5400003)
- Multiple internal IO errors unified to `MSERR_EXT_API9_IO`

### Example: AVPlayer.prepare()

**Service layer possible returns** (player_server.cpp):
- `MSERR_INVALID_OPERATION` - Wrong state
- `MSERR_INVALID_STATE` - State error
- `MSERR_CREATE_PLAYER_ENGINE_FAILED` - Engine creation failed

**After conversion JS receives**:
| Internal Error | Public Error Code | Value |
|----------------|-------------------|-------|
| `MSERR_INVALID_OPERATION` | `MSERR_EXT_API9_OPERATE_NOT_PERMIT` | 5400002 |
| `MSERR_INVALID_STATE` | `MSERR_EXT_API9_OPERATE_NOT_PERMIT` | 5400002 |
| `MSERR_CREATE_PLAYER_ENGINE_FAILED` | `MSERR_EXT_API9_NO_MEMORY` | 5400001 |

**Convergence characteristics**:
- State errors unified to `OPERATE_NOT_PERMIT`
- Engine creation failure treated as memory issue

## NAPI Layer Direct Returns

Some errors are returned directly at NAPI layer, bypassing service layer:

### Parameter Validation Errors
```cpp
// avscreen_capture_napi.cpp:517
CHECK_AND_RETURN_RET_LOG(status == napi_ok,
    (asyncCtx->AVScreenCaptureSignError(MSERR_EXT_API9_INVALID_PARAMETER, ...));
```

### State Check Errors
```cpp
// avplayer_napi.cpp:422
if (state != STATE_INITIALIZED && state != STATE_STOPPED) {
    promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "...");
}
```

### Permission Errors
```cpp
// avscreen_capture_napi.cpp:322
ThrowCustomError(env, MSERR_EXT_API9_PERMISSION_DENIED, "permission denied");
```

## Search Patterns

Use the built-in grep tool for searching (no bash needed):

### Find NAPI Error Handling Points
```
pattern: "MSErrorToExtErrorAPI9|SignError|ThrowCustomError|CreateError"
path: "frameworks/js/"
include: "*.cpp"
```

### Find Service Layer Error Returns
```
pattern: "return MSERR_"
path: "services/services/"
include: "*.cpp"
```

### Find Error Callbacks
```
pattern: "OnError|ErrorCallback"
path: "services/services/"
include: "*.cpp"
```

### Find Subsystem Error Conversions
```
pattern: "ToMSError|StatusToMSError"
path: "frameworks/native/"
include: "*.cpp"
```

## Output Format

When analyzing an interface, I provide:

1. **Interface Summary**: Name, file location, purpose
2. **Call Chain**: Application→Framework→IPC→Server→System Services
3. **Service Layer Errors**: All possible `MSERR_*` return values
4. **Public Errors**: Complete list of converted `MSERR_EXT_API9_*`
5. **Convergence Analysis**: Internal→Public mapping table
6. **NAPI Direct Returns**: Parameter validation, state check and other early returns
7. **Async Errors**: Errors that may return through OnError callback

## Best Practices

1. Analyze in layer order: JS→NAPI→Impl→Server→System Services
2. Distinguish between sync returns and async callbacks as error sources
3. Note NAPI layer parameter validation may return errors directly
4. Check if service layer has subsystem integration errors needing conversion
5. Confirm all errors have mappings in `MSERRCODE_TO_EXTERRORCODEAPI9` table
6. Document API versions: API9 basic errors, API14 IO detailed errors, API20 hardware errors