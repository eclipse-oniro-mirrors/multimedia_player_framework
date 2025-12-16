/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "screen_capture_service_stub.h"
#include "media_server_manager.h"
#include "media_log.h"
#include "media_errors.h"
#include "avsharedmemory_ipc.h"
#include "screen_capture_listener_proxy.h"

namespace {
constexpr int MAX_WINDOWS_LEN = 1000;
constexpr int MAX_FILTER_CONTENTS_COUNT = 1000;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureServiceStub"};
}

namespace OHOS {
namespace Media {
sptr<ScreenCaptureServiceStub> ScreenCaptureServiceStub::Create()
{
    sptr<ScreenCaptureServiceStub> screenCaptureStub = new(std::nothrow) ScreenCaptureServiceStub();
    CHECK_AND_RETURN_RET_LOG(screenCaptureStub != nullptr, nullptr, "failed to new ScreenCaptureServiceStub");

    int32_t ret = screenCaptureStub->Init();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed to screenCapture stub init");
    return screenCaptureStub;
}

ScreenCaptureServiceStub::ScreenCaptureServiceStub()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

ScreenCaptureServiceStub::~ScreenCaptureServiceStub()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t ScreenCaptureServiceStub::Init()
{
    screenCaptureServer_ = ScreenCaptureServer::Create();
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_NO_MEMORY,
        "failed to create ScreenCaptureServer Service");
    screenCaptureStubFuncs_[SET_LISTENER_OBJ] = &ScreenCaptureServiceStub::SetListenerObject;
    screenCaptureStubFuncs_[RELEASE] = &ScreenCaptureServiceStub::Release;
    screenCaptureStubFuncs_[SET_MIC_ENABLE] = &ScreenCaptureServiceStub::SetMicrophoneEnabled;
    screenCaptureStubFuncs_[SET_SCREEN_ROTATION] = &ScreenCaptureServiceStub::SetCanvasRotation;
    screenCaptureStubFuncs_[RESIZE_CANVAS] = &ScreenCaptureServiceStub::ResizeCanvas;
    screenCaptureStubFuncs_[SKIP_PRIVACY] = &ScreenCaptureServiceStub::SkipPrivacyMode;
    screenCaptureStubFuncs_[SET_MAX_FRAME_RATE] = &ScreenCaptureServiceStub::SetMaxVideoFrameRate;
    screenCaptureStubFuncs_[SET_CAPTURE_MODE] = &ScreenCaptureServiceStub::SetCaptureMode;
    screenCaptureStubFuncs_[SET_DATA_TYPE] = &ScreenCaptureServiceStub::SetDataType;
    screenCaptureStubFuncs_[SET_RECORDER_INFO] = &ScreenCaptureServiceStub::SetRecorderInfo;
    screenCaptureStubFuncs_[SET_OUTPUT_FILE] = &ScreenCaptureServiceStub::SetOutputFile;
    screenCaptureStubFuncs_[INIT_AUDIO_ENC_INFO] = &ScreenCaptureServiceStub::InitAudioEncInfo;
    screenCaptureStubFuncs_[INIT_AUDIO_CAP] = &ScreenCaptureServiceStub::InitAudioCap;
    screenCaptureStubFuncs_[INIT_VIDEO_ENC_INFO] = &ScreenCaptureServiceStub::InitVideoEncInfo;
    screenCaptureStubFuncs_[INIT_VIDEO_CAP] = &ScreenCaptureServiceStub::InitVideoCap;
    screenCaptureStubFuncs_[START_SCREEN_CAPTURE] = &ScreenCaptureServiceStub::StartScreenCapture;
    screenCaptureStubFuncs_[START_SCREEN_CAPTURE_WITH_SURFACE] =
        &ScreenCaptureServiceStub::StartScreenCaptureWithSurface;
    screenCaptureStubFuncs_[STOP_SCREEN_CAPTURE] = &ScreenCaptureServiceStub::StopScreenCapture;
    screenCaptureStubFuncs_[ACQUIRE_AUDIO_BUF] = &ScreenCaptureServiceStub::AcquireAudioBuffer;
    screenCaptureStubFuncs_[ACQUIRE_VIDEO_BUF] = &ScreenCaptureServiceStub::AcquireVideoBuffer;
    screenCaptureStubFuncs_[RELEASE_AUDIO_BUF] = &ScreenCaptureServiceStub::ReleaseAudioBuffer;
    screenCaptureStubFuncs_[RELEASE_VIDEO_BUF] = &ScreenCaptureServiceStub::ReleaseVideoBuffer;
    screenCaptureStubFuncs_[DESTROY] = &ScreenCaptureServiceStub::DestroyStub;
    screenCaptureStubFuncs_[EXCLUDE_CONTENT] = &ScreenCaptureServiceStub::ExcludeContent;
    screenCaptureStubFuncs_[INCLUDE_CONTENT] = &ScreenCaptureServiceStub::IncludeContent;
    screenCaptureStubFuncs_[EXCLUDE_PICKER_WINDOWS] = &ScreenCaptureServiceStub::ExcludePickerWindows;
    screenCaptureStubFuncs_[SET_PICKER_MODE] = &ScreenCaptureServiceStub::SetPickerMode;
    screenCaptureStubFuncs_[SHOW_CURSOR] = &ScreenCaptureServiceStub::ShowCursor;
    screenCaptureStubFuncs_[SET_CHECK_SA_LIMIT] = &ScreenCaptureServiceStub::SetAndCheckSaLimit;
    screenCaptureStubFuncs_[SET_CHECK_LIMIT] = &ScreenCaptureServiceStub::SetAndCheckLimit;
    screenCaptureStubFuncs_[SET_STRATEGY] = &ScreenCaptureServiceStub::SetScreenCaptureStrategy;
    screenCaptureStubFuncs_[UPDATE_SURFACE] = &ScreenCaptureServiceStub::UpdateSurface;
    screenCaptureStubFuncs_[SET_CAPTURE_AREA] = &ScreenCaptureServiceStub::SetCaptureArea;
    screenCaptureStubFuncs_[SET_HIGH_LIGHT_MODE] = &ScreenCaptureServiceStub::SetCaptureAreaHighlight;
    screenCaptureStubFuncs_[PRESENT_PICKER] = &ScreenCaptureServiceStub::PresentPicker;
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::DestroyStub()
{
    screenCaptureServer_ = nullptr;
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::SCREEN_CAPTURE, AsObject());
    return MSERR_OK;
}

int ScreenCaptureServiceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    MEDIA_LOGD("Stub: OnRemoteRequest of code: %{public}u is received", code);

    auto remoteDescriptor = data.ReadInterfaceToken();
    if (ScreenCaptureServiceStub::GetDescriptor() != remoteDescriptor) {
        MEDIA_LOGE("Invalid descriptor");
        return MSERR_INVALID_OPERATION;
    }

    auto itFunc = screenCaptureStubFuncs_.find(code);
    if (itFunc != screenCaptureStubFuncs_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            std::lock_guard<std::mutex> lock(mutex_);
            int32_t ret = (this->*memberFunc)(data, reply);
            if (ret != MSERR_OK) {
                MEDIA_LOGE("Calling memberFunc is failed.");
            }
            return MSERR_OK;
        }
    }
    MEDIA_LOGW("ScreenCaptureServiceStub: no member func supporting, applying default process");

    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t ScreenCaptureServiceStub::SetCaptureMode(CaptureMode captureMode)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->SetCaptureMode(captureMode);
}

int32_t ScreenCaptureServiceStub::SetDataType(DataType dataType)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->SetDataType(dataType);
}

int32_t ScreenCaptureServiceStub::SetRecorderInfo(RecorderInfo recorderInfo)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->SetRecorderInfo(recorderInfo);
}

int32_t ScreenCaptureServiceStub::SetOutputFile(int32_t fd)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->SetOutputFile(fd);
}

int32_t ScreenCaptureServiceStub::SetAndCheckLimit()
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->SetAndCheckLimit();
}

int32_t ScreenCaptureServiceStub::SetAndCheckSaLimit(OHOS::AudioStandard::AppInfo &appInfo)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->SetAndCheckSaLimit(appInfo);
}

int32_t ScreenCaptureServiceStub::InitAudioEncInfo(AudioEncInfo audioEncInfo)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->InitAudioEncInfo(audioEncInfo);
}

int32_t ScreenCaptureServiceStub::InitAudioCap(AudioCaptureInfo audioInfo)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->InitAudioCap(audioInfo);
}

int32_t ScreenCaptureServiceStub::InitVideoEncInfo(VideoEncInfo videoEncInfo)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->InitVideoEncInfo(videoEncInfo);
}

int32_t ScreenCaptureServiceStub::InitVideoCap(VideoCaptureInfo videoInfo)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->InitVideoCap(videoInfo);
}

int32_t ScreenCaptureServiceStub::StartScreenCapture(bool isPrivacyAuthorityEnabled)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->StartScreenCapture(isPrivacyAuthorityEnabled);
}

int32_t ScreenCaptureServiceStub::StartScreenCaptureWithSurface(sptr<Surface> surface, bool isPrivacyAuthorityEnabled)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");

    return screenCaptureServer_->StartScreenCaptureWithSurface(surface, isPrivacyAuthorityEnabled);
}

int32_t ScreenCaptureServiceStub::UpdateSurface(sptr<Surface> surface)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE, "screen capture server is nullptr");

    return screenCaptureServer_->UpdateSurface(surface);
}

int32_t ScreenCaptureServiceStub::StopScreenCapture()
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->StopScreenCapture();
}

int32_t ScreenCaptureServiceStub::PresentPicker()
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->PresentPicker();
}

int32_t ScreenCaptureServiceStub::SetListenerObject(const sptr<IRemoteObject> &object)
{
    CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "set listener object is nullptr");

    sptr<IStandardScreenCaptureListener> listener = iface_cast<IStandardScreenCaptureListener>(object);
    CHECK_AND_RETURN_RET_LOG(listener != nullptr, MSERR_NO_MEMORY, "failed to convert IStandardScreenCaptureListener");

    std::shared_ptr<ScreenCaptureCallBack> callback = std::make_shared<ScreenCaptureListenerCallback>(listener);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_NO_MEMORY, "failed to new ScreenCaptureCallBack");

    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_NO_MEMORY, "screen capture server is nullptr");
    (void)screenCaptureServer_->SetScreenCaptureCallback(callback);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::ExcludeContent(ScreenCaptureContentFilter &contentFilter)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->ExcludeContent(contentFilter);
}

int32_t ScreenCaptureServiceStub::IncludeContent(ScreenCaptureContentFilter &contentFilter)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->IncludeContent(contentFilter);
}

int32_t ScreenCaptureServiceStub::ExcludePickerWindows(std::vector<int32_t> &windowIDsVec)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->ExcludePickerWindows(windowIDsVec);
}

int32_t ScreenCaptureServiceStub::SetPickerMode(PickerMode pickerMode)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->SetPickerMode(pickerMode);
}

int32_t ScreenCaptureServiceStub::SetMicrophoneEnabled(bool isMicrophone)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->SetMicrophoneEnabled(isMicrophone);
}

int32_t ScreenCaptureServiceStub::SetCanvasRotation(bool canvasRotation)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
                             "screen capture server is nullptr");
    return screenCaptureServer_->SetCanvasRotation(canvasRotation);
}

int32_t ScreenCaptureServiceStub::ShowCursor(bool showCursor)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
                             "screen capture server is nullptr");
    return screenCaptureServer_->ShowCursor(showCursor);
}

int32_t ScreenCaptureServiceStub::ResizeCanvas(int32_t width, int32_t height)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
                             "screen capture server is nullptr");
    return screenCaptureServer_->ResizeCanvas(width, height);
}

int32_t ScreenCaptureServiceStub::SkipPrivacyMode(std::vector<uint64_t> &windowIDsVec)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
                             "screen capture server is nullptr");
    return screenCaptureServer_->SkipPrivacyMode(windowIDsVec);
}

int32_t ScreenCaptureServiceStub::SetMaxVideoFrameRate(int32_t frameRate)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
                             "screen capture server is nullptr");
    return screenCaptureServer_->SetMaxVideoFrameRate(frameRate);
}

int32_t ScreenCaptureServiceStub::AcquireAudioBuffer(std::shared_ptr<AudioBuffer> &audioBuffer,
                                                     AudioCaptureSourceType type)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->AcquireAudioBuffer(audioBuffer, type);
}

int32_t ScreenCaptureServiceStub::AcquireVideoBuffer(sptr<OHOS::SurfaceBuffer> &surfaceBuffer, int32_t &fence,
                                                     int64_t &timestamp, OHOS::Rect &damage)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->AcquireVideoBuffer(surfaceBuffer, fence, timestamp, damage);
}

int32_t ScreenCaptureServiceStub::ReleaseAudioBuffer(AudioCaptureSourceType type)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->ReleaseAudioBuffer(type);
}

int32_t ScreenCaptureServiceStub::ReleaseVideoBuffer()
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->ReleaseVideoBuffer();
}

int32_t ScreenCaptureServiceStub::SetScreenCaptureStrategy(ScreenCaptureStrategy strategy)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->SetScreenCaptureStrategy(strategy);
}

int32_t ScreenCaptureServiceStub::SetCaptureAreaHighlight(AVScreenCaptureHighlightConfig config)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->SetCaptureAreaHighlight(config);
}

int32_t ScreenCaptureServiceStub::SetCaptureArea(uint64_t displayId, OHOS::Rect area)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    return screenCaptureServer_->SetCaptureArea(displayId, area);
}

int32_t ScreenCaptureServiceStub::ExcludeContent(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    ScreenCaptureContentFilter contentFilter;
    int32_t size = data.ReadInt32();
    CHECK_AND_RETURN_RET_LOG(size < MAX_FILTER_CONTENTS_COUNT, MSERR_INVALID_STATE,
                             "content filter size is exceed max range");
    for (int32_t i = 0; i < size; i++) {
        contentFilter.filteredAudioContents.insert(
            static_cast<AVScreenCaptureFilterableAudioContent>(data.ReadInt32()));
    }
    int32_t windowIdSize = data.ReadInt32();
    CHECK_AND_RETURN_RET_LOG(windowIdSize < MAX_FILTER_CONTENTS_COUNT, MSERR_INVALID_STATE,
                             "windowID size is exceed max range");
    if (windowIdSize > 0) {
        std::vector<uint64_t> vec;
        for (int32_t i = 0; i < windowIdSize; i++) {
            vec.push_back(data.ReadUint64());
        }
        contentFilter.windowIDsVec = vec;
    }
    int32_t ret = ExcludeContent(contentFilter);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::IncludeContent(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    ScreenCaptureContentFilter contentFilter;
    int32_t windowIdSize = 0;
    uint64_t windowID = 0;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(windowIdSize), MSERR_INVALID_STATE, "failed to read data from MessageParcel");
    CHECK_AND_RETURN_RET_LOG(windowIdSize < MAX_FILTER_CONTENTS_COUNT, MSERR_INVALID_STATE,
                             "windowID size is exceed max range");
    if (windowIdSize > 0) {
        std::vector<uint64_t> vec;
        for (int32_t i = 0; i < windowIdSize; i++) {
            CHECK_AND_RETURN_RET_LOG(data.ReadUInt64(windowID), MSERR_INVALID_STATE,
                "failed to read data from MessageParcel");
            vec.push_back(windowID);
        }
        contentFilter.windowIDsVec = vec;
    }
    int32_t ret = IncludeContent(contentFilter);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::ExcludePickerWindows(MessageParcel &data, MessageParcel &reply)
{
    FALSE_RETURN_AND_REPLY(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE, "screen capture server is nullptr");
    std::vector<int32_t> windowIDsVec;
    uint64_t size = 0;
    int32_t windowID = 0;
    FALSE_RETURN_AND_REPLY(data.ReadUint64(size), MSERR_INVALID_STATE, "failed to read data from MessageParcel");
    FALSE_RETURN_AND_REPLY(size < MAX_WINDOWS_LEN, MSERR_INVALID_STATE, "windowID size is exceed max range");
    for (uint64_t i = 0; i < size; i++) {
        FALSE_RETURN_AND_REPLY(data.ReadInt32(windowID), MSERR_INVALID_STATE,
            "failed to read data from MessageParcel");
        windowIDsVec.push_back(windowID);
    }
    int32_t ret = ExcludePickerWindows(windowIDsVec);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::SetPickerMode(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    int32_t mode = 0;
    CHECK_AND_RETURN_RET_LOG(data.ReadInt32(mode), MSERR_INVALID_STATE, "failed to read data from MessageParcel");
    PickerMode pickerMode = static_cast<PickerMode>(mode);
    int32_t ret = SetPickerMode(pickerMode);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::SetMicrophoneEnabled(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    bool setMicEnable = data.ReadBool();
    int32_t ret = SetMicrophoneEnabled(setMicEnable);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::SetCanvasRotation(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
                             "screen capture server is nullptr");
    bool canvasRotation = data.ReadBool();
    int32_t ret = SetCanvasRotation(canvasRotation);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::ShowCursor(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
                             "screen capture server is nullptr");
    bool showCursor = data.ReadBool();
    int32_t ret = ShowCursor(showCursor);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::ResizeCanvas(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
                             "screen capture server is nullptr");
    int32_t width = data.ReadInt32();
    int32_t height = data.ReadInt32();
    int32_t ret = ResizeCanvas(width, height);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::SkipPrivacyMode(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
                             "screen capture server is nullptr");
    int32_t windowIdSize = data.ReadInt32();
    CHECK_AND_RETURN_RET_LOG(windowIdSize < MAX_FILTER_CONTENTS_COUNT, MSERR_INVALID_STATE,
                             "windowID size is exceed max range");
    if (windowIdSize >= 0) {
        std::vector<uint64_t> vec;
        for (int32_t i = 0; i < windowIdSize; i++) {
            vec.push_back(data.ReadUint64());
        }
        int32_t ret = SkipPrivacyMode(vec);
        reply.WriteInt32(ret);
    }
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::SetMaxVideoFrameRate(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
                             "screen capture server is nullptr");
    int32_t frameRate = data.ReadInt32();
    int32_t ret = SetMaxVideoFrameRate(frameRate);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::SetCaptureMode(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    CaptureMode mode = static_cast<CaptureMode>(data.ReadInt32());
    int32_t ret = SetCaptureMode(mode);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::SetDataType(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    DataType dataType = static_cast<DataType>(data.ReadInt32());
    int32_t ret = SetDataType(dataType);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::SetRecorderInfo(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    RecorderInfo recorderInfo;
    recorderInfo.url = data.ReadString();
    recorderInfo.fileFormat = data.ReadString();
    int32_t ret = SetRecorderInfo(recorderInfo);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::SetOutputFile(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    int32_t fd = data.ReadFileDescriptor();
    int32_t ret = SetOutputFile(fd);
    reply.WriteInt32(ret);
    CHECK_AND_RETURN_RET_LOG(fd >= 0, MSERR_INVALID_VAL, "fd is invalid, fd is %{public}d", fd);
    CHECK_AND_RETURN_RET_LOG(close(fd) == 0, MSERR_UNKNOWN, "close fd failed, fd is %{public}d", fd);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::SetAndCheckLimit(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    (void)data;
    int32_t ret = SetAndCheckLimit();
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::SetAndCheckSaLimit(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    OHOS::AudioStandard::AppInfo appInfo;
    appInfo.appUid = data.ReadInt32();
    appInfo.appPid = data.ReadInt32();
    appInfo.appTokenId = data.ReadUint32();
    appInfo.appFullTokenId = data.ReadUint64();
    int32_t ret = SetAndCheckSaLimit(appInfo);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::InitAudioEncInfo(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    AudioEncInfo audioEncInfo;
    audioEncInfo.audioBitrate = data.ReadInt32();
    audioEncInfo.audioCodecformat = static_cast<AudioCodecFormat>(data.ReadInt32());
    int32_t ret = InitAudioEncInfo(audioEncInfo);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::InitAudioCap(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    AudioCaptureInfo audioInfo;
    audioInfo.audioSampleRate = data.ReadInt32();
    audioInfo.audioChannels = data.ReadInt32();
    audioInfo.audioSource = static_cast<AudioCaptureSourceType>(data.ReadInt32());
    int32_t ret = InitAudioCap(audioInfo);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::InitVideoEncInfo(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    VideoEncInfo videoEncInfo;
    videoEncInfo.videoCodec = static_cast<VideoCodecFormat>(data.ReadInt32());
    videoEncInfo.videoBitrate = data.ReadInt32();
    videoEncInfo.videoFrameRate = data.ReadInt32();
    int32_t ret = InitVideoEncInfo(videoEncInfo);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::InitVideoCap(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    VideoCaptureInfo videoInfo;
    videoInfo.displayId = data.ReadUint64();
    videoInfo.taskIDs = {};
    int32_t size = data.ReadInt32();
    size = size >= MAX_WINDOWS_LEN ? MAX_WINDOWS_LEN : size;
    if (size > 0) {
        for (auto i = 0; i < size; i++) {
            int32_t missionId = data.ReadInt32();
            if (missionId >= 0) {
                videoInfo.taskIDs.push_back(missionId);
            }
        }
    }
    videoInfo.videoFrameWidth = data.ReadInt32();
    videoInfo.videoFrameHeight = data.ReadInt32();
    videoInfo.videoSource = static_cast<VideoSourceType>(data.ReadInt32());
    int32_t ret = InitVideoCap(videoInfo);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::StartScreenCapture(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    bool isPrivacyAuthorityEnabled = data.ReadBool();
    int32_t ret = StartScreenCapture(isPrivacyAuthorityEnabled);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::StartScreenCaptureWithSurface(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");

    sptr<IRemoteObject> object = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY,
        "ScreenCaptureServiceProxy StartScreenCaptureWithSurface object is nullptr");

    sptr<IBufferProducer> producer = iface_cast<IBufferProducer>(object);
    CHECK_AND_RETURN_RET_LOG(producer != nullptr, MSERR_NO_MEMORY, "failed to convert object to producer");

    sptr<Surface> surface = Surface::CreateSurfaceAsProducer(producer);
    CHECK_AND_RETURN_RET_LOG(surface != nullptr, MSERR_NO_MEMORY, "failed to create surface");

    bool isPrivacyAuthorityEnabled = data.ReadBool();
    int32_t ret = StartScreenCaptureWithSurface(surface, isPrivacyAuthorityEnabled);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::UpdateSurface(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE, "screen capture server is nullptr");

    sptr<IRemoteObject> object = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(
        object != nullptr, MSERR_NO_MEMORY, "ScreenCaptureServiceProxy UpdateSurface object is nullptr");

    sptr<IBufferProducer> producer = iface_cast<IBufferProducer>(object);
    CHECK_AND_RETURN_RET_LOG(producer != nullptr, MSERR_NO_MEMORY, "failed to convert object to producer");

    sptr<Surface> surface = Surface::CreateSurfaceAsProducer(producer);
    CHECK_AND_RETURN_RET_LOG(surface != nullptr, MSERR_NO_MEMORY, "failed to create surface");

    int32_t ret = UpdateSurface(surface);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::StopScreenCapture(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    (void)data;
    int32_t ret = StopScreenCapture();
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::PresentPicker(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    (void)data;
    int32_t ret = PresentPicker();
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::AcquireAudioBuffer(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    std::shared_ptr<AudioBuffer> audioBuffer;
    AudioCaptureSourceType type = static_cast<AudioCaptureSourceType>(data.ReadInt32());
    int32_t ret = AcquireAudioBuffer(audioBuffer, type);
    reply.WriteInt32(ret);
    if (ret == MSERR_OK) {
        reply.WriteInt32(audioBuffer->length);
        if ((audioBuffer->buffer != nullptr)&&(audioBuffer->length > 0)) {
            reply.WriteBuffer(audioBuffer->buffer, audioBuffer->length);
        }
        reply.WriteInt32(audioBuffer->sourcetype);
        reply.WriteInt64(audioBuffer->timestamp);
    }
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::AcquireVideoBuffer(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    (void)data;
    int32_t fence = -1; // init value start here
    int64_t timestamp = 0;
    OHOS::Rect damage;
    sptr<OHOS::SurfaceBuffer> videoBuffer = nullptr;
    int32_t ret = AcquireVideoBuffer(videoBuffer, fence, timestamp, damage);
    reply.WriteInt32(ret);
    if (ret == MSERR_OK) {
        if (videoBuffer != nullptr) {
            videoBuffer->WriteToMessageParcel(reply);
        }
        reply.WriteInt32(fence); // return to App client
        reply.WriteInt64(timestamp);
        reply.WriteInt32(damage.x);
        reply.WriteInt32(damage.y);
        reply.WriteInt32(damage.w);
        reply.WriteInt32(damage.h);
    }
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::ReleaseAudioBuffer(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    AudioCaptureSourceType type = static_cast<AudioCaptureSourceType>(data.ReadInt32());
    int32_t ret = ReleaseAudioBuffer(type);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::ReleaseVideoBuffer(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    (void)data;
    int32_t ret = ReleaseVideoBuffer();
    reply.WriteInt32(ret);
    return MSERR_OK;
}
int32_t ScreenCaptureServiceStub::SetListenerObject(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    reply.WriteInt32(SetListenerObject(object));
    return MSERR_OK;
}

void ScreenCaptureServiceStub::Release()
{
    CHECK_AND_RETURN_LOG(screenCaptureServer_ != nullptr, "screen capture server is nullptr");
    return screenCaptureServer_->Release();
}

int32_t ScreenCaptureServiceStub::Release(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    (void)reply;
    Release();
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::DestroyStub(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(DestroyStub());
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::SetCaptureAreaHighlight(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    AVScreenCaptureHighlightConfig config;
    config.lineThickness = data.ReadUint32();
    config.lineColor = data.ReadUint32();
    config.mode = static_cast<ScreenCaptureHighlightMode>(data.ReadInt32());
    int32_t ret = SetCaptureAreaHighlight(config);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::SetScreenCaptureStrategy(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    ScreenCaptureStrategy strategy;
    strategy.enableDeviceLevelCapture = data.ReadBool();
    strategy.keepCaptureDuringCall = data.ReadBool();
    strategy.strategyForPrivacyMaskMode = data.ReadInt32();
    strategy.canvasFollowRotation = data.ReadBool();
    strategy.enableBFrame = data.ReadBool();
    strategy.pickerPopUp = static_cast<AVScreenCapturePickerPopUp>(data.ReadInt32());
    strategy.fillMode = static_cast<AVScreenCaptureFillMode>(data.ReadInt32());
    int32_t ret = SetScreenCaptureStrategy(strategy);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureServiceStub::SetCaptureArea(MessageParcel &data, MessageParcel &reply)
{
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture server is nullptr");
    uint64_t displayId = data.ReadUint64();
    OHOS::Rect area;
    area.x = data.ReadInt32();
    area.y = data.ReadInt32();
    area.w = data.ReadInt32();
    area.h = data.ReadInt32();

    int32_t ret = SetCaptureArea(displayId, area);
    reply.WriteInt32(ret);
    return MSERR_OK;
}
} // namespace Media
} // namespace OHOS
