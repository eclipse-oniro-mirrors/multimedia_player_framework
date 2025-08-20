/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "screen_capture_controller_stub.h"
#include "media_server_manager.h"
#include "media_log.h"
#include "media_errors.h"
#include "avsharedmemory_ipc.h"
#include "media_utils.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureControllerStub"};
}

namespace OHOS {
namespace Media {

sptr<ScreenCaptureControllerStub> ScreenCaptureControllerStub::Create()
{
    MEDIA_LOGI("ScreenCaptureControllerStub::Create() start");
    sptr<ScreenCaptureControllerStub> screenCaptureControllerStub = new(std::nothrow) ScreenCaptureControllerStub();
    CHECK_AND_RETURN_RET_LOG(screenCaptureControllerStub != nullptr, nullptr,
        "failed to new ScreenCaptureControllerStub");

    int32_t ret = screenCaptureControllerStub->Init();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed to screenCapture controller stub init");
    return screenCaptureControllerStub;
}

ScreenCaptureControllerStub::ScreenCaptureControllerStub()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

ScreenCaptureControllerStub::~ScreenCaptureControllerStub()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t ScreenCaptureControllerStub::Init()
{
    MEDIA_LOGI("ScreenCaptureControllerStub::Init() start");
    std::unique_lock<std::mutex> lock(mutex_);
    screenCaptureControllerServer_ = ScreenCaptureControllerServer::Create();
    CHECK_AND_RETURN_RET_LOG(screenCaptureControllerServer_ != nullptr, MSERR_NO_MEMORY,
        "failed to create screenCaptureControllerServer Service");
    screenCaptureControllerStubFuncs_[REPORT_USER_CHOICE] =
        &ScreenCaptureControllerStub::ReportAVScreenCaptureUserChoice;
    screenCaptureControllerStubFuncs_[GET_CONFIG_PARAM] =
        &ScreenCaptureControllerStub::GetAVScreenCaptureConfigurableParameters;
    screenCaptureControllerStubFuncs_[DESTROY] = &ScreenCaptureControllerStub::DestroyStub;

    return MSERR_OK;
}

int ScreenCaptureControllerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    MEDIA_LOGD("ScreenCaptureControllerStub: OnRemoteRequest of code: %{public}u is received", code);

    auto remoteDescriptor = data.ReadInterfaceToken();
    if (ScreenCaptureControllerStub::GetDescriptor() != remoteDescriptor) {
        MEDIA_LOGE("Invalid descriptor");
        return MSERR_INVALID_OPERATION;
    }

    auto itFunc = screenCaptureControllerStubFuncs_.find(code);
    if (itFunc != screenCaptureControllerStubFuncs_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            int32_t ret = (this->*memberFunc)(data, reply);
            if (ret != MSERR_OK) {
                MEDIA_LOGE("Calling memberFunc is failed.");
            }
            return MSERR_OK;
        }
    }
    MEDIA_LOGW("ScreenCaptureControllerStub: no member func supporting, applying default process");

    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t ScreenCaptureControllerStub::DestroyStub()
{
    std::unique_lock<std::mutex> lock(mutex_);
    screenCaptureControllerServer_ = nullptr;
    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::SCREEN_CAPTURE_CONTROLLER, AsObject());
    return MSERR_OK;
}

int32_t ScreenCaptureControllerStub::DestroyStub(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(DestroyStub());
    return MSERR_OK;
}

int32_t ScreenCaptureControllerStub::ReportAVScreenCaptureUserChoice(int32_t sessionId, std::string choice)
{
    MEDIA_LOGI("ScreenCaptureControllerStub::ReportAVScreenCaptureUserChoice start 2");
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(screenCaptureControllerServer_ != nullptr, false,
        "screen capture controller server is nullptr");
    int32_t appUid = IPCSkeleton::GetCallingUid();
    std::string appName = GetClientBundleName(appUid);
    if (GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"]
            .compare(appName) != 0) {
        MEDIA_LOGE("ScreenCaptureControllerStub called by app name %{public}s", appName.c_str());
        return MSERR_INVALID_OPERATION;
    }
    return screenCaptureControllerServer_->ReportAVScreenCaptureUserChoice(sessionId, choice);
}

int32_t ScreenCaptureControllerStub::ReportAVScreenCaptureUserChoice(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_LOGI("ScreenCaptureControllerStub::ReportAVScreenCaptureUserChoice start 1");
    CHECK_AND_RETURN_RET_LOG(screenCaptureControllerServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture controller server is nullptr");
    (void)data;
    int32_t sessionId = data.ReadInt32();
    std::string choice = data.ReadString();
    int32_t ret = ReportAVScreenCaptureUserChoice(sessionId, choice);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t ScreenCaptureControllerStub::GetAVScreenCaptureConfigurableParameters(int32_t sessionId, std::string &resultStr)
{
    MEDIA_LOGI("ScreenCaptureControllerStub::GetAVScreenCaptureConfigurableParameters start");
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(screenCaptureControllerServer_ != nullptr, false,
        "screen capture controller server is nullptr");
    int32_t appUid = IPCSkeleton::GetCallingUid();
    std::string appName = GetClientBundleName(appUid);
    if (GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"]
            .compare(appName) != 0) {
        MEDIA_LOGE("ScreenCaptureControllerStub called by app name %{public}s", appName.c_str());
        return MSERR_INVALID_OPERATION;
    }
    return screenCaptureControllerServer_->GetAVScreenCaptureConfigurableParameters(sessionId, resultStr);
}

int32_t ScreenCaptureControllerStub::GetAVScreenCaptureConfigurableParameters(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_LOGI("ScreenCaptureControllerStub::GetAVScreenCaptureConfigurableParameters start");
    CHECK_AND_RETURN_RET_LOG(screenCaptureControllerServer_ != nullptr, MSERR_INVALID_STATE,
        "screen capture controller server is nullptr");
    (void)data;
    int32_t sessionId = data.ReadInt32();
    std::string resultStr;
    int32_t ret = GetAVScreenCaptureConfigurableParameters(sessionId, resultStr);
    MEDIA_LOGI("ScreenCaptureControllerStub::GetAVScreenCaptureConfigurableParameters start resultStr: %{public}s",
        resultStr.c_str());
    reply.WriteInt32(ret);
    reply.WriteString(resultStr);
    return MSERR_OK;
}


} // namespace Media
} // namespace OHOS