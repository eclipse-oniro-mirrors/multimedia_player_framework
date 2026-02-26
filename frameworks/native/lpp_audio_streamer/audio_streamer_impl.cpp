/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "audio_streamer_impl.h"
#include "i_media_service.h"
#include "media_log.h"
#include "media_errors.h"
#include "param_wrapper.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "AudioStreamerImpl"};
}

namespace OHOS {
namespace Media {
std::shared_ptr<AudioStreamer> AudioStreamerFactory::CreateByMime(const std::string &mime)
{
    std::shared_ptr<AudioStreamerImpl> impl = std::make_shared<AudioStreamerImpl>();
    CHECK_AND_RETURN_RET_LOG(impl != nullptr, nullptr, "failed to new AudioStreamerImpl");
    int32_t ret = impl->Init(mime);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed to init AudioStreamerImpl");

    return impl;
}

int32_t AudioStreamerImpl::Init(const std::string &mime)
{
    std::string enableLpp;
    auto ret = OHOS::system::GetStringParameter("debug.media_service.enable_lpp_avsink", enableLpp, "true");
    enableLppSink_ = ret == 0 ? enableLpp == "true" : false;
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    MEDIA_LOGI("AudioStreamerImpl Init, mime %{public}s", mime.c_str());
    streamerService_ = MediaServiceFactory::GetInstance().CreateLppAudioStreamerService();
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_NO_MEMORY, "streamerService_ nulptr");
    ret = streamerService_->Init(mime);
    return ret;
}

AudioStreamerImpl::AudioStreamerImpl()
{}

AudioStreamerImpl::~AudioStreamerImpl()
{
    if (streamerService_ != nullptr) {
        (void)MediaServiceFactory::GetInstance().DestroyLppAudioStreamerService(streamerService_);
        streamerService_ = nullptr;
    }
}

int32_t AudioStreamerImpl::Configure(const Format &param)
{
    MEDIA_LOGI("AudioStreamerImpl Configure");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->Configure(param);
    return ret;
}

int32_t AudioStreamerImpl::SetParameter(const Format &param)
{
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    return streamerService_->SetParameter(param);
}

int32_t AudioStreamerImpl::GetParameter(Format &param)
{
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    return streamerService_->GetParameter(param);
}

int32_t AudioStreamerImpl::Prepare()
{
    MEDIA_LOGI("AudioStreamerImpl Prepare");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->Prepare();
    return ret;
}

int32_t AudioStreamerImpl::Start()
{
    MEDIA_LOGI("AudioStreamerImpl Start");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->Start();
    return ret;
}

int32_t AudioStreamerImpl::Pause()
{
    MEDIA_LOGI("AudioStreamerImpl Pause");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->Pause();
    return ret;
}

int32_t AudioStreamerImpl::Resume()
{
    MEDIA_LOGI("AudioStreamerImpl Resume");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->Resume();
    return ret;
}

int32_t AudioStreamerImpl::Flush()
{
    MEDIA_LOGI("AudioStreamerImpl Flush");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->Flush();
    return ret;
}
int32_t AudioStreamerImpl::Stop()
{
    MEDIA_LOGI("AudioStreamerImpl Stop");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->Stop();
    return ret;
}

int32_t AudioStreamerImpl::Reset()
{
    MEDIA_LOGI("AudioStreamerImpl Reset");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->Reset();
    return ret;
}

int32_t AudioStreamerImpl::Release()
{
    MEDIA_LOGI("AudioStreamerImpl Release");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->Release();
    return ret;
}

int32_t AudioStreamerImpl::SetVolume(float volume)
{
    MEDIA_LOGI("AudioStreamerImpl SetVolume");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->SetVolume(volume);
    return ret;
}

int32_t AudioStreamerImpl::SetLoudnessGain(const float loudnessGain)
{
    MEDIA_LOGD("SetLoudnessGain");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->SetLoudnessGain(loudnessGain);
    return ret;
}

int32_t AudioStreamerImpl::SetPlaybackSpeed(float speed)
{
    MEDIA_LOGI("AudioStreamerImpl SetPlaybackSpeed");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->SetPlaybackSpeed(speed);
    return ret;
}

int32_t AudioStreamerImpl::ReturnFrames(sptr<LppDataPacket> framePacket)
{
    MEDIA_LOGD("AudioStreamerImpl ReturnFrames");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->ReturnFrames(framePacket);
    return ret;
}

int32_t AudioStreamerImpl::RegisterCallback()
{
    MEDIA_LOGI("AudioStreamerImpl RegisterCallback");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->RegisterCallback();
    return ret;
}

int32_t AudioStreamerImpl::SetLppAudioStreamerCallback(const std::shared_ptr<AudioStreamerCallback> &callback)
{
    MEDIA_LOGI("AudioStreamerImpl:0x%{public}06" PRIXPTR " SetRecorderCallback in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_INVALID_VAL, "input callback is nullptr.");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return streamerService_->SetLppAudioStreamerCallback(callback);
}

int32_t AudioStreamerImpl::SetLppVideoStreamerId(const std::string videoStreamId)
{
    MEDIA_LOGI("AudioStreamerImpl:0x%{public}06" PRIXPTR " SetLppVideoStreamerId in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return streamerService_->SetLppVideoStreamerId(videoStreamId);
}

std::string AudioStreamerImpl::GetStreamerId()
{
    MEDIA_LOGI("AudioStreamerImpl:0x%{public}06" PRIXPTR " GetStreamerId in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, "", "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, "", "player service does not exist..");
    return streamerService_->GetStreamerId();
}
}  // namespace Media
}  // namespace OHOS
