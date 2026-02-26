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

#include "video_streamer_impl.h"
#include "i_media_service.h"
#include "media_log.h"
#include "media_errors.h"
#include "param_wrapper.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "VideoStreamerImpl"};
}

namespace OHOS {
namespace Media {
std::shared_ptr<VideoStreamer> VideoStreamerFactory::CreateByMime(const std::string &mime)
{
    std::shared_ptr<VideoStreamerImpl> impl = std::make_shared<VideoStreamerImpl>();
    CHECK_AND_RETURN_RET_LOG(impl != nullptr, nullptr, "failed to new VideoStreamerImpl");
    int32_t ret = impl->Init(mime);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed to init VideoStreamerImpl");
    return impl;
}

LppAvCapabilityInfo *VideoStreamerFactory::GetLppCapacity()
{
    LppAvCapabilityInfo *lppAvCapability = MediaServiceFactory::GetInstance().GetLppCapacity();
    CHECK_AND_RETURN_RET_LOG(lppAvCapability != nullptr, nullptr, "VideoStreamerFactory::failed to GetLppCapacity");
    return lppAvCapability;
}

int32_t VideoStreamerImpl::Init(const std::string &mime)
{
    MEDIA_LOGI("VideoStreamerImpl Init, mime %{public}s", mime.c_str());
    std::string enableLpp;
    auto ret = OHOS::system::GetStringParameter("debug.media_service.enable_lpp_avsink", enableLpp, "true");
    enableLppSink_ = ret == 0 ? enableLpp == "true" : false;
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    streamerService_ = MediaServiceFactory::GetInstance().CreateLppVideoStreamerService();
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_NO_MEMORY, "streamerService_ nulptr");
    ret = streamerService_->Init(mime);
    return ret;
}

VideoStreamerImpl::VideoStreamerImpl()
{}

VideoStreamerImpl::~VideoStreamerImpl()
{
    if (streamerService_ != nullptr) {
        (void)MediaServiceFactory::GetInstance().DestroyLppVideoStreamerService(streamerService_);
        streamerService_ = nullptr;
    }
}

int32_t VideoStreamerImpl::Configure(const Format &param)
{
    MEDIA_LOGI("VideoStreamerImpl Configure");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->Configure(param);
    return ret;
}

int32_t VideoStreamerImpl::SetOutputSurface(sptr<Surface> surface)
{
    MEDIA_LOGI("VideoStreamerImpl SetOutputSurface");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->SetOutputSurface(surface);
    return ret;
}

int32_t VideoStreamerImpl::SetParameter(const Format &param)
{
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->SetParameter(param);
    return ret;
}

int32_t VideoStreamerImpl::GetParameter(Format &param)
{
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->GetParameter(param);
    return ret;
}

int32_t VideoStreamerImpl::Prepare()
{
    MEDIA_LOGI("VideoStreamerImpl Prepare");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->Prepare();
    return ret;
}

int32_t VideoStreamerImpl::StartDecode()
{
    MEDIA_LOGI("VideoStreamerImpl StartDecode");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->StartDecode();
    return ret;
}

int32_t VideoStreamerImpl::StartRender()
{
    MEDIA_LOGI("VideoStreamerImpl StartRender");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->StartRender();
    return ret;
}

int32_t VideoStreamerImpl::Start()
{
    MEDIA_LOGI("VideoStreamerImpl Start");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->Start();
    return ret;
}

int32_t VideoStreamerImpl::Pause()
{
    MEDIA_LOGI("VideoStreamerImpl Pause");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->Pause();
    return ret;
}

int32_t VideoStreamerImpl::Resume()
{
    MEDIA_LOGI("VideoStreamerImpl Resume");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->Resume();
    return ret;
}

int32_t VideoStreamerImpl::Flush()
{
    MEDIA_LOGI("VideoStreamerImpl Flush");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->Flush();
    return ret;
}
int32_t VideoStreamerImpl::Stop()
{
    MEDIA_LOGI("VideoStreamerImpl Stop");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->Stop();
    return ret;
}

int32_t VideoStreamerImpl::Reset()
{
    MEDIA_LOGI("VideoStreamerImpl Reset");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->Reset();
    return ret;
}

int32_t VideoStreamerImpl::Release()
{
    MEDIA_LOGI("VideoStreamerImpl Release");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->Release();
    return ret;
}

int32_t VideoStreamerImpl::SetSyncAudioStreamer(std::shared_ptr<AudioStreamer> audioStreamer)
{
    MEDIA_LOGI("VideoStreamerImpl SetSyncAudioStreamer");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(audioStreamer != nullptr, MSERR_INVALID_VAL, "service died");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    std::string videoStreamerId = streamerService_->GetStreamerId();
    MEDIA_LOGI("videoStreamerId %{public}s", videoStreamerId.c_str());
    int32_t ret = audioStreamer->SetLppVideoStreamerId(videoStreamerId);
    std::string audioStreamerId = audioStreamer->GetStreamerId();
    MEDIA_LOGI("audioStreamerId %{public}s", audioStreamerId.c_str());
    ret = streamerService_->SetLppAudioStreamerId(audioStreamerId);
    return ret;
}

int32_t VideoStreamerImpl::SetTargetStartFrame(const int64_t targetPts, const int timeoutMs)
{
    MEDIA_LOGI("VideoStreamerImpl SetTargetStartFrame");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->SetTargetStartFrame(targetPts, timeoutMs);
    return ret;
}

int32_t VideoStreamerImpl::SetVolume(float volume)
{
    MEDIA_LOGI("VideoStreamerImpl SetVolume");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->SetVolume(volume);
    return ret;
}

int32_t VideoStreamerImpl::SetPlaybackSpeed(float speed)
{
    MEDIA_LOGI("VideoStreamerImpl SetPlaybackSpeed");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->SetPlaybackSpeed(speed);
    return ret;
}

int32_t VideoStreamerImpl::ReturnFrames(sptr<LppDataPacket> framePacket)
{
    MEDIA_LOGD("VideoStreamerImpl ReturnFrames");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->ReturnFrames(framePacket);
    return ret;
}

int32_t VideoStreamerImpl::RegisterCallback()
{
    MEDIA_LOGI("VideoStreamerImpl RegisterCallback");
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->RegisterCallback();
    return ret;
}

int32_t VideoStreamerImpl::SetLppVideoStreamerCallback(const std::shared_ptr<VideoStreamerCallback> &callback)
{
    MEDIA_LOGI("RecorderImpl:0x%{public}06" PRIXPTR " SetRecorderCallback in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_INVALID_VAL, "input callback is nullptr.");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    callback_ = callback;
    return streamerService_->SetLppVideoStreamerCallback(callback);
}

std::shared_ptr<VideoStreamerCallback> VideoStreamerImpl::GetLppVideoStreamerCallback()
{
    return callback_;
}

int32_t VideoStreamerImpl::RenderFirstFrame()
{
    CHECK_AND_RETURN_RET_LOG(enableLppSink_, MSERR_UNSUPPORT, "Lpp is disabled");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED, "service died");
    int32_t ret = streamerService_->RenderFirstFrame();
    return ret;
}

std::string VideoStreamerImpl::GetStreamerId()
{
    MEDIA_LOGI("VideoStreamerImpl:0x%{public}06" PRIXPTR " GetStreamerId in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, "", "player service does not exist..");
    return streamerService_->GetStreamerId();
}

int32_t VideoStreamerImpl::GetLatestPts(int64_t &pts)
{
    MEDIA_LOGI("VideoStreamerImpl GetLatestPts");
    CHECK_AND_RETURN_RET_LOG(streamerService_ != nullptr, MSERR_SERVICE_DIED,
        "GetLatestPts player service does not exist.");
    int32_t ret = streamerService_->GetLatestPts(pts);
    pts = (ret == MSERR_OK) ? pts : 0;
    return ret;
}
}  // namespace Media
}  // namespace OHOS
