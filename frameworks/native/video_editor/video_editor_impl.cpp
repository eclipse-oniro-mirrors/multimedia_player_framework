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

#include "media_log.h"
#include "video_editor_impl.h"
#include "video_editor_manager.h"

namespace OHOS {
namespace Media {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoEditor"};
}

VideoEditorImpl::VideoEditorImpl(uint64_t id) : id_(id)
{
    logTag_ = "editorImpl-" + std::to_string(id);
}

VideoEditorImpl::~VideoEditorImpl()
{
    MEDIA_LOGD("[%{public}s] destruct.", logTag_.c_str());
    if (state_ == VideoEditorState::COMPOSITING) {
        auto err = compositeEngine_->StopComposite();
        if (err != VEFError::ERR_OK) {
            //This branch may failed to accessed, maybe the type of StopComposite could be changed to void.
            MEDIA_LOGE("[%{public}s] stop composite engine failed.", logTag_.c_str());
        }
    }
    VideoEditorManager::GetInstance().ReleaseVideoEditor(id_);
}

uint64_t VideoEditorImpl::GetId() const
{
    return id_;
}

VideoEditorState VideoEditorImpl::GetState() const
{
    return state_;
}

VEFError VideoEditorImpl::Init()
{
    MEDIA_LOGI("[%{public}s] init video editor.", logTag_.c_str());
    std::lock_guard<std::mutex> lock(editorLock_);
    dataCenter_ = IDataCenter::Create();
    if (dataCenter_ == nullptr) {
        MEDIA_LOGE("[%{public}s] create data center failed.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    compositeEngine_ = ICompositeEngine::CreateCompositeEngine(dataCenter_);
    if (compositeEngine_ == nullptr) {
        MEDIA_LOGE("[%{public}s] create coomposite engine failed.", logTag_.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    state_ = VideoEditorState::IDLE;
    MEDIA_LOGD("[%{public}s] init video editor finish.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoEditorImpl::AppendVideoFile(int fileFd, const std::string &effectDescription)
{
    MEDIA_LOGI("[%{public}s] append video file: %{public}d and apply effect[%{public}s].",
        logTag_.c_str(), fileFd, effectDescription.c_str());
    std::lock_guard<std::mutex> lock(editorLock_);
    VEFError err = dataCenter_->AppendVideo(fileFd, effectDescription);
    if (err != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] append file failed, err: %{public}d.", logTag_.c_str(), err);
        return err;
    }
    MEDIA_LOGD("[%{public}s] append video file success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoEditorImpl::StartComposite(const std::shared_ptr<CompositionOptions> &options)
{
    MEDIA_LOGI("[%{public}s] start composite.", logTag_.c_str());
    std::lock_guard<std::mutex> lock(editorLock_);
    if (!VideoEditorManager::GetInstance().IsFlowControlPass()) {
        MEDIA_LOGE("[%{public}s] start composite failed, flow control not pass.", logTag_.c_str());
        return VEFError::ERR_FLOW_CONTROL_INTERCEPT;
    }
    if (state_ != VideoEditorState::IDLE) {
        MEDIA_LOGE("[%{public}s] start composite failed, editor is busy, state: %{public}d.", logTag_.c_str(), state_);
        return VEFError::ERR_EDITOR_IS_BUSY;
    }
    VEFError err = compositeEngine_->StartComposite(options);
    if (err != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] start composite engine failed, error: %{public}d.", logTag_.c_str(), err);
        return err;
    }
    state_ = VideoEditorState::COMPOSITING;
    MEDIA_LOGI("[%{public}s] start composite engine success.", logTag_.c_str());
    return err;
}

VEFError VideoEditorImpl::CancelComposite()
{
    MEDIA_LOGI("[%{public}s] cancel composite.", logTag_.c_str());
    std::lock_guard<std::mutex> lock(editorLock_);
    if (state_ != VideoEditorState::COMPOSITING) {
        MEDIA_LOGW("[%{public}s] current state[%{public}d] is not compositing, need not cancel.",
            logTag_.c_str(), state_);
        return VEFError::ERR_OK;
    }
    state_ = VideoEditorState::CANCELLING;
    VEFError err = compositeEngine_->StopComposite();
    if (err != VEFError::ERR_OK) {
        MEDIA_LOGE("[%{public}s] cancel composite failed with error: %{public}d.", logTag_.c_str(), err);
        return err;
    }
    state_ = VideoEditorState::IDLE;
    MEDIA_LOGD("[%{public}s] cancel composite success.", logTag_.c_str());
    return err;
}

void VideoEditorImpl::OnCompositeResult(VEFResult result)
{
    MEDIA_LOGI("[%{public}s] composite result: %{public}d.", logTag_.c_str(), result);
    std::lock_guard<std::mutex> lock(editorLock_);
    state_ = VideoEditorState::IDLE;
}

}  // namespace Media
}  // namespace OHOS