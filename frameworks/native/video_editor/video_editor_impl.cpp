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
    logTag_ = "video-editor-" + std::to_string(id);
    MEDIA_LOGI("[%{public}s] construct.", logTag_.c_str());
}

VideoEditorImpl::~VideoEditorImpl()
{
    MEDIA_LOGI("[%{public}s] destruct.", logTag_.c_str());
    VideoEditorManager::GetInstance().ReleaseVideoEditor(id_);
}

VEFError VideoEditorImpl::Init()
{
    MEDIA_LOGI("[%{public}s] init video editor.", logTag_.c_str());
    MEDIA_LOGI("[%{public}s] create composite engine success.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoEditorImpl::AppendVideoFile(int fileFd, const std::string &effectDescription)
{
    MEDIA_LOGI("[%{public}s] append video file: %{public}d and apply effect[%{public}s].",
        logTag_.c_str(), fileFd, effectDescription.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoEditorImpl::StartComposite(const std::shared_ptr<CompositionOptions> &options)
{
    MEDIA_LOGI("[%{public}s] start composite.", logTag_.c_str());
    return VEFError::ERR_OK;
}

VEFError VideoEditorImpl::CancelComposite()
{
    MEDIA_LOGI("[%{public}s] cancel composite.", logTag_.c_str());
    return VEFError::ERR_OK;
}

uint64_t VideoEditorImpl::GetId() const
{
    return id_;
}
}  // namespace Media
}  // namespace OHOS