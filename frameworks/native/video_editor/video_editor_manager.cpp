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

#include "video_editor.h"
#include "video_editor_impl.h"
#include "video_editor_manager.h"
#include "media_log.h"

namespace OHOS {
namespace Media {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoEditor"};
}

constexpr uint64_t FLOW_CONTROL_MAX_EDITOR_THRESHOLD = 5;

std::shared_ptr<VideoEditor> VideoEditorFactory::CreateVideoEditor()
{
    return VideoEditorManager::GetInstance().CreateVideoEditor();
}

VideoEditorManager& VideoEditorManager::GetInstance()
{
    static VideoEditorManager instance;
    return instance;
}

std::shared_ptr<VideoEditor> VideoEditorManager::CreateVideoEditor()
{
    auto videoEditor = std::make_shared<VideoEditorImpl>(id_.fetch_add(1));
    uint64_t id = videoEditor->GetId();
    MEDIA_LOGD("create VideoEditor[id = %{public}" PRIu64 "] object success.", id);

    VEFError error = videoEditor->Init();
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("init VideoEditor[id = %{public}" PRIu64 "] failed, error: %{public}d.", id, error);
        return nullptr;
    }

    editorMapMutex_.lock();
    editorMap_[id] = std::weak_ptr<VideoEditorImpl>(videoEditor);
    editorMapMutex_.unlock();

    MEDIA_LOGI("create VideoEditor[id = %{public}" PRIu64 "] success.", id);
    return videoEditor;
}

void VideoEditorManager::ReleaseVideoEditor(uint64_t id)
{
    MEDIA_LOGI("release VideoEditor[id = %{public}" PRIu64 "] start.", id);
    editorMapMutex_.lock();
    editorMap_.erase(id);
    editorMapMutex_.unlock();
    MEDIA_LOGI("release VideoEditor[id = %{public}" PRIu64 "] finish.", id);
}

bool VideoEditorManager::IsFlowControlPass() const
{
    uint32_t compositingCount = 0;
    std::shared_lock<std::shared_mutex> lock(editorMapMutex_);
    for (auto it = editorMap_.begin(); it != editorMap_.end(); ++it) {
        auto editor = it->second.lock();
        if (editor == nullptr) {
            continue;
        }
        if (editor->GetState() == VideoEditorState::COMPOSITING) {
            compositingCount++;
        }
        if (compositingCount >= FLOW_CONTROL_MAX_EDITOR_THRESHOLD) {
            return false;
        }
    }
    return true;
}

} // namespace Media
} // namespace OHOS
