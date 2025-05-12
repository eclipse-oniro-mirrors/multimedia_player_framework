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

#ifndef META_UTILS
#define META_UTILS

#include "media_types.h"
#include "meta.h"
#include "meta_key.h"

namespace OHOS {
namespace Media {
namespace MetaUtils {
inline bool CheckFileType(const std::shared_ptr<Meta> meta)
{
    if (meta == nullptr) {
        return false;
    }
    FileType fileType = FileType::UNKNOW;
    return meta->Get<Tag::MEDIA_FILE_TYPE>(fileType) && fileType != FileType::UNKNOW;
}
 
inline bool CheckHasAudio(const std::shared_ptr<Meta> meta)
{
    if (meta == nullptr) {
        return false;
    }
    bool hasAudio = false;
    meta->Get<Tag::MEDIA_HAS_AUDIO>(hasAudio);
    return hasAudio;
}
 
inline bool CheckHasVideo(const std::shared_ptr<Meta> meta)
{
    if (meta == nullptr) {
        return false;
    }
    bool hasVideo = false;
    meta->Get<Tag::MEDIA_HAS_VIDEO>(hasVideo);
    return hasVideo;
}
} // namespace MetaUtils
}  // namespace Media
}  // namespace OHOS
#endif  // META_UTILS