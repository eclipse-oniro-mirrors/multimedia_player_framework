/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
 
#ifndef TRANSPARENT_VIDEO_LAYOUT_MODE_H
#define TRANSPARENT_VIDEO_LAYOUT_MODE_H
 
#include <cstdint>
 
namespace OHOS {
namespace Media {
 
enum class SideBySideTransparentVideoLayoutMode : int32_t {
    SIDE_BY_SIDE_LAYOUT_HORIZONTAL = 0,
    SIDE_BY_SIDE_LAYOUT_VERTICAL = 1,
    SIDE_BY_SIDE_LAYOUT_HORIZONTAL_REVERSE = 2,
    SIDE_BY_SIDE_LAYOUT_VERTICAL_REVERSE = 3,
};
 
} // namespace Media
} // namespace OHOS
 
#endif // TRANSPARENT_VIDEO_LAYOUT_MODE_H