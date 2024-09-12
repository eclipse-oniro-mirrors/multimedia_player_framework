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

#ifndef OH_VEF_INNER_INTERFACE_H
#define OH_VEF_INNER_INTERFACE_H

#include <memory>
#include <string>

namespace OHOS {
namespace Media {

enum class VEFError : int32_t {
    // No error, the operation was successful.
    ERR_OK = 0,

    // An invalid parameter was provided, causing the operation to fail.
    ERR_INVALID_PARAM,

    // Out of memory, the operation could not be completed due to insufficient memory.
    ERR_OOM,

    // Flow control intercepted the operation
    // the current number of concurrent connections exceeds the set threshold (5).
    ERR_FLOW_CONTROL_INTERCEPT,

    // The input video has not been set, which is required for the operation to proceed.
    ERR_NOT_SET_INPUT_VIDEO,

    // The number of input video files exceeds the upper limit(<2).
    ERR_INPUT_VIDEO_COUNT_LIMITED,

    // The editor is busying(compositing/cancelling...), please try again later.
    ERR_EDITOR_IS_BUSY,

    // The effect is not supported.
    ERR_EFFECT_IS_NOT_SUPPORTED,

    // An internal error occurred, which is an unexpected failure in the operation.
    ERR_INTERNAL_ERROR
};

enum class VEFResult : int32_t {
    SUCCESS,
    FAILED,
    CANCELLED,
    UNKNOWN
};

/**
 * @class CompositionCallback
 *
 * @brief Result and progress callback interface for video composition.
 * the user needs to inherit and implement CompositionCallback.
 */
class CompositionCallback {
public:
    /**
     * @brief Used to notify the caller of the result of the effects video composition.
     *
     * @param result result of the effects video composition. VEFResult::SUCCESS: success; other values: failure.
     * @param errorCode When an error occurs, errorCode represents the specific error code.
     */
    virtual void onResult(VEFResult result, VEFError errorCode) = 0;

    /**
     * @brief Used to notify the caller of the progress of the effects video composition.
     *
     * @param progress progress of the effects video composition. The value ranges is [0, 100].
     */
    virtual void onProgress(uint32_t progress) = 0;
};

/**
 * @class CompositionOptions
 *
 * @brief parameters for composition.
 */
class CompositionOptions {
public:
    CompositionOptions(int fd, std::shared_ptr<CompositionCallback> callback)
    {
        targetFileFd_ = fd;
        callback_ = callback;
    }
public:
    /**
     * the fd of target effect video, caller need open the file with write permission,
     * required fields, -1 is not accepted.
     */
    int targetFileFd_ = -1;

    /**
     * CompositionCallback, result and progress callback interface for video composition.
     * required fields, null pointer is not accepted.
     */
    std::shared_ptr<CompositionCallback> callback_ = nullptr;
};

class VideoEditor {
public:
    virtual ~VideoEditor() = default;

    /**
     * @brief Apply the effect description information to apply the effect to the input media file
     *
     * @param inputFileFd the fd of original raw video footage, caller need open the file with read permission.
     * @param effectDescription the description[edit_data] of video effect to the video,
     * which must comply with the specifications of the media library, camera, and gallery components.
     * @return VEF_OK: success; other values: failure.
     */
    virtual VEFError AppendVideoFile(int fileFd, const std::string& effectDescription) = 0;

    /**
     * @brief Start compositing effects video.
     *
     * @param targetFileFd the fd of target effect video, caller need open the file with write permission.
     * @param options Options for compositing video, null pointer is not accepted.
     * @return VEF_OK: success; other values: failure.
     */
    virtual VEFError StartComposite(const std::shared_ptr<CompositionOptions>& options) = 0;

    /**
     * @brief Cancel compositing effects video.
     *
     * @return Result of cancelling composition operation, VEF_OK: success; other values: failure.
     */
    virtual VEFError CancelComposite() = 0;
};

class __attribute__((visibility("default"))) VideoEditorFactory {
public:
#ifdef UNSUPPORT_VIDEO_EDITOR
    static std::shared_ptr<VideoEditor> CreateVideoEditor()
    {
        return nullptr;
    }
#else
    /**
    * Creating a Video Editor Instance.
    * @return Returns a shared pointer to the newly created video editor instanceCreate Video Editor Instance.
    */
    static std::shared_ptr<VideoEditor> CreateVideoEditor();
#endif
private:
    VideoEditorFactory() = default;
    ~VideoEditorFactory() = default;
};

} // namespace Media
} // namespace OHOS

#endif // OH_VEF_INNER_INTERFACE_H