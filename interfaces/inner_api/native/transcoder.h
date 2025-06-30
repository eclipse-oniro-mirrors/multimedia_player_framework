/*
 * Copyright (C) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef TRANSCODER_H
#define TRANSCODER_H

#include <cstdint>
#include <string>
#include <map>
#include <set>
#include <parcel.h>
#include "meta/format.h"
#include "surface.h"
#include "surface/native_buffer.h"
#include "av_common.h"
#include "codec_capability.h"
#include "media_core.h"

namespace OHOS {
namespace Media {
using ConfigMap = std::map<std::string, int32_t>;

/**
 * @brief Enumerates transcodering error types.
 *
 * @since 5.0
 * @version 5.0
 */
enum TransCoderErrorType : int32_t {
    TRANSCODER_ERROR_INTERNAL
};

enum TransCoderOnInfoType : int32_t {
    /* return the current progress of transcoder automatically. */
    INFO_TYPE_TRANSCODER_COMPLETED = 0,
    /* return the current progress of transcoder automatically. */
    INFO_TYPE_PROGRESS_UPDATE = 1,
};

/**
 * @brief Enumerates transcodering color space.
 *
 * @since 6.0
 * @version 6.0
 */
enum TranscoderColorSpace : int32_t {
    /** None color space */
    TRANSCODER_COLORSPACE_NONE = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_NONE,
    /** COLORPRIMARIES_BT601_P */
    TRANSCODER_COLORSPACE_BT601_EBU_FULL = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT601_EBU_FULL,
    /** COLORPRIMARIES_BT601_N */
    TRANSCODER_COLORSPACE_BT601_SMPTE_C_FULL = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT601_SMPTE_C_FULL,
    /** COLORPRIMARIES_BT709 */
    TRANSCODER_COLORSPACE_BT709_FULL = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT709_FULL,
    /** COLORPRIMARIES_BT2020 */
    TRANSCODER_COLORSPACE_BT2020_HLG_FULL = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_HLG_FULL,
    /** COLORPRIMARIES_BT2020 */
    TRANSCODER_COLORSPACE_BT2020_PQ_FULL = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_PQ_FULL,
    /** COLORPRIMARIES_BT601_P */
    TRANSCODER_COLORSPACE_BT601_EBU_LIMIT = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT601_EBU_LIMIT,
    /** COLORPRIMARIES_BT601_N */
    TRANSCODER_COLORSPACE_BT601_SMPTE_C_LIMIT = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT601_SMPTE_C_LIMIT,
    /** COLORPRIMARIES_BT709 */
    TRANSCODER_COLORSPACE_BT709_LIMIT = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT709_LIMIT,
    /** COLORPRIMARIES_BT2020 */
    TRANSCODER_COLORSPACE_BT2020_HLG_LIMIT = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_HLG_LIMIT,
    /** COLORPRIMARIES_BT2020 */
    TRANSCODER_COLORSPACE_BT2020_PQ_LIMIT = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_PQ_LIMIT,
    /** COLORPRIMARIES_SRGB */
    TRANSCODER_COLORSPACE_SRGB_FULL = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_SRGB_FULL,
    /** COLORPRIMARIES_P3_D65 */
    TRANSCODER_COLORSPACE_P3_FULL = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_FULL,
    /** COLORPRIMARIES_P3_D65 */
    TRANSCODER_COLORSPACE_P3_HLG_FULL = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_HLG_FULL,
    /** COLORPRIMARIES_P3_D65 */
    TRANSCODER_COLORSPACE_P3_PQ_FULL = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_PQ_FULL,
    /** COLORPRIMARIES_ADOBERGB */
    TRANSCODER_COLORSPACE_ADOBERGB_FULL = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_ADOBERGB_FULL,
    /** COLORPRIMARIES_SRGB */
    TRANSCODER_COLORSPACE_SRGB_LIMIT = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_SRGB_LIMIT,
    /** COLORPRIMARIES_P3_D65 */
    TRANSCODER_COLORSPACE_P3_LIMIT = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_LIMIT,
    /** COLORPRIMARIES_P3_D65 */
    TRANSCODER_COLORSPACE_P3_HLG_LIMIT = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_HLG_LIMIT,
    /** COLORPRIMARIES_P3_D65 */
    TRANSCODER_COLORSPACE_P3_PQ_LIMIT = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_PQ_LIMIT,
    /** COLORPRIMARIES_ADOBERGB */
    TRANSCODER_COLORSPACE_ADOBERGB_LIMIT = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_ADOBERGB_LIMIT,
    /** COLORPRIMARIES_SRGB */
    TRANSCODER_COLORSPACE_LINEAR_SRGB = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_LINEAR_SRGB,
    /** equal to OH_COLORSPACE_LINEAR_SRGB */
    TRANSCODER_COLORSPACE_LINEAR_BT709 = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_LINEAR_BT709,
    /** COLORPRIMARIES_P3_D65 */
    TRANSCODER_COLORSPACE_LINEAR_P3 = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_LINEAR_P3,
    /** COLORPRIMARIES_BT2020 */
    TRANSCODER_COLORSPACE_LINEAR_BT2020 = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_LINEAR_BT2020,
    /** equal to OH_COLORSPACE_SRGB_FULL */
    TRANSCODER_COLORSPACE_DISPLAY_SRGB = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_DISPLAY_SRGB,
    /** equal to OH_COLORSPACE_P3_FULL */
    TRANSCODER_COLORSPACE_DISPLAY_P3_SRGB = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_DISPLAY_P3_SRGB,
    /** equal to OH_COLORSPACE_P3_HLG_FULL */
    TRANSCODER_COLORSPACE_DISPLAY_P3_HLG = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_DISPLAY_P3_HLG,
    /** equal to OH_COLORSPACE_P3_PQ_FULL */
    TRANSCODER_COLORSPACE_DISPLAY_P3_PQ = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_DISPLAY_P3_PQ,
    /** COLORPRIMARIES_BT2020 */
    TRANSCODER_COLORSPACE_DISPLAY_BT2020_SRGB = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_DISPLAY_BT2020_SRGB,
    /** equal to OH_COLORSPACE_BT2020_HLG_FULL */
    TRANSCODER_COLORSPACE_DISPLAY_BT2020_HLG = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_DISPLAY_BT2020_HLG,
    /** equal to OH_COLORSPACE_BT2020_PQ_FULL */
    TRANSCODER_COLORSPACE_DISPLAY_BT2020_PQ = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_DISPLAY_BT2020_PQ,
};

/**
 * @brief Provides listeners for transcodering errors and information events.
 *
 * @since 5.0
 * @version 5.0
 */
class TransCoderCallback {
public:
    virtual ~TransCoderCallback() = default;

    /**
     * @brief Called when an error occurs during transcodering. This callback is used to report transcodering errors.
     *
     * @param errorType Indicates the error type. For details, see {@link TransCoderErrorType}.
     * @param errorCode Indicates the error code.
     * @since 1.0
     * @version 1.0
     */
    virtual void OnError(int32_t errorCode, const std::string &errorMsg) = 0;

    /**
     * @brief Called when an information event occurs during transcodering. This callback is used to report
     * transcodering information.
     *
     * @param type Indicates the information type. For details, see {@link TransCoderInfoType}.
     * @param extra Indicates other information, for example, the start time position of a transcodering file.
     * @since 1.0
     * @version 1.0
     */
    virtual void OnInfo(int32_t type, int32_t extra) = 0;
};

/**
 * @brief Provides functions for audio and video transcodering.
 *
 * @since 1.0
 * @version 1.0
 */
class TransCoder {
public:
    virtual ~TransCoder() = default;

    /**
     * @brief Sets the output file format.
     *
     * This function must be called before {@link Prepare} and after after all required sources have been set. After
     * this function called, no more source settings allowed.
     *
     * @param format Indicates the output file format. For details, see {@link OutputFormatType}.
     * @return Returns {@link MSERR_OK} if the setting is successful; returns an error code otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetOutputFormat(OutputFormatType format) = 0;

    /**
     * @brief Sets the encoder of the video to transcoder.
     *
     * If this function is not called, the output file does not contain the video track when the video source is
     * YUV or RGB.
     * This function must be called after {@link SetOutputFormat} but before {@link Prepare}.
     *
     * @param encoder Indicates the video encoder to set. For details, see {@link VideoCodecFormat}.
     * @return Returns {@link MSERR_OK} if the setting is successful; returns an error code otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetVideoEncoder(VideoCodecFormat encoder) = 0;

    /**
     * @brief Sets the encoding bit rate of the video to transcoder.
     *
     * This function must be called after {@link SetOutputFormat} but before {@link Prepare}.
     *
     * @param rate Indicates the encoding bit rate to set.
     * @return Returns {@link MSERR_OK} if the setting is successful; returns an error code otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetVideoEncodingBitRate(int32_t rate) = 0;

    /**
     * @brief Sets the encoding video size of the video to transcoder.
     *
     * This function must be called after {@link SetOutputFormat} but before {@link Prepare}.
     *
     * @param rate Indicates the encoding bit rate to set.
     * @return Returns {@link MSERR_OK} if the setting is successful; returns an error code otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetVideoSize(int32_t videoFrameWidth, int32_t videoFrameHeight) = 0;

    /**
     * @brief Sets the colorspace of the video to transcoder
     *
     * This function must be called after {@link SetOutputFormat} but before {@link Prepare}.
     *
     * @param colorSpaceFormat Indicates the colorSpace format of the video to set.
     * @return Returns {@link MSERR_OK} if the setting is successful; returns an error code otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetColorSpace(TranscoderColorSpace colorSpaceFormat) = 0;

    /**
     * @brief Sets the B frame encoding to transcoder
     *
     * This function must be called after {@link SetOutputFormat} but before {@link Prepare}.
     *
     * @param enableBFrame Indicates whether to enable B frame encoding for reduce file size.
     * The default value is false, which means B frame encoding cannot be enabled.
     * @return Returns {@link MSERR_OK} if the setting is successful; returns an error code otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetEnableBFrame(bool enableBFrame) = 0;

    /**
     * @brief Sets the encoder of the audio to transcoder.
     *
     * If this function is not called, the output file does not contain the audio track.
     * This function must be called after {@link SetOutputFormat} but before {@link Prepare}.
     *
     * @param encoder Indicates the audio encoder to set.
     * @return Returns {@link MSERR_OK} if the setting is successful; returns an error code otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetAudioEncoder(AudioCodecFormat encoder) = 0;

    /**
     * @brief Sets the encoding bit rate of the audio to transcoder.
     *
     * This function must be called after {@link SetOutputFormat} but before {@link Prepare}.
     *
     * @param bitRate Indicates the audio encoding bit rate, in bit/s.
     * @return Returns {@link MSERR_OK} if the setting is successful; returns an error code otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetAudioEncodingBitRate(int32_t bitRate) = 0;

    /**
     * @brief Sets the file descriptor (FD) of the input file.
     *
     * @param fd Indicates the FD of the file.
     * @return Returns {@link MSERR_OK} if the setting is successful; returns an error code otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetInputFile(int32_t fd, int64_t offset, int64_t size) = 0;

    /**
     * @brief Sets the file descriptor (FD) of the output file.
     *
     * This function must be called after {@link SetOutputFormat} but before {@link Prepare}
     *
     * @param fd Indicates the FD of the file.
     * @return Returns {@link MSERR_OK} if the setting is successful; returns an error code otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetOutputFile(int32_t fd) = 0;

    /**
     * @brief Registers a transcodering listener.
     *
     * This function must be called after {@link SetOutputFormat} but before {@link Prepare}
     *
     * @param callback Indicates the transcodering listener to register. For details, see {@link TransCoderCallback}.
     * @return Returns {@link MSERR_OK} if the setting is successful; returns an error code otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t SetTransCoderCallback(const std::shared_ptr<TransCoderCallback> &callback) = 0;

    /**
     * @brief Prepares for transcodering.
     *
     * This function must be called before {@link Start}.
     *
     * @return Returns {@link MSERR_OK} if the preparation is successful; returns an error code otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t Prepare() = 0;

    /**
     * @brief Starts transcodering.
     *
     * This function must be called after {@link Prepare}.
     *
     * @return Returns {@link MSERR_OK} if the transcodering is started; returns an error code otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t Start() = 0;

    /**
     * @brief Pauses transcodering.
     *
     * After {@link Start} is called, you can call this function to pause transcodering.
     *
     * @return Returns {@link MSERR_OK} if the transcodering is paused; returns an error code otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t Pause() = 0;

    /**
    * @brief Resumes transcodering.
    *
    * You can call this function to resume transcodering after {@link Pause} is called.
     *
     * @return Returns {@link MSERR_OK} if the transcodering is resumed; returns an error code otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t Resume() = 0;

    /**
     * @brief Cancel transcodering.
     *
     * @param block Indicates the stop mode. The value <b>true</b> indicates that the processing stops after all caches
     * are processed, and <b>false</b> indicates that the processing stops immediately and all caches are discarded.
     * After the transcodering stopped, all sources and parameters must be set again to restore transcodering.
     * The function is like to {@link Reset}, except that the block parameter is allowed to be specified.
     * @return Returns {@link MSERR_OK} if the transcodering is stopped; returns an error code otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t Cancel() = 0;

    /**
     * @brief Releases transcodering resources. After this function called, none of interfaces of {@link Transcoder}
     * can be used.
     *
     * @return Returns {@link MSERR_OK} if the transcodering is stopped; returns an error code otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t Release() = 0;
};

class __attribute__((visibility("default"))) TransCoderFactory {
public:
#ifdef UNSUPPORT_TRANSCODER
    static std::shared_ptr<TransCoder> CreateTransCoder()
    {
        return nullptr;
    }
#else
    static std::shared_ptr<TransCoder> CreateTransCoder();
#endif
private:
    TransCoderFactory() = default;
    ~TransCoderFactory() = default;
};
} // namespace Media
} // namespace OHOS
#endif // TRANSCODER_H
