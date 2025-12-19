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

/**
 * @addtogroup AVMetadataExtractor
 * @{
 *
 * @brief Provides APIs of metadata capability for Media Source.
 *
 * @syscap SystemCapability.Multimedia.Media.AVMetadataExtractor
 * @since 16
 */

/**
 * @file avmetadata_extractor.h
 *
 * @brief Defines the avmetadata extractor APIs. Uses the Native APIs provided by Media AVMetadataExtractor
 *        to get metadata from the media source.
 *
 * @kit MediaKit
 * @library libavmetadata_extractor.so
 * @since 16
 */

#ifndef MULTIMEDIA_PLAYER_FRAMEWORK_NATIVE_AVMETADATA_EXTRACTOR_H
#define MULTIMEDIA_PLAYER_FRAMEWORK_NATIVE_AVMETADATA_EXTRACTOR_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "native_averrors.h"
#include "avmetadata_extractor_base.h"
#include "native_avcodec_base.h"
#include "native_avformat.h"
#include "pixelmap_native.h"
#include "avmedia_source.h"
#include "avmedia_base.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Define OH_AVMetadataExtractor field.
 *
 * @syscap SystemCapability.Multimedia.Media.AVMetadataExtractor
 * @since 16
 */
typedef struct OH_AVMetadataExtractor OH_AVMetadataExtractor;

/**
 * @brief Create a pixel map params instance.
 * @return Returns a pointer to an OH_AVMetadataExtractor_OutputParam instance for success, nullptr for failure.
 *         Possible failure causes: memory allocation failed.
 * @since 23
 */
OH_AVMetadataExtractor_OutputParam* OH_AVMetadataExtractor_OutputParam_Create();

/**
 * @brief Destroy the pixel map params object and release its resources.
 *
 * @param params Pointer to an OH_AVMetadataExtractor_OutputParam instance.
 * @return Function result code.
 *         {@link AV_ERR_OK} if the execution is successful.
 *         {@link AV_ERR_INVALID_VAL} if input params is nullptr.
 * @since 23
 */
OH_AVErrCode OH_AVMetadataExtractor_OutputParam_Destroy(OH_AVMetadataExtractor_OutputParam* outputParam);

/**
 * @brief Set the desired output size for the fetched frame.
 * @param params Pointer to an OH_AVMetadataExtractor_OutputParam instance.
 * @param width The desired width of the output frame.
 *              If width is less than 0, the original width will be used.
 *              If width is equal to 0, the width will be used scaled by height.
 * @param height The desired height of the output frame.
 *               If height is less than 0, the original height will be used.
 *               If height is equal to 0, the height will be used scaled by width.
 * @return T success, F failure.
 * @since 23
 */
bool OH_AVMetadataExtractor_OutputParam_SetSize(OH_AVMetadataExtractor_OutputParam* outputParam,
    int32_t width, int32_t height);

/**
 * @brief Fetch a frame at the specified time from the video source.
 *        This function must be called after {@link OH_AVMetadataExtractor_SetFDSource}.
 * @param extractor Pointer to an OH_AVMetadataExtractor instance.
 * @param timeUs The time position where the frame is to be retrieved, in microseconds.
 * @param options The query option that defines the relationship between the given time and a frame.
 *                For details, see {@link OH_AVMedia_SeekMode}.
 * @param outputParams Pointer to an OH_AVMetadataExtractor_OutputParam instance that specifies output parameters.
 * @param pixelMap The fetched frame from the video source. For details, see {@link OH_PixelmapNative}.
 * @return Function result code.
 *         {@link AV_ERR_OK} if the execution is successful.
 *         {@link AV_ERR_INVALID_VAL} if input extractor is nullptr or input param is invalid.
 *         {@link AV_ERR_OPERATE_NOT_PERMIT} if operation not allowed.
 *         {@link AV_ERR_UNSUPPORTED_FORMAT} if format is unsupported.
 *         {@link AV_ERR_NO_MEMORY} if internal memory allocation failed.
 *         {@link AV_ERR_IO_CLEARTEXT_NOT_PERMITTED} if http cleartext traffic is not permitted.
 * @since 23
 */
OH_AVErrCode OH_AVMetadataExtractor_FetchFrameByTime(OH_AVMetadataExtractor* extractor, int64_t timeUs,
    OH_AVMedia_SeekMode queryOption, const OH_AVMetadataExtractor_OutputParam* outputParam,
    OH_PixelmapNative** pixelMap);

typedef void (*OH_AVMetadataExtractor_OnFrameFetched)(OH_AVMetadataExtractor* extractor,
    const OH_AVMetadataExtractor_FrameInfo* frameInfo, OH_AVErrCode code, void* userData);

/**
 * @brief Fetch multiple frames at specified times from the video source.
 *        This function must be called after {@link OH_AVMetadataExtractor_SetFDSource}.
 *        Frames are fetched according to the given query option for each time point, and results are
 *        returned asynchronously via the provided callback.
 * @param extractor Pointer to an OH_AVMetadataExtractor instance.
 * @param timeUs Pointer to an array of time positions (in microseconds) where frames are to be retrieved.
 *               Must not be nullptr when timesLen > 0.
 * @param timesUsSize The number of time points in the timeUs array.
 * @param queryOption The query option that defines the relationship between each given time and a frame.
 *                For details, see {@link OH_AVMedia_SeekMode}.
 * @param outputParam Pointer to an OH_AVMetadataExtractor_OutputParam instance that specifies output parameters
 *                     for the fetched frames (such as desired size and pixel format). Can be nullptr to use defaults.
 * @param onFrameInfoCallback Callback invoked for each fetched result. For details, see
 *           {@link OH_AVMetadataExtractor_OnFrameFetched}. Must not be nullptr.
 * @param userData User-defined data pointer passed through to the callback. Can be nullptr.
 * @return Function result code.
 *         {@link AV_ERR_OK} if the execution is successful.
 *         {@link AV_ERR_INVALID_VAL} if input extractor is nullptr or input param is invalid.
 *         {@link AV_ERR_SERVICE_DIED} if media service died.
 *         {@link AV_ERR_IO_CLEARTEXT_NOT_PERMITTED} http cleartext traffic is not permitted.
 *         {@link AV_ERR_OPERATE_NOT_PERMIT} if operation not allowed.
 *         {@link AV_ERR_UNSUPPORTED_FORMAT} if format is unsupported.
 *         {@link AV_ERR_TIMEOUT} if http cleartext traffic is not permitted.
 * @since 23
 */
OH_AVErrCode OH_AVMetadataExtractor_FetchFramesByTimes(OH_AVMetadataExtractor* extractor, int64_t timeUs[],
    uint16_t timesUsSize, OH_AVMedia_SeekMode queryOption, const OH_AVMetadataExtractor_OutputParam* outputParam,
    OH_AVMetadataExtractor_OnFrameFetched onFrameInfoCallback, void* userData);

/**
 * @brief Cancel all pending or ongoing frame fetch requests initiated by
 *        {@link OH_AVMetadataExtractor_FetchFramesByTimes}.
 *        This function must be called after {@link OH_AVMetadataExtractor_SetFDSource}.
 * @param extractor Pointer to an OH_AVMetadataExtractor instance.
 * @note After cancellation, callbacks for the cancelled requests may still be invoked
 *       with status {@link OH_AVMetadataExtractor_FetchStatus::CANCELLED}, depending on timing.
 * @since 23
 */
void OH_AVMetadataExtractor_CancelAllFetchFrames(OH_AVMetadataExtractor* extractor);

/**
 * @brief Get the track description information from the media source.
 *        This function must be called after {@link OH_AVMetadataExtractor_SetFDSource}.
 * @param extractor Pointer to an OH_AVMetadataExtractor instance.
 * @param index The index of the track description to retrieve.
 * @return Returns a pointer to an OH_AVFormat instance containing track description for success, nullptr for failure.
 *         Possible failure causes: extractor is nullptr, no source set, or format is unsupported.
 * @since 23
 */
OH_AVFormat *OH_AVMetadataExtractor_GetTrackDescription(OH_AVMetadataExtractor *extractor, uint32_t index);

/**
 * @brief Get the custom information from the media source.
 *        This function must be called after {@link OH_AVMetadataExtractor_SetFDSource}.
 * @param extractor Pointer to an OH_AVMetadataExtractor instance.
 * @return Returns a pointer to an OH_AVFormat instance containing custom metadata for success, nullptr for failure.
 *         Possible failure causes: extractor is nullptr, no source set, or custom info not found.
 * @since 23
 */
OH_AVFormat *OH_AVMetadataExtractor_GetCustomInfo(OH_AVMetadataExtractor *extractor);

/**
 * @brief Get the custom information from the media source.
 *        This function must be called after {@link OH_AVMetadataExtractor_SetFDSource}.
 * @param extractor Pointer to an OH_AVMetadataExtractor instance.
 * @param source The media source to set for the extractor.
 * @return Function result code.
 *         {@link AV_ERR_OK} if the execution is successful.
 *         {@link AV_ERR_INVALID_VAL} if input extractor is nullptr or input source is invalid.
 * @since 23
 */
OH_AVErrCode OH_AVMetadataExtractor_SetMediaSource(OH_AVMetadataExtractor *extractor, OH_AVMediaSource *source);

/**
 * @brief Create a metadata extractor.
 *
 * @syscap SystemCapability.Multimedia.Media.AVMetadataExtractor
 * @return Returns a pointer to an OH_AVMetadataExtractor instance for success, nullptr for failure
 * Possible failure causes: failed to HstEngineFactory::CreateAVMetadataHelperEngine.
 * @since 16
 */
OH_AVMetadataExtractor* OH_AVMetadataExtractor_Create(void);

/**
 * @brief Sets the media file descriptor source for the metadata extractor.
 *
 * @syscap SystemCapability.Multimedia.Media.AVMetadataExtractor
 * @param extractor Pointer to an OH_AVMetadataExtractor instance.
 * @param fd Indicates the file descriptor of media source.
 * @param offset Indicates the offset of media source in file descriptor.
 * @param size Indicates the size of media source.
 * @return Function result code.
 *         {@link AV_ERR_OK} if the execution is successful.
 *         {@link AV_ERR_INVALID_VAL} if input extractor is nullptr or input param is invalid.
 *         {@link AV_ERR_OPERATE_NOT_PERMIT} if operation not allowed.
 *         {@link AV_ERR_NO_MEMORY} if internal memory allocation failed.
 * @since 16
 */
OH_AVErrCode OH_AVMetadataExtractor_SetFDSource(OH_AVMetadataExtractor* extractor,
    int32_t fd, int64_t offset, int64_t size);

/**
 * @brief Extract metadata info from the media source.
 *        This function must be called after {@link SetFDSource}.
 *
 * @syscap SystemCapability.Multimedia.Media.AVMetadataExtractor
 * @param extractor Pointer to an OH_AVMetadataExtractor instance.
 * @param avMetadata Pointer to an {@link OH_AVFormat} instance, its content contains the fetched metadata info.
 * @return Function result code.
 *         {@link AV_ERR_OK} if the execution is successful.
 *         {@link AV_ERR_INVALID_VAL} if input extractor is nullptr or input param is invalid.
 *         {@link AV_ERR_OPERATE_NOT_PERMIT} if operation not allowed.
 *         {@link AV_ERR_UNSUPPORTED_FORMAT} if format is unsupported.
 *         {@link AV_ERR_NO_MEMORY} if internal memory allocation failed.
 * @since 16
 */
OH_AVErrCode OH_AVMetadataExtractor_FetchMetadata(OH_AVMetadataExtractor* extractor, OH_AVFormat* avMetadata);

/**
 * @brief Fetch album cover from the audio source.
 *        This function must be called after {@link SetFDSource}.
 *
 * @syscap SystemCapability.Multimedia.Media.AVMetadataExtractor
 * @param extractor Pointer to an OH_AVMetadataExtractor instance.
 * @param pixelMap The fetched album cover from the audio source. For details, see {@link OH_PixelmapNative}.
 * @return Function result code.
 *         {@link AV_ERR_OK} if the execution is successful.
 *         {@link AV_ERR_INVALID_VAL} if input extractor is nullptr or input param is invalid.
 *         {@link AV_ERR_OPERATE_NOT_PERMIT} if operation not allowed.
 *         {@link AV_ERR_UNSUPPORTED_FORMAT} if format is unsupported.
 *         {@link AV_ERR_NO_MEMORY} if internal memory allocation failed.
 * @since 16
 */
OH_AVErrCode OH_AVMetadataExtractor_FetchAlbumCover(OH_AVMetadataExtractor* extractor, OH_PixelmapNative** pixelMap);

/**
 * @brief Release the resource used for AVMetadataExtractor.
 *
 * @syscap SystemCapability.Multimedia.Media.AVMetadataExtractor
 * @param extractor Pointer to an OH_AVMetadataExtractor instance.
 * @return Function result code.
 *         {@link AV_ERR_OK} if the execution is successful.
 *         {@link AV_ERR_INVALID_VAL} if input extractor is nullptr or input param is invalid.
 * @since 16
 */
OH_AVErrCode OH_AVMetadataExtractor_Release(OH_AVMetadataExtractor* extractor);

#ifdef __cplusplus
}
#endif

#endif // MULTIMEDIA_PLAYER_FRAMEWORK_NATIVE_AVMETADATA_EXTRACTOR_H