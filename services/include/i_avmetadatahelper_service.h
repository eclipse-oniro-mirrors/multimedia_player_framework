/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef IAVMETADATAHELPER_SERVICE_H
#define IAVMETADATAHELPER_SERVICE_H

#include "avmetadatahelper.h"
#include "buffer/avsharedmemory.h"
#include "meta/meta.h"

namespace OHOS {
namespace Media {
struct OutputFrame {
public:
    OutputFrame(int32_t width, int32_t height, int32_t stride, int32_t bytesPerPixel)
        : width_(width),
          height_(height),
          stride_(stride),
          bytesPerPixel_(bytesPerPixel),
          size_(stride_ * height),  // interleaved layout
          rotation_(0)
    {
    }

    int32_t GetFlattenedSize() const
    {
        return sizeof(OutputFrame) + size_;
    }

    uint8_t *GetFlattenedData() const
    {
        return const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(this)) + sizeof(OutputFrame);
    }

    int32_t width_;
    int32_t height_;
    int32_t stride_;  // interleaved layout
    int32_t bytesPerPixel_;
    int32_t size_;
    int32_t rotation_;
};

struct OutputConfiguration {
    int32_t dstWidth = -1;
    int32_t dstHeight = -1;
    PixelFormat colorFormat = PixelFormat::RGB_565;

    bool operator==(const OutputConfiguration &other) const
    {
        return dstWidth == other.dstWidth && dstHeight == other.dstHeight && colorFormat == other.colorFormat;
    }
};

class IAVMetadataHelperService {
public:
    virtual ~IAVMetadataHelperService() = default;

    /**
     * @brief Method to set helper callback.
     *
     * @param callback object pointer.
     * @return Returns {@link MSERR_OK} if the helpercallback is set; returns an error code defined
     * in {@link media_errors.h} otherwise.
     */
    virtual int32_t SetHelperCallback(const std::shared_ptr<HelperCallback> &callback) = 0;

    /**
     * Set the media source uri to use. Calling this method before the reset
     * of the methods in this class. This method maybe time consuming.
     * @param uri the URI of input media source.
     * @param usage indicates which scene the avmedatahelper's instance will
     * be used to, see {@link AVMetadataUsage}. If the usage need to be changed,
     * this method must be called again.
     * @return Returns {@link MSERR_OK} if the setting is successful; returns
     * an error code otherwise.
     */
    virtual int32_t SetSource(const std::string &uri, int32_t usage) = 0;

    /**
     * @brief Sets the media file descriptor source to resolve. Calling this method
     * before the reset of the methods in this class. This method maybe time consuming.
     * @param fd Indicates the file descriptor of media source.
     * @param offset Indicates the offset of media source in file descriptor.
     * @param size Indicates the size of media source.
     * @param usage Indicates which scene the avmedatahelper's instance will
     * be used to, see {@link AVMetadataUsage}. If the usage need to be changed,
     * this method must be called again.
     * @return Returns {@link MSERR_OK} if the setting is successful; returns
     * an error code otherwise.
     */
    virtual int32_t SetSource(int32_t fd, int64_t offset, int64_t size, int32_t usage) = 0;

    /**
     * Sets the media data source to resolve.
     * @param dataSrc A data source instance with the fileSize and a callback {@link IMediaDataSource}.
     * @return Returns the status code.
     */
    virtual int32_t SetSource(const std::shared_ptr<IMediaDataSource> &dataSrc) = 0;

    /**
     * Retrieve the meta data associated with the specified key. This method can be
     * called after the SetSource.
     * @param key One of the constants listed above at the definition of {@link AVMetadataCode}.
     * @return Returns the meta data value associate with the given key code on
     * success; empty string on failure.
     */
    virtual std::string ResolveMetadata(int32_t key) = 0;

    /**
     * Fetch the album art picture associated with the data source. If there are
     * more than one pictures, the cover image will be returned preferably.
     * @return Returns the a chunk of shared memory containing a picture, which can be
     * null, if such a picture can not be fetched.
     */
    virtual std::shared_ptr<AVSharedMemory> FetchArtPicture() = 0;

    /**
     * Retrieve all meta data within the listed above at the definition of {@link AVMetadataCode}.
     * This method must be called after the SetSource.
     * @return Returns the meta data values on success; empty hash map on failure.
     */
    virtual std::unordered_map<int32_t, std::string> ResolveMetadata() = 0;

    /**
     * get all avmetadata.
     * This method must be called after the SetSource.
     * @return Returns the meta data values on success; nullptr on failure.
     */
    virtual std::shared_ptr<Meta> GetAVMetadata() = 0;

    /**
     * Fetch a representative video frame near a given timestamp by considering the given
     * option if possible, and return a video frame with given parameters. This method must be
     * called after the SetSource.
     * @param timeMs The time position in microseconds where the frame will be fetched.
     * When fetching the frame at the given time position, there is no guarantee that
     * the video source has a frame located at the position. When this happens, a frame
     * nearby will be returned. If timeUs is negative, time position and option will ignored,
     * and any frame that the implementation considers as representative may be returned.
     * @param option the hint about how to fetch a frame, see {@link AVMetadataQueryOption}
     * @param param the desired configuration of returned video frame, see {@link OutputConfiguration}.
     * @return Returns a chunk of shared memory containing a scaled video frame, which
     * can be null, if such a frame cannot be fetched.
     */
    virtual std::shared_ptr<AVSharedMemory> FetchFrameAtTime(
        int64_t timeUs, int32_t option, const OutputConfiguration &param) = 0;

    /**
     * Fetch a representative video frame near a given timestamp by considering the given
     * option if possible, and return a video frame with given parameters. This method must be
     * called after the SetSource.
     * @param timeMs The time position in microseconds where the frame will be fetched.
     * When fetching the frame at the given time position, there is no guarantee that
     * the video source has a frame located at the position. When this happens, a frame
     * nearby will be returned. If timeUs is negative, time position and option will ignored,
     * and any frame that the implementation considers as representative may be returned.
     * @param option the hint about how to fetch a frame, see {@link AVMetadataQueryOption}
     * @param param the desired configuration of returned video frame, see {@link OutputConfiguration}.
     * @return Returns a chunk of shared memory containing a scaled video frame, which
     * can be null, if such a frame cannot be fetched.
     */
    virtual std::shared_ptr<AVBuffer> FetchFrameYuv(
        int64_t timeUs, int32_t option, const OutputConfiguration &param) = 0;

    /**
     * Release the internel resource. After this method called, the service instance
     * can not be used again.
     */
    virtual void Release() = 0;

    /**
     * Get timestamp according to frame index.
     * @param timeUs : Index of the frame.
     * @returns returns time
     */
    virtual int32_t GetTimeByFrameIndex(uint32_t index, int64_t &time) = 0;

    /**
     * Get frame index according to the given timestamp.
     * @param timeUs : Timestamp of the frame, in microseconds.
     * @returns Returns frame
     */
    virtual int32_t GetFrameIndexByTime(int64_t time, uint32_t &index) = 0;
};
}  // namespace Media
}  // namespace OHOS

#endif