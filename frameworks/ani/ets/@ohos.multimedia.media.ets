/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { AsyncCallback, Callback, BusinessError } from '@ohos.base';
import image from '@ohos.multimedia.image';
import audio from '@ohos.multimedia.audio';

type RejectString = (e: BusinessError<string>) => void;

function businessError<T = void>(c: number, d?: string): BusinessError<T> {
  let err: BusinessError<T> = new BusinessError<T>();
  err.code = c;
  err.message = d ? d : "";
  return err;
}

class MediaAniError extends Error {
  code: number;
  constructor(code: number, message: string) {
    super('MediaAniError', message, undefined);
    this.code = code;
  }
}

function isNullish(d: NullishType): boolean {
  return (d === null || d === undefined) ? true : false;
}

export namespace media {
  loadLibrary("media_ani");

  enum StateChangeReason {
    USER = 1,
    BACKGROUND = 2,
  }

  enum VideoScaleType {
    VIDEO_SCALE_TYPE_FIT = 0,
    VIDEO_SCALE_TYPE_FIT_CROP = 1,
  }

  type AVPlayerState = 'idle' | 'initialized' | 'prepared' | 'playing' | 'paused' | 'completed' | 'stopped' | 'released' | 'error';
  type OnAVPlayerStateChangeHandle = (state: AVPlayerState, reason: StateChangeReason) => void;

  export native function createAVPlayerAsync(): AVPlayer;
  export function createAVPlayer(): Promise<AVPlayer> {
    return new Promise<AVPlayer>((resolve: (v: AVPlayer) => void, reject: RejectString) => {
      let cb = (): AVPlayer | MediaAniError => {
        try {
          return media.createAVPlayerAsync();
        } catch(e) {
          return e as MediaAniError;
        }
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaAniError) {
          let err = ret as MediaAniError;
          reject(businessError<string>(err.code, err.message));
        } else {
          if (isNullish(ret)) {
            reject(businessError<string>(-1, "Operation failed"));
          } else {
            resolve(ret as AVPlayer);
          }
        }
      });
    });
  }

  export function createAVPlayer(callback: AsyncCallback<AVPlayer | undefined>): void {
    let cb = (): MediaAniError | AVPlayer => {
      try {
        return media.createAVPlayerAsync();
      } catch(e) {
        return e as MediaAniError;
      }
    }
    taskpool.execute(cb).then((ret: NullishType): void => {
      if (ret instanceof MediaAniError) {
      let err = ret as MediaAniError;
        callback(businessError(err.code, err.message), undefined);
      } else {
        if (isNullish(ret)) {
          callback(businessError(-1, "Operation failed"), undefined);
        } else {
          callback(businessError(0), ret as AVPlayer);
        }
      }
    });
  }

  export native function createAVImageGeneratorAsync(): AVImageGenerator;
  export function createAVImageGenerator(): Promise<AVImageGenerator> {
    return new Promise<AVImageGenerator>((resolve: (v: AVImageGenerator) => void, reject: RejectString) => {
      let cb = (): AVImageGenerator | MediaAniError => {
        try {
          return media.createAVImageGeneratorAsync();
        } catch(e) {
          return e as MediaAniError;
        }
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaAniError) {
          let err = ret as MediaAniError;
          reject(businessError<string>(err.code, err.message));
        } else {
          if (isNullish(ret)) {
            reject(businessError<string>(-1, "Operation failed"));
          } else {
            resolve(ret as AVImageGenerator);
          }
        }
      });
    });
  }
  
  export function createAVImageGenerator(callback: AsyncCallback<AVImageGenerator | undefined>): void {
     let cb = (): MediaAniError | AVImageGenerator => {
      try {
        return media.createAVImageGeneratorAsync();
      } catch(e) {
        return e as MediaAniError;
      }
    }
    taskpool.execute(cb).then((ret: NullishType): void => {
      if (ret instanceof MediaAniError) {
      let err = ret as MediaAniError;
        callback(businessError(err.code, err.message), undefined);
      } else {
        if (isNullish(ret)) {
          callback(businessError(-1, "Operation failed"), undefined);
        } else {
          callback(businessError(0), ret as AVImageGenerator);
        }
      }
    });
  }

  export interface PixelMapParams {
    width: number;
    height: number;
    colorFormat?: PixelFormat;
  }

  class ParamsInner implements PixelMapParams {
    width: number = 3;
    height: number = 1;
    colorFormat: PixelFormat | undefined;
  }

  export enum AVImageQueryOptions {
    AV_IMAGE_QUERY_NEXT_SYNC,
    AV_IMAGE_QUERY_PREVIOUS_SYNC,
    AV_IMAGE_QUERY_CLOSEST_SYNC,
    AV_IMAGE_QUERY_CLOSEST,
  }

  export enum PixelFormat {
    RGB_565 = 2,
    RGBA_8888 = 3,
    RGB_888 = 5,
  }

  export enum PlaybackSpeed {
    SPEED_FORWARD_0_75_X = 0,
    SPEED_FORWARD_1_00_X = 1,
    SPEED_FORWARD_1_25_X = 2,
    SPEED_FORWARD_1_75_X = 3,
    SPEED_FORWARD_2_00_X = 4,
    SPEED_FORWARD_0_50_X = 5,
    SPEED_FORWARD_1_50_X = 6,
    SPEED_FORWARD_3_00_X = 7,
    SPEED_FORWARD_0_25_X = 8,
    SPEED_FORWARD_0_125_X = 9,
  }

  export enum SeekMode {
    SEEK_NEXT_SYNC = 0,
    SEEK_PREV_SYNC = 1,
    SEEK_CLOSEST = 2,
    SEEK_CONTINUOUS = 3,
  }

  export enum MediaType {
    MEDIA_TYPE_AUD = 0,
    MEDIA_TYPE_VID = 1,
    MEDIA_TYPE_SUBTITLE = 2,
  }

  export enum MediaDescriptionKey {
    MD_KEY_BITRATE = 'bitrate',
    MD_KEY_FRAME_RATE = 'frame_rate',
  }

  export enum BufferingInfoType {
    BUFFERING_START = 1,
    BUFFERING_END = 2,
    BUFFERING_PERCENT = 3,
    CACHED_DURATION = 4,
  }

  export enum AudioEncoder {
    DEFAULT = 0,
    AMR_NB = 1,
    AMR_WB = 2,
    AAC_LC = 3,
    HE_AAC = 4
  }

  export enum AudioOutputFormat {
    DEFAULT = 0,
    MPEG_4 = 2,
    AMR_NB = 3,
    AMR_WB = 4,
    AAC_ADTS = 6
  }

  export enum AudioSourceType {
    AUDIO_SOURCE_TYPE_DEFAULT = 0,
    AUDIO_SOURCE_TYPE_MIC = 1,
    AUDIO_SOURCE_TYPE_VOICE_RECOGNITION = 2,
    AUDIO_SOURCE_TYPE_VOICE_COMMUNICATION = 7,
    AUDIO_SOURCE_TYPE_VOICE_MESSAGE = 10,
    AUDIO_SOURCE_TYPE_CAMCORDER = 13,
  }

  export enum CodecMimeType {
    VIDEO_H263 = 'video/h263',
    VIDEO_AVC = 'video/avc',
    VIDEO_MPEG2 = 'video/mpeg2',
    VIDEO_MPEG4 = 'video/mp4v-es',
    VIDEO_VP8 = 'video/x-vnd.on2.vp8',
    AUDIO_AAC = 'audio/mp4a-latm',
    AUDIO_VORBIS = 'audio/vorbis',
    AUDIO_FLAC = 'audio/flac',
    VIDEO_HEVC = 'video/hevc',
    AUDIO_MP3 = 'audio/mpeg',
    AUDIO_G711MU = 'audio/g711mu',
    AUDIO_AMR_NB = 'audio/3gpp',
    AUDIO_AMR_WB = 'audio/amr-wb',
  }

  export enum ContainerFormatType {
    CFT_MPEG_4 = 'mp4',
    CFT_MPEG_4A = 'm4a',
    CFT_MP3 = 'mp3',
    CFT_WAV = 'wav',
    CFT_AMR = 'amr',
  }

  export enum FileGenerationMode {
    APP_CREATE = 0,
    AUTO_CREATE_CAMERA_SCENE = 1,
  }

  export enum HdrType {
    AV_HDR_TYPE_NONE = 0,
    AV_HDR_TYPE_VIVID = 1,
  }

  export enum SwitchMode {
    SMOOTH = 0,
    SEGMENT = 1,
    CLOSEST = 2,
  }

  export enum VideoSourceType {
    VIDEO_SOURCE_TYPE_SURFACE_YUV = 0,
    VIDEO_SOURCE_TYPE_SURFACE_ES = 1,
  }

  type MediaDescription = Record<string, Object>;
  interface AVFileDescriptor {
    fd: number
    offset?: number
    length?: number
  }

  class AVFileDescriptorHandle implements AVFileDescriptor {
    fd: number = 0;
    offset?: number = 0;
    length?: number = -1;
  }

  export interface AVDataSrcDescriptor {
    fileSize: number;
    callback: (buffer: ArrayBuffer, length: number, pos?: number) => number;
  }

  class AVDataSrcDescriptorHandle implements AVDataSrcDescriptor {
    fileSize: number = 0;
    callback: (buffer: ArrayBuffer, length: number, pos?: number) => number;
  }

  export interface AVPlayer {
    url?: string;
    surfaceId?: string;
    readonly state: AVPlayerState;
    dataSrc?: AVDataSrcDescriptor;
    audioInterruptMode?: audio.InterruptMode;
    loop: boolean;
    readonly currentTime: number;
    readonly duration: number;
    videoScaleType?: VideoScaleType;
    audioRendererInfo?: audio.AudioRendererInfo;
    prepare(callback: AsyncCallback<void>): void;
    prepare(): Promise<void>;
    pause(callback: AsyncCallback<void>): void;
    pause(): Promise<void>;
    play(callback: AsyncCallback<void>): void;
    play(): Promise<void>;
    reset(callback: AsyncCallback<void>): void;
    reset(): Promise<void>;
    stop(): Promise<void>;
    stop(callback: AsyncCallback<void>): void;
    seek(timeMs: number, mode?: SeekMode): void;
    setVolume(volume: number): void;
    setSpeed(speed: PlaybackSpeed): void;
    on(type: 'stateChange', callback: OnAVPlayerStateChangeHandle): void;
    off(type: 'stateChange', callback: OnAVPlayerStateChangeHandle): void;
    getTrackDescription(callback: AsyncCallback<Array<MediaDescription> | undefined>): void;
    getTrackDescription(): Promise<Array<MediaDescription>>;
  }

  class AVPlayerHandle implements AVPlayer {
    private nativeAVPlayer: long = 0;
    set url(url?: string) {
      this.setUrl(url);
      return;
    }
    override get url(): string {
      return this.getUrl();
    }
    set surfaceId(surfaceId?: string) {
      this.setSurfaceId(surfaceId);
      return;
    }
    override get surfaceId(): string {
      return this.getSurfaceId();
    }
    override get state(): AVPlayerState {
      return this.getstate();
    }
    set dataSrc(des?: AVDataSrcDescriptor) {
      let arrayBuffer: ArrayBuffer = new ArrayBuffer(1024);
      des!.callback(arrayBuffer, 0)
      this.setDataSrc(des);
      return;
    }
    override get dataSrc(): AVDataSrcDescriptor {
      return this.getDataSrc();
    }
    set audioInterruptMode(mode?: audio.InterruptMode) {
      this.setAudioInterruptMode(mode);
      return;
    }
    override get audioInterruptMode(): audio.InterruptMode {
      return this.getAudioInterruptMode();
    }
    set loop(isLoop: boolean) {
      this.setLoop(isLoop);
      return;
    }
    override get loop(): boolean {
      return this.getLoop();
    }
    override get currentTime(): number {
      return this.getCurrentTime();
    }
    override get duration(): number {
      return this.getDuration();
    }
    override set videoScaleType(type?: VideoScaleType) {
      this.setVideoScaleType(type);
      return;
    }
    override get videoScaleType(): VideoScaleType {
      return this.getVideoScaleType(); 
    }
    override set audioRendererInfo(info?: audio.AudioRendererInfo) {
      this.setAudioRendererInfo(info);
      return;
    }
    override get audioRendererInfo(): audio.AudioRendererInfo {
      return this.getAudioRendererInfo();
    }
    constructor(context:long) {
      if(this.nativeAVPlayer == 0){
        this.nativeAVPlayer = context;
      }
    }
    native setUrl(url?: string): void;
    native getUrl(): string;
    native setSurfaceId(surfaceId?: string): void;
    native getSurfaceId(): string;
    native getstate(): AVPlayerState;
    native setDataSrc(des?: AVDataSrcDescriptor): void;
    native getDataSrc(): AVDataSrcDescriptor;
    native setAudioInterruptMode(mode?: audio.InterruptMode): void;
    native getAudioInterruptMode(): audio.InterruptMode;
    native setLoop(isLoop: boolean): void;
    native getLoop(): boolean;
    native getCurrentTime(): number;
    native getDuration(): number;
    native setVideoScaleType(type?: VideoScaleType): void;
    native getVideoScaleType(): VideoScaleType;
    native setAudioRendererInfo(info?: audio.AudioRendererInfo): void;
    native getAudioRendererInfo(): audio.AudioRendererInfo;
    native setSpeed(speed:PlaybackSpeed): void;
    native setVolume(volume: number): void;
    native seekmode(timeMs: number, mode: SeekMode): void;
    native seekWithoutmode(timeMs: number): void;
    seek(timeMs: number, mode?: SeekMode): void {
      if (mode !== undefined) {
        return this.seekmode(timeMs, mode);
      } else {
        return this.seekWithoutmode(timeMs);
      }
    }

    native prepareSync(): void;
    prepare(): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: RejectString):void => {
        let cb = (): MediaAniError | undefined => {
        try {
          this.prepareSync();
          return undefined;
        } catch(e) {
          return e as MediaAniError;
        }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
        if (isNullish(ret)) {
          resolve(undefined);
        } else {
          let err = ret as MediaAniError;
          reject(businessError<string>(err.code, err.message));
        }
        });
      });
    }

    prepare(callback: AsyncCallback<void>): void {
      let cb = (): MediaAniError | undefined => {
        try{
          this.prepareSync();
          return undefined;
        } catch(e) {
          return e as MediaAniError;
        }
      }
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaAniError) {
        let err = ret as MediaAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1, "Operation failed"), undefined);
          } else {
            callback(businessError(0), undefined);
          }
        }
      });
    }

    native pauseSync(): void;
    pause(): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: RejectString):void => {
        let cb = (): MediaAniError | undefined => {
        try {
          this.pauseSync();
          return undefined;
        } catch(e) {
          return e as MediaAniError;
        }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
        if (isNullish(ret)) {
          resolve(undefined);
        } else {
          let err = ret as MediaAniError;
          reject(businessError<string>(err.code, err.message));
        }
        });
      });
    }

    pause(callback: AsyncCallback<void>): void {
      let cb = (): MediaAniError | undefined => {
        try{
          this.pauseSync();
          return undefined;
        } catch(e) {
          return e as MediaAniError;
        }
      }
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaAniError) {
        let err = ret as MediaAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1, "Operation failed"), undefined);
          } else {
            callback(businessError(0), undefined);
          }
        }
      });
    }

    native playSync(): void;
    play(): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: RejectString):void => {
        let cb = (): MediaAniError | undefined => {
        try {
          this.playSync();
          return undefined;
        } catch(e) {
          return e as MediaAniError;
        }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
        if (isNullish(ret)) {
          resolve(undefined);
        } else {
          let err = ret as MediaAniError;
          reject(businessError<string>(err.code, err.message));
        }
        });
      });
    }

    play(callback: AsyncCallback<void>):void {
      let cb = (): MediaAniError | undefined => {
        try{
          this.playSync();
          return undefined;
        } catch(e) {
          return e as MediaAniError;
        }
      }
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaAniError) {
        let err = ret as MediaAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1, "Operation failed"), undefined);
          } else {
            callback(businessError(0), undefined);
          }
        }
      });
    }

    native resetSync():void;
    reset(): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: RejectString):void => {
        let cb = (): MediaAniError | undefined => {
        try {
          this.resetSync();
          return undefined;
        } catch(e) {
          return e as MediaAniError;
        }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
        if (isNullish(ret)) {
          resolve(undefined);
        } else {
          let err = ret as MediaAniError;
          reject(businessError<string>(err.code, err.message));
        }
        });
      });
    }

    reset(callback: AsyncCallback<void>): void {
       let cb = (): MediaAniError | undefined => {
        try{
          this.resetSync();
          return undefined;
        } catch(e) {
          return e as MediaAniError;
        }
      }
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaAniError) {
        let err = ret as MediaAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1, "Operation failed"), undefined);
          } else {
            callback(businessError(0), undefined);
          }
        }
      });
    }

    native stopSync(): void;
    stop(): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: RejectString):void => {
        let cb = (): MediaAniError | undefined => {
        try {
          this.stopSync();
          return undefined;
        } catch(e) {
          return e as MediaAniError;
        }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
        if (isNullish(ret)) {
          resolve(undefined);
        } else {
          let err = ret as MediaAniError;
          reject(businessError<string>(err.code, err.message));
        }
        });
      });
    }

    stop(callback: AsyncCallback<void>): void {
      let cb = (): MediaAniError | undefined => {
        try{
          this.stopSync();
          return undefined;
        } catch(e) {
          return e as MediaAniError;
        }
      }
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaAniError) {
        let err = ret as MediaAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1, "Operation failed"), undefined);
          } else {
            callback(businessError(0), undefined);
          }
        }
      });
    }

    native getTrackDescriptionSync(): Array<MediaDescription>;
    getTrackDescription(callback: AsyncCallback<Array<MediaDescription> | undefined>): void {
      let cb = (): MediaAniError | Array<MediaDescription> => {
        try {
          return this.getTrackDescriptionSync();
        } catch(e) {
          return e as MediaAniError;
        }
      };
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaAniError) {
          let err = ret as MediaAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1, "Operation failed"), undefined);
          } else {
            callback(businessError(0), ret as Array<MediaDescription>);
          }
        }
      });
    }
    getTrackDescription(): Promise<Array<MediaDescription>> {
      return new Promise<Array<MediaDescription>>((resolve : (v: Array<MediaDescription>) => void, reject: RejectString) => {
        let cb = (): Array<MediaDescription> | MediaAniError => {
          try {
            return this.getTrackDescriptionSync();
          } catch(e) {
            return e as MediaAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaAniError) {
            let err = ret as MediaAniError;
            reject(businessError<string>(err.code, err.message));
          } else {
            if (isNullish(ret)) {
              reject(businessError<string>(-1, "Operation failed"));
            } else {
              resolve(ret as Array<MediaDescription>);
            }
          }
        });
      });
    }
    native on(type: 'stateChange', callback: OnAVPlayerStateChangeHandle): void;
    native off(type: 'stateChange', callback: OnAVPlayerStateChangeHandle): void;
  }
  export interface AVImageGenerator {
    fdSrc?: AVFileDescriptor;
    release(callback: AsyncCallback<void>): void;
    release(): Promise<void>;
    fetchFrameByTime(timeUs: number, options: AVImageQueryOptions, param: PixelMapParams,
      callback: AsyncCallback<image.PixelMap | undefined>): void;
    fetchFrameByTime(timeUs: number, options: AVImageQueryOptions, param: PixelMapParams): Promise<image.PixelMap>;
  }

  export class AVImageGeneratorHandle implements AVImageGenerator {
    private nativeAVImageGenerator: long = 0;
    constructor(context:long) {
      if (this.nativeAVImageGenerator == 0) {
        this.nativeAVImageGenerator = context;
      }
    }
    set fdSrc(des?: AVFileDescriptor) {
      this.setFdSrc(des);
      return;
    }
    override get fdSrc(): AVFileDescriptor {
      return this.getFdSrc();
    }
    native setFdSrc(des?: AVFileDescriptor): void;
    native getFdSrc(): AVFileDescriptor;
    native releaseAsync(): void;
    release(): Promise<void> {
      return new Promise<void>((resolve: (v: undefined) => void, reject: RejectString): void => {
        let cb = (): MediaAniError | undefined => {
        try {
          this.releaseAsync();
          return undefined;
        } catch(e) {
          return e as MediaAniError;
        }
        };
        taskpool.execute(cb).then((ret: MediaAniError): void => {
          if (isNullish(ret)) {
            resolve(undefined);
          } else {
            let err = ret as MediaAniError;
            reject(businessError<string>(err.code, err.message));
          }
        });
      });
    }
    release(callback: AsyncCallback<void>): void {
      let cb = (): MediaAniError | undefined => {
        try {
          this.releaseAsync();
          return undefined;
        } catch(e) {
          return e as MediaAniError;
        }
      }
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaAniError) {
        let err = ret as MediaAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1, "Operation failed"), undefined);
          } else {
            callback(businessError(0), undefined);
          }
        }
      });
    }

    native fetchFrameByTimeAsync(timeUs: number, options: AVImageQueryOptions, param: PixelMapParams): image.PixelMap;
    fetchFrameByTime(timeUs: number, options: AVImageQueryOptions, param: PixelMapParams): Promise<image.PixelMap> {
      return new Promise<image.PixelMap>((resolve: (v: image.PixelMap) => void, reject: RejectString) => {
        let cb = (): image.PixelMap | MediaAniError => {
          try {
            return this.fetchFrameByTimeAsync(timeUs, options, param);
          } catch(e) {
            return e as MediaAniError;
          }
        };
        taskpool.execute(cb).then((ret: NullishType): void => {
          if (ret instanceof MediaAniError) {
            let err = ret as MediaAniError;
            reject(businessError<string>(err.code, err.message));
          } else {
            if (isNullish(ret)) {
            reject(businessError<string>(-1, "Operation failed"));
            } else {
            resolve(ret as image.PixelMap);
            }
          }
        });
      });
    }
    
    fetchFrameByTime(timeUs: number, options: AVImageQueryOptions, param: PixelMapParams, callback: AsyncCallback<image.PixelMap | undefined>): void {
      let cb = (): MediaAniError | image.PixelMap => {
        try{
          return this.fetchFrameByTimeAsync(timeUs, options, param);
        } catch(e) {
          return e as MediaAniError;
        }
      }
      taskpool.execute(cb).then((ret: NullishType): void => {
        if (ret instanceof MediaAniError) {
        let err = ret as MediaAniError;
          callback(businessError(err.code, err.message), undefined);
        } else {
          if (isNullish(ret)) {
            callback(businessError(-1, "Operation failed"), undefined);
          } else {
            callback(businessError(0), ret as image.PixelMap);
          }
        }
      });
    }
  }
}