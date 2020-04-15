import * as core from "@actions/core";
import { HttpClient, HttpCodes } from "@actions/http-client";
import { BearerCredentialHandler } from "@actions/http-client/auth";
import {
    IHttpClientResponse,
    IRequestOptions,
    ITypedResponse
} from "@actions/http-client/interfaces";
import * as crypto from "crypto";
import * as fs from "fs";

import { Inputs } from "./constants";
import {
    ArtifactCacheEntry,
    CommitCacheRequest,
    ReserveCacheRequest,
    ReserveCacheResponse
} from "./contracts";
import * as utils from "./utils/actionUtils";

const versionSalt = "1.0";

function isSuccessStatusCode(statusCode?: number): boolean {
    if (!statusCode) {
        return false;
    }
    return statusCode >= 200 && statusCode < 300;
}

function isRetryableStatusCode(statusCode?: number): boolean {
    if (!statusCode) {
        return false;
    }
    const retryableStatusCodes = [
        HttpCodes.BadGateway,
        HttpCodes.ServiceUnavailable,
        HttpCodes.GatewayTimeout
    ];
    return retryableStatusCodes.includes(statusCode);
}

function getCacheApiUrl(resource: string): string {
    // Ideally we just use ACTIONS_CACHE_URL
    const baseUrl: string = (
        process.env["ACTIONS_CACHE_URL"] ||
        process.env["ACTIONS_RUNTIME_URL"] ||
        ""
    ).replace("pipelines", "artifactcache");
    if (!baseUrl) {
        throw new Error(
            "Cache Service Url not found, unable to restore cache."
        );
    }

    const url = `${baseUrl}_apis/artifactcache/${resource}`;
    core.debug(`Resource Url: ${url}`);
    return url;
}

function createAcceptHeader(type: string, apiVersion: string): string {
    return `${type};api-version=${apiVersion}`;
}

function getRequestOptions(): IRequestOptions {
    const requestOptions: IRequestOptions = {
        headers: {
            Accept: createAcceptHeader("application/json", "6.0-preview.1")
        },
    };

    return requestOptions;
}

function createHttpClient(): HttpClient {
    const token = process.env["ACTIONS_RUNTIME_TOKEN"] || "";
    const bearerCredentialHandler = new BearerCredentialHandler(token);

    return new HttpClient(
        "actions/cache",
        [bearerCredentialHandler],
        getRequestOptions()
    );
}

export function getCacheVersion(): string {
    // Add salt to cache version to support breaking changes in cache entry
    const components = [
        core.getInput(Inputs.Path, { required: true }),
        versionSalt
    ];

    return crypto
        .createHash("sha256")
        .update(components.join("|"))
        .digest("hex");
}

export async function getCacheEntry(
    keys: string[]
): Promise<ArtifactCacheEntry | null> {
    const httpClient = createHttpClient();
    const version = getCacheVersion();
    const resource = `cache?keys=${encodeURIComponent(
        keys.join(",")
    )}&version=${version}`;

    const response = await httpClient.getJson<ArtifactCacheEntry>(
        getCacheApiUrl(resource)
    );
    if (response.statusCode === 204) {
        return null;
    }
    if (!isSuccessStatusCode(response.statusCode)) {
        throw new Error(`Cache service responded with ${response.statusCode}`);
    }

    const cacheResult = response.result;
    const cacheDownloadUrl = cacheResult?.archiveLocation;
    if (!cacheDownloadUrl) {
        throw new Error("Cache not found.");
    }
    core.setSecret(cacheDownloadUrl);
    core.debug(`Cache Result:`);
    core.debug(JSON.stringify(cacheResult));

    return cacheResult;
}

function writeLog(stream: LoggingStream) {
    const currentTime: number = Date.now();
    const elapsedTime = currentTime - stream.startTime;
    const downloadSpeed = (stream.totalBytes / (1024 * 1024)) / (elapsedTime / 1000.0);

    core.debug(`${new Date()} - Received ${stream.intervalBytes}, Total: ${stream.totalBytes}, Speed: ${downloadSpeed.toFixed(2)} MB/s`);
    stream.intervalBytes = 0;

    //if (elapsedTime > 90000 || (elapsedTime > 5000 && downloadSpeed < 0.5)) {
    //    core.error(`Aborting download.`);
    //    stream.response.message.connection.end();
    //    stream.response.message.socket.end();
    //    stream.end();
    //}

    if (!stream.isFinished) {
        stream.timeoutHandle = setTimeout(writeLog, 1000, stream);
    }
}

export class LoggingStream implements NodeJS.WritableStream {
    public constructor(stream: NodeJS.WritableStream, response: IHttpClientResponse) {
        this.stream = stream;
        this.response = response;
        this.writable = stream.writable;
        this.intervalBytes = 0;
        this.totalBytes = 0;
        this.startTime = Date.now();
        this.isFinished = false;

        core.debug(`${this.startTime} - Starting`);

        this.timeoutHandle = setTimeout(writeLog, 1000, this);
    }

    intervalBytes: number;
    totalBytes: number;
    stream: NodeJS.WritableStream;
    response: IHttpClientResponse;
    writable: boolean;
    startTime: number;
    isFinished: boolean;
    timeoutHandle: number;

    write(buffer: string | Uint8Array, cb?: ((err?: Error | null | undefined) => void) | undefined): boolean;
    write(str: string, encoding?: string | undefined, cb?: ((err?: Error | null | undefined) => void) | undefined): boolean;
    write(str: any, encoding?: any, cb?: any) {
        this.intervalBytes += str.length;
        this.totalBytes += str.length;

        return this.stream.write(str, encoding, cb);
    }
    end(cb?: (() => void) | undefined): void;
    end(data: string | Uint8Array, cb?: (() => void) | undefined): void;
    end(str: string, encoding?: string | undefined, cb?: (() => void) | undefined): void;
    end(str?: any, encoding?: any, cb?: any) {
        if (str) {
            this.intervalBytes += str.length;
            this.totalBytes += str.length;
        }

        this.stream.end(str, encoding, cb);

        this.isFinished = true;
        clearTimeout(this.timeoutHandle)
        writeLog(this);
    }
    addListener(event: string | symbol, listener: (...args: any[]) => void): this {
        this.stream.addListener(event, listener);
        return this;
    }
    on(event: string | symbol, listener: (...args: any[]) => void): this {
        this.stream.on(event, listener);
        return this;
    }
    once(event: string | symbol, listener: (...args: any[]) => void): this {
        this.stream.once(event, listener);
        return this;
    }
    removeListener(event: string | symbol, listener: (...args: any[]) => void): this {
        this.stream.removeListener(event, listener);
        return this;
    }
    off(event: string | symbol, listener: (...args: any[]) => void): this {
        this.stream.off(event, listener);
        return this;
    }
    removeAllListeners(event?: string | symbol | undefined): this {
        this.stream.removeAllListeners(event);
        return this;
    }
    setMaxListeners(n: number): this {
        this.stream.setMaxListeners(n);
        return this;
    }
    getMaxListeners(): number {
        return this.stream.getMaxListeners();
    }
    listeners(event: string | symbol): Function[] {
        return this.stream.listeners(event);
    }
    rawListeners(event: string | symbol): Function[] {
        return this.stream.rawListeners(event);
    }
    emit(event: string | symbol, ...args: any[]): boolean {
        return this.stream.emit(event, args);
    }
    listenerCount(type: string | symbol): number {
        return this.stream.listenerCount(type);
    }
    prependListener(event: string | symbol, listener: (...args: any[]) => void): this {
        this.stream.prependListener(event, listener);
        return this;
    }
    prependOnceListener(event: string | symbol, listener: (...args: any[]) => void): this {
        this.stream.prependOnceListener(event, listener);
        return this;
    }
    eventNames(): (string | symbol)[] {
        return this.stream.eventNames();
    }

}

async function pipeResponseToStream(
    response: IHttpClientResponse,
    stream: NodeJS.WritableStream
): Promise<number> {
    return new Promise(resolve => {
        core.debug("Injecting Logging Stream (Timer)...");
        response.message.pipe(new LoggingStream(stream, response)).on("close", () => {
            var contentLength = -1;
            var contentLengthHeader = response.message.headers["content-length"];
            
            if (contentLengthHeader) {
                contentLength = parseInt(contentLengthHeader.toString());
            }

            resolve(contentLength);
        });
    });
}

export async function downloadCache(
    archiveLocation: string,
    archivePath: string
): Promise<void> {
    const stream = fs.createWriteStream(archivePath);
    const httpClient = new HttpClient("actions/cache");
    const downloadResponse = await httpClient.get(archiveLocation);

    downloadResponse.message.socket.setTimeout(5000, () => {
        downloadResponse.message.socket.end();
        core.error("Socket timeout");
    })

    const expectedLength = await pipeResponseToStream(downloadResponse, stream);

    if (expectedLength >= 0) {
        const actualLength = fs.statSync(archivePath).size;
        core.debug(`Content-Length: ${expectedLength}, Actual Length: ${actualLength}`);

        if (actualLength != expectedLength) {
            throw new Error(
                `Incomplete download. Expected file size: ${expectedLength}, actual file size: ${actualLength}`
            );
        }
    } else {
        core.debug("Unable to validate download, no Content-Length header");
    }
}

// Reserve Cache
export async function reserveCache(key: string): Promise<number> {
    const httpClient = createHttpClient();
    const version = getCacheVersion();

    const reserveCacheRequest: ReserveCacheRequest = {
        key,
        version
    };
    const response = await httpClient.postJson<ReserveCacheResponse>(
        getCacheApiUrl("caches"),
        reserveCacheRequest
    );
    return response?.result?.cacheId ?? -1;
}

function getContentRange(start: number, end: number): string {
    // Format: `bytes start-end/filesize
    // start and end are inclusive
    // filesize can be *
    // For a 200 byte chunk starting at byte 0:
    // Content-Range: bytes 0-199/*
    return `bytes ${start}-${end}/*`;
}

async function uploadChunk(
    httpClient: HttpClient,
    resourceUrl: string,
    data: NodeJS.ReadableStream,
    start: number,
    end: number
): Promise<void> {
    core.debug(
        `Uploading chunk of size ${end -
            start +
            1} bytes at offset ${start} with content range: ${getContentRange(
            start,
            end
        )}`
    );
    const additionalHeaders = {
        "Content-Type": "application/octet-stream",
        "Content-Range": getContentRange(start, end)
    };

    const uploadChunkRequest = async (): Promise<IHttpClientResponse> => {
        return await httpClient.sendStream(
            "PATCH",
            resourceUrl,
            data,
            additionalHeaders
        );
    };

    const response = await uploadChunkRequest();
    if (isSuccessStatusCode(response.message.statusCode)) {
        return;
    }

    if (isRetryableStatusCode(response.message.statusCode)) {
        core.debug(
            `Received ${response.message.statusCode}, retrying chunk at offset ${start}.`
        );
        const retryResponse = await uploadChunkRequest();
        if (isSuccessStatusCode(retryResponse.message.statusCode)) {
            return;
        }
    }

    throw new Error(
        `Cache service responded with ${response.message.statusCode} during chunk upload.`
    );
}

function parseEnvNumber(key: string): number | undefined {
    const value = Number(process.env[key]);
    if (Number.isNaN(value) || value < 0) {
        return undefined;
    }
    return value;
}

async function uploadFile(
    httpClient: HttpClient,
    cacheId: number,
    archivePath: string
): Promise<void> {
    // Upload Chunks
    const fileSize = fs.statSync(archivePath).size;
    const resourceUrl = getCacheApiUrl(`caches/${cacheId.toString()}`);
    const fd = fs.openSync(archivePath, "r");

    const concurrency = parseEnvNumber("CACHE_UPLOAD_CONCURRENCY") ?? 4; // # of HTTP requests in parallel
    const MAX_CHUNK_SIZE =
        parseEnvNumber("CACHE_UPLOAD_CHUNK_SIZE") ?? 32 * 1024 * 1024; // 32 MB Chunks
    core.debug(`Concurrency: ${concurrency} and Chunk Size: ${MAX_CHUNK_SIZE}`);

    const parallelUploads = [...new Array(concurrency).keys()];
    core.debug("Awaiting all uploads");
    let offset = 0;

    try {
        await Promise.all(
            parallelUploads.map(async () => {
                while (offset < fileSize) {
                    const chunkSize = Math.min(
                        fileSize - offset,
                        MAX_CHUNK_SIZE
                    );
                    const start = offset;
                    const end = offset + chunkSize - 1;
                    offset += MAX_CHUNK_SIZE;
                    const chunk = fs.createReadStream(archivePath, {
                        fd,
                        start,
                        end,
                        autoClose: false
                    });

                    await uploadChunk(
                        httpClient,
                        resourceUrl,
                        chunk,
                        start,
                        end
                    );
                }
            })
        );
    } finally {
        fs.closeSync(fd);
    }
    return;
}

async function commitCache(
    httpClient: HttpClient,
    cacheId: number,
    filesize: number
): Promise<ITypedResponse<null>> {
    const commitCacheRequest: CommitCacheRequest = { size: filesize };
    return await httpClient.postJson<null>(
        getCacheApiUrl(`caches/${cacheId.toString()}`),
        commitCacheRequest
    );
}

export async function saveCache(
    cacheId: number,
    archivePath: string
): Promise<void> {
    const httpClient = createHttpClient();

    core.debug("Upload cache");
    await uploadFile(httpClient, cacheId, archivePath);

    // Commit Cache
    core.debug("Commiting cache");
    const cacheSize = utils.getArchiveFileSize(archivePath);
    const commitCacheResponse = await commitCache(
        httpClient,
        cacheId,
        cacheSize
    );
    if (!isSuccessStatusCode(commitCacheResponse.statusCode)) {
        throw new Error(
            `Cache service responded with ${commitCacheResponse.statusCode} during commit cache.`
        );
    }

    core.info("Cache saved successfully");
}
