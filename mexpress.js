// @ts-check

// MIT License (this line count as the inclusion of the license): https://mit-license.org/ or https://en.wikipedia.org/wiki/MIT_License

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mimeLookup = { 'aac': 'audio/aac', 'abw': 'application/x-abiword', 'arc': 'application/x-freearc', 'avi': 'video/x-msvideo', 'azw': 'application/vnd.amazon.ebook', 'bin': 'application/octet-stream', 'bmp': 'image/bmp', 'bz': 'application/x-bzip', 'bz2': 'application/x-bzip2', 'csh': 'application/x-csh', 'css': 'text/css', 'csv': 'text/csv', 'doc': 'application/msword', 'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'eot': 'application/vnd.ms-fontobject', 'epub': 'application/epub+zip', 'gz': 'application/gzip', 'gif': 'image/gif', 'htm': 'text/html', 'html': 'text/html', 'ico': 'image/vnd.microsoft.icon', 'ics': 'text/calendar', 'jar': 'application/java-archive', 'jpeg': 'image/jpeg', 'jpg': 'image/jpeg', 'js': 'text/javascript', 'json': 'application/json', 'jsonld': 'application/ld+json', 'mid': 'audio/midi', 'midi': 'audio/midi', 'mjs': 'text/javascript', 'mp3': 'audio/mpeg', 'mpeg': 'video/mpeg', 'mpkg': 'application/vnd.apple.installer+xml', 'odp': 'application/vnd.oasis.opendocument.presentation', 'ods': 'application/vnd.oasis.opendocument.spreadsheet', 'odt': 'application/vnd.oasis.opendocument.text', 'oga': 'audio/ogg', 'ogv': 'video/ogg', 'ogx': 'application/ogg', 'opus': 'audio/opus', 'otf': 'font/otf', 'png': 'image/png', 'pdf': 'application/pdf', 'php': 'application/x-httpd-php', 'ppt': 'application/vnd.ms-powerpoint', 'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'rar': 'application/vnd.rar', 'rtf': 'application/rtf', 'sh': 'application/x-sh', 'svg': 'image/svg+xml', 'swf': 'application/x-shockwave-flash', 'tar': 'application/x-tar', 'tif': 'image/tiff', 'tiff': 'image/tiff', 'ts': 'video/mp2t', 'ttf': 'font/ttf', 'txt': 'text/plain', 'vsd': 'application/vnd.visio', 'wav': 'audio/wav', 'weba': 'audio/webm', 'webm': 'video/webm', 'webp': 'image/webp', 'woff': 'font/woff', 'woff2': 'font/woff2', 'xhtml': 'application/xhtml+xml', 'xls': 'application/vnd.ms-excel', 'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'xml': 'application/xml ', 'xul': 'application/vnd.mozilla.xul+xml', 'zip': 'application/zip', '3gp': 'video/3gpp', '3g2': 'video/3gpp2', '7z': 'application/x-7z-compressed' };

const RESPOND_ERRORS_WITH_THE_STACK_TRACE = process.env.NODE_ENV === 'development';

/**
 * Factory function for MexpressRequest
 * @param {http.IncomingMessage} request
 * @returns {MexpressRequest}
 */
function generateMexpressRequestFromRequest(request) {
    /** @type {any} */
    const method = request.method;
    return new MexpressRequest(
        method,
        request.url,
        request,
    );
}

class MexpressRequest {
    /**
     * @param {'GET' | 'POST' | 'HEAD' | 'PUT' | 'DELETE' | 'CONNECT' | 'OPTIONS' | 'PATCH' | 'TRACE'} method
     * @param {string} url
     * @param {http.IncomingMessage | null} incomingRequest
     */
    constructor(method, url, incomingRequest = null) {
        this.method = method;
        this.url = url;
        this.primitive = incomingRequest;

        /**
         * The headers from the incoming request
         * @type {{[headerName: string]: string | string[]}}
         */
        this.headers = incomingRequest ? incomingRequest.headers : {};

        /**
         * URL parameter key-value pairs populated by `app.handleRequest()`
         * @type {{[urlParam: string]: string}}
         */
        this.params = {};

        /** @type {Promise<Buffer> | Buffer} */
        this._binaryBody = null;

        /**
         * The query string parameters (after the question mark on a url's pathname)
         * @type {{[queryParam: string]: string}}
         */
        this.query = {};
        if (url) {
            const pathnameQuestionMarkIndex = url.indexOf('?');
            if (pathnameQuestionMarkIndex !== -1) {
                this.queryString = url.substring(pathnameQuestionMarkIndex + 1);
                const queryParamList = this.queryString.split('&');
                for (const queryParam of queryParamList) {
                    const queryMiddleIndex = queryParam.indexOf('=');
                    if (queryMiddleIndex === -1) {
                        this.query[decodeURIComponent(queryParam)] = '';
                    } else {
                        this.query[decodeURIComponent(queryParam.substring(0, queryMiddleIndex))] = decodeURIComponent(queryParam.substring(queryMiddleIndex + 1));
                    }
                }
            }
        }

        /**
         * The cookies as a key-value pair object
         * @type {{[cookieName: string]: string}}
         */
        this.cookies = {};
        if (this.headers['cookie']) {
            const cookies = this.headers['cookie'] instanceof Array ? this.headers['cookie'].join(';') : this.headers['cookie'];
            const cookieList = cookies.split(';').map(pair => pair.trim().split('='));
            for (const pair of cookieList) {
                this.cookies[pair[0]] = pair[1];
            }
        }
    }

    async getBodyAsBinary() {
        if (this.method === 'GET' || this.method === 'HEAD' || this.method === 'TRACE') {
            throw new Error(`The request method (${this.method}) cannot have a request body`);
        }
        if (this._binaryBody instanceof Promise) {
            await this._binaryBody;
        }
        this._binaryBody = new Promise((resolve, reject) => {
            if (!this.primitive) {
                // @ts-ignore
                if (this.body instanceof Buffer) {
                    // @ts-ignore
                    resolve(this.body);
                    return;
                }
                reject(new Error('Cannot get request body because of it is the missing primitive (IncomingRequest) and missing a "body" property with the Buffer object'));
                return;
            }
            const data = [];
            this.primitive.on('data', (chunk) => data.push(chunk));
            this.primitive.on('end', () => resolve(Buffer.concat(data)));
            this.primitive.on('error', reject);
        });
        this._binaryBody = await this._binaryBody;
        return this._binaryBody;
    }

    /**
     * Get the request body as text, tries to find content-type encoding to use, has utf8 as fallback
     * If an argument is supplied it will force the encoding instead of looking for one
     * @param {BufferEncoding} [encoding]
     */
    async getBodyAsText(encoding = null) {
        const buffer = await this.getBodyAsBinary();
        const contentType = this.headers['content-type'];
        if (contentType && !encoding) {
            /** @type {BufferEncoding[]} */
            const possibleEncodingList = ['ascii', 'utf8', 'utf-8', 'utf16le', 'ucs2', 'ucs-2', 'base64', 'base64url', 'latin1', 'binary', 'hex'];
            for (let possibleEncoding of possibleEncodingList) {
                if (contentType.includes(possibleEncoding)) {
                    encoding = possibleEncoding;
                    break;
                }
            }
        }
        return buffer.toString(encoding);
    }

    async getBodyAsJson() {
        const text = await this.getBodyAsText();
        return JSON.stringify(text);
    }
}

/**
 * Factory function for MexpressResponse
 * @param {http.ServerResponse} res 
 * @returns {MexpressResponse}
 */
function generateMexpressResponseFromResponse(res) {
    return new MexpressResponse(res);
}

class MexpressResponse {
    /**
     * @param {http.ServerResponse} primitiveResponse 
     */
    constructor(primitiveResponse) {
        this.primitive = primitiveResponse;
        this.complete = false;
        this.statusCode = 200;
    }

    /**
     * @param {number} code
     */
    status(code) {
        if (typeof code !== 'number') {
            throw new Error('Invalid status code of type ' + (typeof code));
        } else if (isNaN(code)) {
            throw new Error('Status code cannot be NaN (not a number)');
        }
        this.statusCode = code;
        this.primitive.statusCode = code;
        return this;
    }

    /**
     * @param {string} name
     * @param {string | number | string[]} value
     */
    header(name, value) {
        if (typeof name !== 'string') {
            throw new Error('Invalid header name of type ' + (typeof name));
        }
        return this.primitive.setHeader(name, value);
    }

    /**
     * @param {string} name
     * @param {string | number | string[]} value
     */
    setHeader(name, value) {
        return this.header(name, value);
    }

    /**
     * @param {string | Buffer} chunk
     * @returns {Promise<void>}
     */
    write(chunk) {
        if (!(chunk instanceof Buffer) && typeof chunk !== 'string') {
            throw new Error('Invalid chunk parameter for response: expected string or Buffer instance.');
        }
        return new Promise(
            (resolve, reject) => this.primitive.write(chunk, (err) => err ? reject(err) : resolve())
        );
    }

    /**
     * Ends the request
     * @param {string | Buffer} [chunk]
     * @param {BufferEncoding} [encoding]
     * @returns {Promise<void>}
     */
    end(chunk, encoding = 'utf8') {
        if (chunk !== undefined) {
            if (!(chunk instanceof Buffer) && typeof chunk !== 'string') {
                throw new Error('Invalid ending chunk parameter for response: expected string, Buffer instance, or undefined');
            }
        }
        if (this.complete === false) {
            this.complete = true;
        } else {
            throw new Error('Response is already finished, completed or closed');
        }
        return new Promise(
            resolve => this.primitive.end(chunk, encoding, resolve)
        );
    }

    /**
     * Stringifies an object and sends it with the content-type header set to application/json.
     * Always ends the request, even on rejects.
     * @param {any} obj
     * @returns {Promise<void>}
     */
    json(obj) {
        this.primitive.setHeader('content-type', 'application/json');
        return this.end(JSON.stringify(obj));
    }

    /**
     * Sends a file as the response, if content-type header is not present it is infered from the file extension. Sends 404 if no file is found.
     * Always ends the requests, even on rejections.
     * @param {string} filePath 
     * @param {{root?: string, etagHeader?: boolean, lastModifiedHeader?: boolean}} [options]
     * @returns {Promise<void>}
     */
    sendFile(filePath, options = {}) {
        if (typeof filePath !== 'string') {
            throw new Error(`Invalid file path with unexpected type: ${typeof filePath}`);
        }
        if (options === undefined || options === null) {
            options = {};
        }
        return new Promise((resolve, reject) => {
            const response = this.primitive;
            let fullFilePath = path.resolve(filePath);
            let type = 'text/plain';
            const lastDot = fullFilePath.lastIndexOf('.');
            if (lastDot !== -1 && fullFilePath.length - lastDot < 6) {
                const extension = fullFilePath.substring(lastDot + 1);
                if (mimeLookup[extension]) {
                    type = mimeLookup[extension];
                }
            }
            fs.stat(fullFilePath, (err, stats) => {
                if (!err && !stats.isFile()) {
                    err = new Error('Cannot serve path because it does not contain a file');
                }
                if (err) {
                    try {
                        response.writeHead(err.code === 'ENOENT' ? 404 : 500, { 'Content-Type': 'text/plain' });
                        response.end(RESPOND_ERRORS_WITH_THE_STACK_TRACE ? (err.stack || err.message) : '');
                        this.complete = true;
                    } catch (_err) {
                        // Ignore error while finishing failing request
                    }
                    reject(err);
                    return;
                }
                if (options.etagHeader !== false) {
                    const sha1OfDate = crypto.createHmac('sha1', 'mexpress').update(stats.mtime.toISOString()).digest('hex');
                    response.setHeader('etag', sha1OfDate);
                }
                if (options.lastModifiedHeader !== false) {
                    response.setHeader('last-modified', stats.mtime.toISOString());
                }
                fs.readFile(fullFilePath, 'binary', (err, data) => {
                    if (err) {
                        try {
                            response.writeHead(err.code === 'ENOENT' ? 404 : 500, { 'Content-Type': 'text/plain' });
                            response.end(RESPOND_ERRORS_WITH_THE_STACK_TRACE ? (err.stack || err.message) : '');
                            this.complete = true;
                        } catch (_err) {
                            // Ignore error while finishing failing request
                        }
                        reject(err);
                        return;
                    }
                    if (this.complete === true) {
                        reject(new Error('Response is already finished, completed or closed'));
                        return;
                    }
                    response.writeHead(200, { 'Content-Type': type });
                    response.write(data, 'binary', (err) => {
                        this.complete = true;
                        if (err) {
                            response.end(RESPOND_ERRORS_WITH_THE_STACK_TRACE ? (err.stack || err.message) : '');
                            reject(err);
                        } else {
                            response.end();
                            resolve();
                        }
                    });
                });
            });
        });
    }

    /**
     * Ends the request with a redirect request using http headers:
     * It sets the 'Location' header, the statusCode, and ends the request
     * This uses a different parameter order from the one from express because I think they did a terrible job with the optional parameter.
     * You may use status 301 for permanent redirect (browsers memorizes the result and redirects automatically next times)
     * You may use status 307 to keep the same method (if it was a post, it will keep its property), useful for form submission redirects.
     * You may use status 308, which is the same as 307 but permanent.
     *
     * @param url The target url to redirect to
     * @param statusCode The default is 302 and specifies a temporary redirect
     * @returns {Promise<void>} Resolves when the redirect is sent to the client
     */
    redirect(url, statusCode = 302) {
        this.primitive.setHeader('Location', url);
        return this.status(statusCode).end();
    }
}

function isInvalidPathPattern(pattern) {
    return !pattern || typeof pattern !== 'string' || (pattern[0] === '*' && pattern.length !== 1) || (pattern[0] !== '/' && pattern[0] !== '*') || pattern.includes(' ') || pattern.includes('?') || pattern.includes('#');
}

function populateParamsFromUrl(pattern, pathname) {
    /**
     * @type {{[paramName: string]: string}}
     */
    const params = {};

    // Handle wildcard
    if (pattern === '*') {
        return {
            matching: true,
            params
        }
    }

    // Handle simple routes
    if (!pattern.includes('*') && !pattern.includes(':')) {
        return {
            matching: pattern === pathname,
            params
        }
    }

    // Handle route with parameters in path pattern
    let matching = true;
    let state = 'after-slash';
    let paramName = '';
    let paramValue = '';
    let patternIndex = 0;
    let pathIndex = 1;
    for (patternIndex = 1; patternIndex <= pattern.length; patternIndex++) {
        if (state === 'after-slash') {
            if (pattern[patternIndex] === undefined) {
                // The url ended after a matching slash
                break;
            } else if (pattern[patternIndex] === ':') {
                state = 'inside-colon-param';
                continue;
            } else {
                if (pathname[pathIndex] === pattern[patternIndex]) {
                    pathIndex++;
                    state = 'matching';
                } else {
                    matching = false;
                    break;
                }
            }
        } else if (state === 'inside-colon-param') {
            // Retrieve param name from the route url
            paramName = '';
            while (patternIndex < pattern.length && pattern[patternIndex] !== '/') {
                paramName += pattern[patternIndex];
                patternIndex++;
            }
            // Retrieve param value from the pathname
            paramValue = '';
            while (pathIndex < pathname.length && pathname[pathIndex] !== '/') {
                paramValue += pathname[pathIndex];
                pathIndex++;
            }
            if (paramValue.length === 0) {
                // Does not match because of empty parameter
                matching = false;
                break;
            }
            params[paramName] = decodeURIComponent(paramValue);
            if (pattern[patternIndex] !== pathname[pathIndex]) {
                // The slash (or lack of slash) does not match
                matching = false;
                break;
            } else {
                pathIndex++;
            }
            state = 'after-slash';
        } else if (state === 'matching') {
            if (pattern[patternIndex] === undefined) {
                break;
            } else if (pattern[patternIndex] === '/') {
                if (pathname[pathIndex] === '/') {
                    pathIndex++;
                    state = 'after-slash';
                } else {
                    matching = false;
                    break;
                }
            } else {
                if (pattern[patternIndex] === pathname[pathIndex]) {
                    pathIndex++;
                    continue;
                } else {
                    matching = false;
                    break;
                }
            }
        }
    }

    return {
        matching,
        params
    };
}

/**
 * @typedef {(req: MexpressRequest, res: MexpressResponse, next: () => void) => (void | Promise<void>)} RequestHandlerFunction
 */

class MexpressRouter {
    /**
     * @param {string} url
     * @param {'GET' | 'POST' | 'HEAD' | 'PUT' | 'DELETE' | 'CONNECT' | 'OPTIONS' | 'PATCH' | 'TRACE' | null} method
     * @param {RequestHandlerFunction} handler
     * @param {null | MexpressRouter} next
     */
    constructor(url, method, handler, next) {
        this.url = url;
        this.method = method;
        this.handler = handler;
        this.next = next;
    }
}

function extractPathnameFromRawUrl(url) {
    if (typeof url !== 'string') {
        throw new Error('Invalid url, expected string, got ' + typeof url);
    }
    const questionMarkIndex = url.indexOf('?');
    if (questionMarkIndex !== -1) {
        return url.substring(0, questionMarkIndex);
    }
    return url;
}

class MexpressApp {
    
    constructor() {
        /**
         * @type {
         *  {
         *      url: string,
         *      method: 'GET' | 'POST' | 'HEAD' | 'PUT' | 'DELETE' | 'CONNECT' | 'OPTIONS' | 'PATCH' | 'TRACE' | null,
         *      handler: RequestHandlerFunction,
         *  }[]
         * }
         */
        this.routes = [];

        /** @type {MexpressRouter} */
        this._firstRoute = null;
        /** @type {MexpressRouter} */
        this._lastRoute = null;
        this._routerCount = 0;

        /**
         * @type {http.Server | https.Server | null}
         */
        this.server = null;
    }

    /**
     * Adds a route that matches any method
     * @param {string} url
     * @param {RequestHandlerFunction} handler
     */
    use(url, handler) {
        if (arguments.length !== 2) {
            throw new Error(`Got ${arguments.length} arguments on a function that expected 2`);
        }
        if (isInvalidPathPattern(url)) {
            throw new Error('The url is invalid, use an asterisk to match all');
        }
        this._addRoute(url, null, handler);
    }

    /**
     * Adds a route to the specified method.
     * @param {string} url
     * @param {RequestHandlerFunction} handler
     */
    get(url, handler) {
        if (arguments.length !== 2) {
            throw new Error(`Got ${arguments.length} arguments on a function that expected 2`);
        }
        if (isInvalidPathPattern(url)) {
            throw new Error('The url is invalid, use an asterisk to match all');
        }
        this._addRoute(url, 'GET', handler);
    }

    /**
     * Adds a route to the specified method.
     * @param {string} url
     * @param {RequestHandlerFunction} handler
     */
    post(url, handler) {
        if (arguments.length !== 2) {
            throw new Error(`Got ${arguments.length} arguments on a function that expected 2`);
        }
        if (isInvalidPathPattern(url)) {
            throw new Error('The url is invalid, use an asterisk to match all');
        }
        this._addRoute(url, 'POST', handler);
    }

    /**
     * Adds a route to the specified method.
     * @param {string} url
     * @param {RequestHandlerFunction} handler
     */
    head(url, handler) {
        if (arguments.length !== 2) {
            throw new Error(`Got ${arguments.length} arguments on a function that expected 2`);
        }
        if (isInvalidPathPattern(url)) {
            throw new Error('The url is invalid, use an asterisk to match all');
        }
        this._addRoute(url, 'HEAD', handler);
    }

    /**
     * Adds a route to the specified method.
     * @param {string} url
     * @param {RequestHandlerFunction} handler
     */
    put(url, handler) {
        if (arguments.length !== 2) {
            throw new Error(`Got ${arguments.length} arguments on a function that expected 2`);
        }
        if (isInvalidPathPattern(url)) {
            throw new Error('The url is invalid, use an asterisk to match all');
        }
        this._addRoute(url, 'PUT', handler);
    }

    /**
     * Adds a route to the specified method.
     * @param {string} url
     * @param {RequestHandlerFunction} handler
     */
    delete(url, handler) {
        if (arguments.length !== 2) {
            throw new Error(`Got ${arguments.length} arguments on a function that expected 2`);
        }
        if (isInvalidPathPattern(url)) {
            throw new Error('The url is invalid, use an asterisk to match all');
        }
        this._addRoute(url, 'DELETE', handler);
    }

    /**
     * Adds a route to the specified method.
     * @param {string} url
     * @param {RequestHandlerFunction} handler
     */
    connect(url, handler) {
        if (arguments.length !== 2) {
            throw new Error(`Got ${arguments.length} arguments on a function that expected 2`);
        }
        if (isInvalidPathPattern(url)) {
            throw new Error('The url is invalid, use an asterisk to match all');
        }
        this._addRoute(url, 'CONNECT', handler);
    }

    /**
     * Adds a route to the specified method.
     * @param {string} url
     * @param {RequestHandlerFunction} handler
     */
    options(url, handler) {
        if (arguments.length !== 2) {
            throw new Error(`Got ${arguments.length} arguments on a function that expected 2`);
        }
        if (isInvalidPathPattern(url)) {
            throw new Error('The url is invalid, use an asterisk to match all');
        }
        this._addRoute(url, 'OPTIONS', handler);
    }

    /**
     * Adds a route to the specified method.
     * @param {string} url
     * @param {RequestHandlerFunction} handler
     */
    patch(url, handler) {
        if (arguments.length !== 2) {
            throw new Error(`Got ${arguments.length} arguments on a function that expected 2`);
        }
        if (isInvalidPathPattern(url)) {
            throw new Error('The url is invalid, use an asterisk to match all');
        }
        this._addRoute(url, 'PATCH', handler);
    }

    /**
     * Adds a route to the specified method.
     * @param {string} url
     * @param {RequestHandlerFunction} handler
     */
    trace(url, handler) {
        if (arguments.length !== 2) {
            throw new Error(`Got ${arguments.length} arguments on a function that expected 2`);
        }
        if (isInvalidPathPattern(url)) {
            throw new Error('The url is invalid, use an asterisk to match all');
        }
        this._addRoute(url, 'TRACE', handler);
    }

    /**
     * Appends a route to the linked list of routes
     * @param {string} url 
     * @param {'GET' | 'POST' | 'HEAD' | 'PUT' | 'DELETE' | 'CONNECT' | 'OPTIONS' | 'PATCH' | 'TRACE' | null} method 
     * @param {(req: MexpressRequest, res: MexpressResponse, next: () => void) => void | Promise<void>} handler 
     */
    _addRoute(url, method, handler) {
        /** @type {MexpressRouter} */
        const route = {
            url,
            method,
            handler,
            next: null,
        }
        if (this._lastRoute) {
            this._lastRoute.next = route;
            this._lastRoute = route;
        } else {
            this._firstRoute = this._lastRoute = route;
        }
        this._routerCount++;
    }

    /**
     * @param {http.IncomingMessage} request
     * @param {http.ServerResponse | null} response
     * @param {undefined | null | (() => void)} next
     */
    async handle(request, response, next) {
        try {
            const pathname = extractPathnameFromRawUrl(request.url);
            const req = generateMexpressRequestFromRequest(request);
            const res = generateMexpressResponseFromResponse(response);

            let route = this._firstRoute;
            for (let i = 0; i < this._routerCount + 1; i++) {
                if (route === null) {
                    return res.status(404).end();
                }
                if (route.method !== null && route.method !== req.method) {
                    route = route.next;
                    continue;
                }
                // @ts-ignore
                if (route.handler.isStatic === true) {
                    if (route.url !== '*' && !pathname.startsWith(route.url)) {
                        route = route.next;
                        continue;
                    }

                    let nextCalled = false;

                    // Send an extra parameter to static handlers to aid in finding the file.
                    await route.handler(
                        req,
                        res,
                        function () {
                            nextCalled = true;
                        },
                        // @ts-ignore
                        route.url === '*' ? '' : route.url
                    );

                    // Check if we must stop transversing the routes
                    if (res.complete) {
                        return;
                    }
                    if (nextCalled === false) {
                        return;
                    }
                    route = route.next;
                    continue;
                } else {
                    // Handle url parameters and matching
                    const result = populateParamsFromUrl(route.url, pathname);
                    if (!result.matching) {
                        route = route.next;
                        continue;
                    }
                    /**
                     * @type {{[paramName: string]: string}}
                     */
                    req.params = result.params;
    
                    try {
                        let nextCalled = false;
    
                        let returned = route.handler(
                            req,
                            res,
                            function () {
                                nextCalled = true;
                            }
                        );
    
                        if (returned instanceof Promise) {
                            returned = await returned;
                        }
                        // @ts-ignore
                        if (returned instanceof Promise) {
                            returned = await returned;
                        }
                        // Check if we must stop transversing the routes
                        if (res.complete) {
                            return;
                        }
                        if (nextCalled === false) {
                            return;
                        }
                        route = route.next;
                        continue;
                    } catch (err) {
                        if (RESPOND_ERRORS_WITH_THE_STACK_TRACE) {
                            err.message = `Request "${request.url}" handling error: ${err.message}`;
                            console.error(err);
                        }
                        try {
                            await res.status(500).end(RESPOND_ERRORS_WITH_THE_STACK_TRACE ? (err.stack || err.message) : '');
                        } catch (_err) {
                            // Ignore request-closing error
                        }
                    }
                }
            }
        } catch (err) {
            try {
                response.writeHead(500)
            } catch (internalError) {
                // Ignore header nested error
            }
            try {
                response.end(RESPOND_ERRORS_WITH_THE_STACK_TRACE ? (err.stack || err.message) : '');
            } catch (internalError) {
                // Ignore end nested error
            }
        }
    }

    /**
     * port?: number, hostname?: string, backlog?: number, listeningListener?: () => void
     * @param {number} [port]
     * @param {string} [hostname] 
     * @param {() => void} [onListenStart] 
     */
    listen(port = 8080, hostname = 'localhost', onListenStart = null) {
        const server = http.createServer(this.handle.bind(this));
        this.server = server;
        server.listen(port, hostname, onListenStart);
    }
}

/**
 * Generates an http or https server app instance with the given configuration
 * @returns {MexpressApp}
 */
const mexpress = function mexpress() {
    /** @type {MexpressApp} */
    let app = null;

    // @ts-ignore
    app = function(req, res, next) {
        // @ts-ignore
        app.handle(req, res, next);
    };

    const instance = new MexpressApp();

    // Add MexpressApp methods
    for (const key of Object.getOwnPropertyNames(MexpressApp.prototype)) {
        if (key === 'constructor') {
            continue;
        }
        app[key] = instance[key];
    }

    // Add MexpressApp properties
    for (const key of Object.getOwnPropertyNames(instance)) {
        app[key] = instance[key];
    }

    return app;
}

mexpress.MexpressRequest = MexpressRequest;
mexpress.MexpressResponse = MexpressResponse;

/**
 * Returns a route handler to serve static resources
 *
 * @param {string} staticPath
 * @param {{etagFeature?: boolean, lastModifiedFeature?: boolean}} options
 * @returns {(req: MexpressRequest, res: MexpressResponse, next: () => void) => Promise<void>}
 */
mexpress.static = function(staticPath, options = {}) {
    if (arguments.length !== 1) {
        throw new Error(`Static function must receive one parameter, got ${arguments.length}`);
    } else if (typeof staticPath !== 'string') {
        throw new Error(`Static function must receive a string parameter, got ${typeof staticPath}`)
    }

    let stat;

    /** @type {(req: MexpressRequest, res: MexpressResponse, next: () => void, mountPoint: string) => Promise<void>} */
    const f = async function(req, res, next, mountPoint) {
        try {
            stat = fs.statSync(staticPath);
        } catch (err) {
            if (err.code === 'ENOENT') {
                next();
                return;
            } else {
                err.message = `Could not find static target at "${staticPath}"`
                throw err;
            }
        }

        let targetFile;
        if (stat.isDirectory()) {
            targetFile = path.resolve(staticPath, decodeURIComponent(req.url.substring(mountPoint.length + 1)));
        } else {
            targetFile = staticPath;
        }
        let isDirectory;
        try {
            isDirectory = await new Promise((resolve, reject) => {
                fs.stat(targetFile, (err, result) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(result.isDirectory());
                    }
                })
            });
        } catch (err) {
            console.log('Could not find target ' + targetFile);
            if (err.code === 'ENOENT') {
                next();
                return;
            } else {
                await res.status(500).end(RESPOND_ERRORS_WITH_THE_STACK_TRACE ? (err.stack || err.message) : '');
                return;
            }
        }
        if (isDirectory) {
            targetFile += '/index.html';
        }
        let lastModifiedTime = null;
        if (options.etagFeature !== false || options.lastModifiedFeature !== false) {
            try {
                lastModifiedTime = await new Promise((resolve, reject) => {
                    fs.stat(targetFile, (err, result) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(result.mtime);
                        }
                    })
                });
            } catch (err) {
                if (err.code === 'ENOENT') {
                    next();
                    return;
                } else {
                    await res.end(RESPOND_ERRORS_WITH_THE_STACK_TRACE ? (err.stack || err.message) : '');
                    return;
                }
            }
        }
        if (options.etagFeature !== false) {
            const sha1OfDate = crypto.createHmac('sha1', 'mexpress').update(lastModifiedTime.toISOString()).digest('hex');
            res.setHeader('etag', sha1OfDate);
            if (req.primitive.headers['etag'] === sha1OfDate && req.primitive.headers['cache-control'] !== 'no-cache') {
                if (['max-age', 'no-store', 'no-transform', 'stale-if-error'].includes(req.primitive.headers['cache-control'])) {
                    res.primitive.setHeader('cache-control', req.primitive.headers['cache-control']);
                }
                res.primitive.statusCode = 304;
                res.primitive.statusMessage = 'Not Modified';
                if (options.lastModifiedFeature !== false) {
                    res.setHeader('last-modified', lastModifiedTime.toISOString());
                }
                await res.end();
                return;
            }
        }
        if (options.lastModifiedFeature !== false) {
            res.setHeader('last-modified', lastModifiedTime.toISOString());
            if (req.primitive.headers['if-modified-since'] && req.primitive.headers['cache-control'] !== 'no-cache') {
                if (['max-age', 'no-store', 'no-transform', 'stale-if-error'].includes(req.primitive.headers['cache-control'])) {
                    res.primitive.setHeader('cache-control', req.primitive.headers['cache-control']);
                }
                const currentClientModifiedDate = new Date(req.primitive.headers['if-modified-since']);
                if (!isNaN(currentClientModifiedDate.getTime())) {
                    if (lastModifiedTime.getTime() >= currentClientModifiedDate.getTime()) {
                        res.primitive.statusCode = 304;
                        res.primitive.statusMessage = 'Not Modified';
                        await res.end();
                        return;
                    }
                }
            }
            if (req.primitive.headers['if-unmodified-since'] && req.primitive.headers['cache-control'] !== 'no-cache') {
                if (['max-age', 'no-store', 'no-transform', 'stale-if-error'].includes(req.primitive.headers['cache-control'])) {
                    res.primitive.setHeader('cache-control', req.primitive.headers['cache-control']);
                }
                const currentClientModifiedDate = new Date(req.primitive.headers['if-unmodified-since']);
                if (!isNaN(currentClientModifiedDate.getTime())) {
                    if (lastModifiedTime.getTime() < currentClientModifiedDate.getTime()) {
                        res.primitive.statusCode = 412;
                        res.primitive.statusMessage = 'Precondition Failed';
                        await res.end();
                        return;
                    }
                }
            }
        }
        await res.sendFile(targetFile, {
            etagHeader: options.etagFeature,
            lastModifiedHeader: options.lastModifiedFeature,
        });
    };
    // @ts-ignore
    f.isStatic = true;
    // @ts-ignore
    return f;
}

module.exports = mexpress;