// @ts-check

// MIT License (this line count as the inclusion of the license): https://mit-license.org/ or https://en.wikipedia.org/wiki/MIT_License

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');
const mimeLookup = { 'aac': 'audio/aac', 'abw': 'application/x-abiword', 'arc': 'application/x-freearc', 'avi': 'video/x-msvideo', 'azw': 'application/vnd.amazon.ebook', 'bin': 'application/octet-stream', 'bmp': 'image/bmp', 'bz': 'application/x-bzip', 'bz2': 'application/x-bzip2', 'csh': 'application/x-csh', 'css': 'text/css', 'csv': 'text/csv', 'doc': 'application/msword', 'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'eot': 'application/vnd.ms-fontobject', 'epub': 'application/epub+zip', 'gz': 'application/gzip', 'gif': 'image/gif', 'htm': 'text/html', 'html': 'text/html', 'ico': 'image/vnd.microsoft.icon', 'ics': 'text/calendar', 'jar': 'application/java-archive', 'jpeg': 'image/jpeg', 'jpg': 'image/jpeg', 'js': 'text/javascript', 'json': 'application/json', 'jsonld': 'application/ld+json', 'mid': 'audio/midi', 'midi': 'audio/midi', 'mjs': 'text/javascript', 'mp3': 'audio/mpeg', 'mpeg': 'video/mpeg', 'mpkg': 'application/vnd.apple.installer+xml', 'odp': 'application/vnd.oasis.opendocument.presentation', 'ods': 'application/vnd.oasis.opendocument.spreadsheet', 'odt': 'application/vnd.oasis.opendocument.text', 'oga': 'audio/ogg', 'ogv': 'video/ogg', 'ogx': 'application/ogg', 'opus': 'audio/opus', 'otf': 'font/otf', 'png': 'image/png', 'pdf': 'application/pdf', 'php': 'application/x-httpd-php', 'ppt': 'application/vnd.ms-powerpoint', 'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'rar': 'application/vnd.rar', 'rtf': 'application/rtf', 'sh': 'application/x-sh', 'svg': 'image/svg+xml', 'swf': 'application/x-shockwave-flash', 'tar': 'application/x-tar', 'tif': 'image/tiff', 'tiff': 'image/tiff', 'ts': 'video/mp2t', 'ttf': 'font/ttf', 'txt': 'text/plain', 'vsd': 'application/vnd.visio', 'wav': 'audio/wav', 'weba': 'audio/webm', 'webm': 'video/webm', 'webp': 'image/webp', 'woff': 'font/woff', 'woff2': 'font/woff2', 'xhtml': 'application/xhtml+xml', 'xls': 'application/vnd.ms-excel', 'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'xml': 'application/xml ', 'xul': 'application/vnd.mozilla.xul+xml', 'zip': 'application/zip', '3gp': 'video/3gpp', '3g2': 'video/3gpp2', '7z': 'application/x-7z-compressed' };

const RESPOND_ERRORS_WITH_THE_STACK_TRACE = process.env.NODE_ENV === 'development';

/**
 * Factory function for MexpressRequest
 * @param {http.IncomingMessage} request 
 * @returns {MexpressRequest}
 */
function generateMexpressRequestFromRequest(request) {
    return new MexpressRequest(
        request.method,
        new URL(request.url, `https://${request.headers.host}`),
        request,
    )
}

class MexpressRequest {
    /**
     * @param {'GET' | 'POST' | 'HEAD' | 'PUT' | 'DELETE' | 'CONNECT' | 'OPTIONS' | 'PATCH' | 'TRACE'} method
     * @param {URL} url
     * @param {http.IncomingMessage | null} incomingRequest
     */
    constructor(method, url, incomingRequest) {
        this.method = method;

        this.url = url;

        this.primitive = incomingRequest;

        /**
         * The headers from the incoming request
         * @type {{[headerName: string]: string}}
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
         * @type {{[queryParam: string]: string} | null}
         */
        this.query = null;

        /**
         * The query string of the request (everything after the question mark)
         * @type {string}
         */
        this.queryString = '';

        /**
         * The hash string of the request (everything after the # but before the question mark)
         */
        this.hash = '';

        /**
         * The cookies from the 'Cookies' header
         * @type {{[cookieName: string]: string} | null}
         */
        this.cookies = null;
    }

    async getBodyAsBinary() {
        if (this._binaryBody instanceof Promise) {
            await this._binaryBody;
        }
        this._binaryBody = new Promise((resolve, reject) => {
            if (!this.primitive) {
                if (this.body instanceof Buffer) {
                    resolve(this.body);
                    return;
                }
                reject(new Error('Cannot get body because this instance does not have a primitive IncomingRequest or a .body buffer property'));
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

    async getBodyAsText(encoding = 'utf8') {
        const buffer = await this.getBodyAsBinary();
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

function isInvalidUrl(url) {
    return !url || typeof url !== 'string' || (url[0] === '*' && url.length !== 1) || (url[0] !== '/' && url[0] !== '*') || url.includes(' ') || url.includes('?') || url.includes('#');
}

/**
 * @typedef {(req: MexpressRequest, res: MexpressResponse, next: () => void) => (void | Promise<void>)} RequestHandlerFunction
 */

class MexpressApp {
    /**
     * @param {string} host 
     * @param {number} port 
     * @param {{key: string, cert: string} | undefined} [ssl]
     */
    constructor(
        host,
        port,
        ssl
    ) {
        if (typeof host !== 'string') {
            throw new Error('Invalid host for Mexpress app');
        }
        if (typeof port !== 'number' || isNaN(port)) {
            throw new Error('Invalid port for Mexpress app');
        }
        if (ssl && typeof ssl !== 'object') {
            throw new Error('Invalid ssl parameter for Mexpress app: expected object');
        }
        if (ssl && (!ssl.key || !ssl.cert)) {
            throw new Error('Invalid ssl object for Mexpress app: object is missing "key" or "cert" properties');
        }
        this.host = host;
        this.port = port;
        this.ssl = ssl;

        /**
         * @type {
         *  {
         *      url: string,
         *      method: 'get' | 'post' | 'head' | 'put' | 'delete' | 'connect' | 'options' | 'patch' | 'trace' | null,
         *      handler: RequestHandlerFunction,
         *  }[]
         * }
         */
        this.routes = [];

        /**
         * @type {http.Server | https.Server | null}
         */
        this.primitive = null;
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
        if (isInvalidUrl(url)) {
            throw new Error('The url is invalid, use an asterisk to match all');
        }
        this.routes.push({ url, method: null, handler });
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
        if (isInvalidUrl(url)) {
            throw new Error('The url is invalid, use an asterisk to match all');
        }
        this.routes.push({ url, method: 'GET', handler });
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
        if (isInvalidUrl(url)) {
            throw new Error('The url is invalid, use an asterisk to match all');
        }
        this.routes.push({ url, method: 'POST', handler });
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
        if (isInvalidUrl(url)) {
            throw new Error('The url is invalid, use an asterisk to match all');
        }
        this.routes.push({ url, method: 'HEAD', handler });
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
        if (isInvalidUrl(url)) {
            throw new Error('The url is invalid, use an asterisk to match all');
        }
        this.routes.push({ url, method: 'PUT', handler });
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
        if (isInvalidUrl(url)) {
            throw new Error('The url is invalid, use an asterisk to match all');
        }
        this.routes.push({ url, method: 'DELETE', handler });
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
        if (isInvalidUrl(url)) {
            throw new Error('The url is invalid, use an asterisk to match all');
        }
        this.routes.push({ url, method: 'CONNECT', handler });
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
        if (isInvalidUrl(url)) {
            throw new Error('The url is invalid, use an asterisk to match all');
        }
        this.routes.push({ url, method: 'OPTIONS', handler });
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
        if (isInvalidUrl(url)) {
            throw new Error('The url is invalid, use an asterisk to match all');
        }
        this.routes.push({ url, method: 'PATCH', handler });
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
        if (isInvalidUrl(url)) {
            throw new Error('The url is invalid, use an asterisk to match all');
        }
        this.routes.push({ url, method: 'TRACE', handler });
    }

    /**
     * Starts the listening of the server
     * @params {() => void} (onListenStart)
     * @returns {void}
     */
    listen(onListenStart) {
        if (arguments.length > 0 && !(onListenStart instanceof Function)) {
            throw new Error(`Invalid first parameter: expected function, got ${typeof onListenStart}`);
        }
        if (arguments.length > 1) {
            throw new Error('Listen does not receive more than one parameter. Host and port are to be passed at the app config object');
        }
        if (this.ssl) {
            this.server = https.createServer({
                key: this.ssl.key,
                cert: this.ssl.cert
            }, (req, res) => {
                const mexpressRequest = generateMexpressRequestFromRequest(req);
                const mexpressResponse = generateMexpressResponseFromResponse(res);
                this.handleRequest(mexpressRequest, mexpressResponse).catch(
                    err => res.status(500).end(RESPOND_ERRORS_WITH_THE_STACK_TRACE ? (err.stack || err.message) : null)
                );
            });
        } else {
            this.server = http.createServer((req, res) => {
                const mexpressRequest = generateMexpressRequestFromRequest(req);
                const mexpressResponse = generateMexpressResponseFromResponse(res);
                this.handleRequest(mexpressRequest, mexpressResponse).catch(
                    err => res.writeHead(500).end(RESPOND_ERRORS_WITH_THE_STACK_TRACE ? (err.stack || err.message) : null)
                );
            });
        }
        this.server.listen(this.port, this.host, onListenStart);
    }

    /**
     * @param {MexpressRequest} req
     * @param {MexpressResponse} res
     * @private
     */
    async handleRequest(req, res) {
        let matchCount = 0;
        for (let i = 0; i < this.routes.length; i++) {
            const route = this.routes[i];
            if (route.method !== null && route.method !== req.method) {
                continue;
            }
            let matching = true;
            const pathname = req.url.pathname;

            // Handle url parameters and matching
            /**
             * @type {{[paramName: string]: string}}
             */
            req.params = {};
            if (route.url !== '*') {
                if (!route.url.includes(':') && !pathname.includes('{')) {
                    // Simple parameter
                    matching = route.url === pathname;
                } else {
                    matching = true;
                    let state = 'after-slash';
                    let paramName = '';
                    let paramValue = '';
                    let urlIndex = 0;
                    let pathIndex = 1;
                    for (urlIndex = 1; urlIndex <= route.url.length; urlIndex++) {
                        if (state === 'after-slash') {
                            if (route.url[urlIndex] === undefined) {
                                // The url ended after a matching slash
                                break;
                            } else if (route.url[urlIndex] === ':') {
                                state = 'inside-colon-param';
                                continue;
                            } else {
                                if (pathname[pathIndex] === route.url[urlIndex]) {
                                    pathIndex++;
                                    state = 'matching';
                                } else {
                                    matching = false;
                                    break;
                                }
                            }
                        } else if (state === 'inside-colon-param') {
                            // Retrieve param name from the route url
                            while (urlIndex < route.url.length && route.url[urlIndex] !== '/') {
                                paramName += route.url[urlIndex];
                                urlIndex++;
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
                            req.params[paramName] = decodeURIComponent(paramValue);
                            state = 'after-slash';
                        } else if (state === 'matching') {
                            if (route.url[urlIndex] === undefined) {
                                break;
                            } else if (route.url[urlIndex] === '/') {
                                if (pathname[pathIndex] === '/') {
                                    pathIndex++;
                                    state = 'after-slash';
                                } else {
                                    matching = false;
                                    break;
                                }
                            } else {
                                if (route.url[urlIndex] === pathname[pathIndex]) {
                                    pathIndex++;
                                    continue;
                                } else {
                                    matching = false;
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            if (matching === false) {
                // Check if this is the last unhandled route
                if (i+1 === this.routes.length) {
                    await res.status(404).end('');
                    return;
                }
                continue;
            }

            if (req.query === null) {
                // Handle query string parameters (query)
                req.query = {};
                const pathnameQuestionMarkIndex = pathname.indexOf('?');
                if (pathnameQuestionMarkIndex !== -1) {
                    req.queryString = pathname.substring(pathnameQuestionMarkIndex);
                    const queryParamList = req.queryString.split('&');
                    for (const queryParam of queryParamList) {
                        const queryMiddleIndex = queryParam.indexOf('=');
                        if (queryMiddleIndex === -1) {
                            req.query[queryParam] = '';
                        } else {
                            req.query[queryParam.substring(0, queryMiddleIndex)] = queryParam.substring(queryMiddleIndex + 1);
                        }
                    }
                }
            }

            if (req.cookies === null) {
                // Handle cookies
                req.cookies = {};
                if (req.headers['cookie']) {
                    const cookieList = req.headers['cookie'].split(';').map(pair => pair.trim().split('='));
                    for (const cookie of cookieList) {
                        req.cookies[cookie[0]] = cookie[1];
                    }
                }
            }

            matchCount++;

            try {
                let nextCalled = false;

                let result;

                // @ts-ignore
                if (route.handler.isStatic === true) {
                    // Send an extra parameter to static handlers to aid in finding the file.
                    // @ts-ignore
                    result = route.handler(
                        req,
                        res,
                        function () {
                            nextCalled = true;
                        },
                        route.url === '*' ? '' : route.url.substring(1)
                    );
                } else {
                    // Normal requests get 3 parameters
                    result = route.handler(
                        req,
                        res,
                        function () {
                            nextCalled = true;
                        }
                    );
                }
                let returnedValue = result;
                if (result instanceof Promise) {
                    returnedValue = await result;
                }
                if (returnedValue !== undefined && returnedValue !== null) {
                    throw new Error(`Request handler should not result into anything, got type "${typeof returnedValue}"`);
                }
                // Check if we must stop transversing the routes
                if (res.complete) {
                    return;
                }
                if (nextCalled === false) {
                    return;
                }
                matchCount--;
            } catch (err) {
                if (process.env.NODE_ENV === 'development') {
                    err.message = `Error while handling request: ${err.message}`;
                    console.error(err);
                }
                try {
                    await res.status(500).end(RESPOND_ERRORS_WITH_THE_STACK_TRACE ? '' : err.stack);
                } catch (_err) {
                    // Ignore request-closing error
                }
            }
        }
        if (matchCount === 0) {
            await res.status(404).end('');
        }
    }
}

/**
 * Generates an http or https server app instance with the given configuration
 * @param {{host: 'localhost' | string, port: 8080 | number, ssl?: {key: string, cert: string}}} [config]
 * @returns {MexpressApp}
 */
const mexpress = function mexpress(config = { host: 'localhost', port: 8080 }) {
    if (typeof config !== 'object') {
        throw new Error('Invalid config object parameter');
    }
    const allowedObjectKeys = ['host', 'port', 'ssl'];
    const invalidKeyList = Object.keys(config).filter(key => !allowedObjectKeys.includes(key));

    if (invalidKeyList.length > 0) {
        throw new Error(`Config object has ${invalidKeyList.length === 1 ? 'an' : invalidKeyList.length} unrecognized propert${invalidKeyList.length === 1 ? 'y' : 'ies'}: "${invalidKeyList[0]}".`);
    }

    const app = new MexpressApp(
        config.host || 'localhost',
        config.port || 8080,
        config.ssl || null
    );

    return app;
}

mexpress.MexpressRequest = MexpressRequest;
mexpress.MexpressResponse = MexpressResponse;

/**
 * Returns a route handler to serve static resources
 * This will call next() on the handler if the url contains a '/.' sequence which indicates a request for dotfiles / dotfolders.
 * For example, the following files will trigger a next() call: ['/.env', '/.git/object.txt', '/.env.dev', '/../']
 * @param {string} staticFolderPath
 * @param {{etagFeature?: boolean, lastModifiedFeature?: boolean}} options
 * @returns {function(req: MexpressRequest, res: MexpressResponse, next: () => void): Promise<void>}
 */
mexpress.static = function(staticFolderPath, options = {}) {
    if (arguments.length !== 1) {
        throw new Error(`Static function must receive one parameter, got ${arguments.length}`);
    } else if (typeof staticFolderPath !== 'string') {
        throw new Error(`Static function must receive a string parameter, got ${typeof staticFolderPath}`)
    }

    try {
        const stat = fs.statSync(staticFolderPath);
        if (!stat.isDirectory()) {
            throw new Error('Static path is not a valid directory');
        }
    } catch (err) {
        if (err.code === 'ENOENT') {
            err.message = `Could not find target static folder at "${staticFolderPath}"`
            throw err;
        }
    }

    /** @type {function(req: MexpressRequest, res: MexpressResponse, next: () => void): Promise<void>} */
    const f = async function(req, res, next, extra) {
        if (typeof extra !== 'string') {
            throw new Error('The extra parameter is missing for static handler');
        }
        let url = decodeURIComponent(req.url.pathname.substring(extra.length)).substring(1);

        // Do not handle dot files on the static server due to security implications
        let dotFileIndex = url.indexOf('/.');
        if (dotFileIndex === -1) {
            dotFileIndex = url.indexOf('\\.');
        }
        if (dotFileIndex !== -1) {
            const hashIndex = url.indexOf('#');
            const questionIndex = url.indexOf('?');
            if (
                (hashIndex === -1 && questionIndex === -1) ||
                (hashIndex === -1 && questionIndex !== -1 && dotFileIndex < questionIndex) ||
                (hashIndex !== -1 && dotFileIndex < hashIndex)
            ) {
                return next();
            }
        }

        let fullPath = path.resolve(staticFolderPath, url);
        let isDirectory;
        try {
            isDirectory = await new Promise((resolve, reject) => {
                fs.stat(fullPath, (err, result) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(result.isDirectory());
                    }
                })
            });
        } catch (err) {
            if (err.code === 'ENOENT') {
                next();
                return;
            } else {
                await res.status(500).end(RESPOND_ERRORS_WITH_THE_STACK_TRACE ? (err.stack || err.message) : '');
                return;
            }
        }
        if (isDirectory && fullPath[fullPath.length-1] !== '/') {
            fullPath += '/';
        }
        if (isDirectory) {
            fullPath += 'index.html';
        }
        let lastModifiedTime = new Date();
        try {
            lastModifiedTime = await new Promise((resolve, reject) => {
                fs.stat(fullPath, (err, result) => {
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
        await res.sendFile(fullPath, {
            etagHeader: options.etagFeature,
            lastModifiedHeader: options.lastModifiedFeature,
        });
    };
    f.isStatic = true;
    return f;
}

module.exports = mexpress;