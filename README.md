# Mexpress

(Under development, not for production use)

A fast and brutally minimalist web-server handling module for Nodejs. It allows you to create a http/https server to route callbacks from requests based on their pathname.

This library:

 - Is minimalist
 - Has no dependencies
 - Is stable (no new features)
 - Is a single javascript file with less than 1000 lines of code.

This project is just a minimalist alternative to the [Expressjs](http://expressjs.com/) http framework.

## Usage

`npm install mexpress`

```js
const mexpress = require('mexpress');

const app = mexpress();

app.use('*', (req, res, next) => {
    if (!req.query.token) {
        res.status(401).end('Missing token');
        return;
    }
    next();
});

app.post('/', async (req, res) => {
    const data = await req.getBodyAsJson();
    res.json(data);
});

app.get('/', (req, res) => {
    res.sendFile('index.html');
});

app.listen(8080, 'localhost', () => {
    console.log('Started listening at http://' + app.host + ':' + app.port);
});
```

# Interface reference

Every exported variable / method from this library is described on this very document you are reading. Here is a simplistic list of interfaces for reference, scroll down or [click here](#interface) for deeper explanations on each interface.

```js
// Server (MexpressServer)
const app = require('mexpress')(); // Creates an app instance
app.any(path: string, callback: function); // Adds a callback to any method on a path
app.get(path: string, callback: function); // Adds a callback to the GET HTTP method on a path 
app.post(path: string, callback: function); // Adds a callback to the POST HTTP method on a path
app[method](path: string, callback: function);  // Adds a callback to a specific HTTP method on a path
app.static(path: string, target: string); // Adds a static file handler to a target file or a folder and all its subfolders
```

```js
// Request (MexpressRequest)
request.params // key-value object for the parameters on the path of the url
request.url // the url string
request.query // key-value object with the name and the value of the query string parameters after the question mark in a url
request.cookies // object where each key is a cookie name and each value is the cookie value
request.getBodyAsBinary(): Promise<Buffer> // Method to get all the request body as a binary buffer
request.getBodyAsText([encoding]): Promise<string> // Get the request body as a string
request.getBodyAsJson(): Promise<any> // Get the request body as a json object
```

```js
// Response (MexpressResponse)
response.status(code); // Sets the response status code (does not sends the http header)
response.header(name, value); // Sets a header value (does not sends the http header)
response.setHeader(name, value); // Same as above
response.write(data: Buffer | string): Promise<void>; // Writes data to the response (will send the http headers if weren't sent yet)
response.end([data]: Buffer | string, [encoding] = 'utf8'): Promise<void>; // Finishes the http response, optionally adds a final data to the response
response.json(data: any): Promise<void>; // Finishes the http response with a stringified JSON object as response.
response.sendFile(path: string): Promise<void>; // Finishes the http response by streaming a file, populates the content-type header from the file extension
response.redirect(url: string, [statusCode] = 302) // Sends a response with headers that instruct the browser to go to the destination url (temporary redirect if status is 302)
```

Each method is described better on the [Interface](#interface) section.

# How it works

This library essentially exports a function that routes request in a linear fashion, allowing you to call `next` on each to go to the next one and also providing some useful helper methods.

If no route matches (reaches the end of the route list) then the request is considered unhandled and a 404 status is sent to the client.

# Why / Motivation

Express.js is a huge code base with a hierarchy of dependencies that are hard to validate for security purposes. At the time I write this the command `npm install express` installs 56 dependencies, downloading 153 javascript files and uses 1.88 MB of disk. That is a total of **28.482** lines of code. Even if you could review that much code express devs work hard to push new major versions with different features every now and then and even provide you with a "upgrade guide". How nice of them!

This library is one source file with 958 lines (52 times smaller by file size) that does not update. The interface is solid, frozen in time.

There are some situations in which updates in nodejs, new http specification, security concerns, bugs, etc, might need this library to update. But the general rule of thumb is: Decrease the work the developer has to do in order to keep their previous apps running.

This library is supposed to do two things: Create a function that can be passed to native nodejs http/https server and route callbacks from requests based on their path pattern.

I included a few helper methods frequently used to handle http requests and responses, such as `.getBodyAsText()`, `.sendFile(filepath)`, `.json(object)`, and `.redirect(url)`, but those were either already present on express or are just too useful to leave them out.

## Handling Cross Origin Resource Security

This is the example of a permissive handling of CORS using this library to get you started:

```js
app.options('*', (req, res) => {
    const origin = req.headers['origin'] || '*';
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,HEAD,PUT,DELETE,CONNECT,OPTIONS,PATCH,TRACE');
    res.setHeader('Access-Control-Allow-Headers', 'content-type,content-length,authorization,pragma,cache-control,referer');
    res.end();
    return;
})
```

## Creating a HTTPS server for production

Do the same thing you would do with express:

```js
const mexpress = require('mexpress');
const https = require('https');
const app = mexpress();
const server = https.createServer({key: key, cert: cert }, app);
server.listen(443, '0.0.0.0', () => console.log('Listening at https://0.0.0.0:443/'));
```

### Websockets

Upgrade requests are not handled by the library, you can listen to the upgrade event on the native http/https server using the `primitive` property of the request (it has the `IncomingRequest` instance, which is an event emitter that emits `upgrade` events) and handle it with a library or manually, like this:

```js
const crypto = require('crypto');

app.get('/', (req, res) => {
    req.primitive.on('upgrade', function(primitive, socket) {
        if (primitive.headers['upgrade'] !== 'websocket') {
            socket.end('HTTP/1.1 400 Bad Request');
            return;
        }
        // Reply with a normal handshake
        socket.write('HTTP/1.1 101 Web Socket Protocol Handshake\r\n');
        socket.write('Upgrade: WebSocket\r\n');
        socket.write('Connection: Upgrade\r\n');
        
        // Handle websocket security level (key exchange)
        const clientWebsocketKey = primitive.headers['sec-websocket-key'];
        const serverWebsocketKey = crypto
            .createHash('sha1')
            .update(acceptKey + '258EAFA5-E914–47DA-95CA-C5AB0DC85B11', 'binary')
            .digest('base64');
        socket.write(`Sec-WebSocket-Accept: ${serverWebsocketKey}\r\n`);
        
        // Select the first protocol the client says he accepts
        const protocol = (req.headers['sec-websocket-protocol'] || '').split(',')[0].trim();
        socket.write(`Sec-WebSocket-Accept: ${protocol}\r\n`);
        
        // Finishes the connection header
        socket.write(`\r\n\r\n`);
        
        // Handle other socket events such as 'data' and 'end'.
    })
})
```

I may create a example repository of how to get `socket.io` to work with this library.

## Path patterns and parameters

Path patterns are strings you use to direct urls to callback, they work similarly to express:

There are three types of paths you can have in this library:

1. The wildcard, which is a single string with the asterisk: `*`, that matches every path.
2. A basic path, which is static and full, such as `/` or `/api/users`.
3. A parametrized path, which contains one or more parameters such as `/user/:id` or `/:project/:file`

Parametric paths (such as `/user/:id`) specifies a param variable in its path and is available at the callback on the request object in the `param` property. Parametric objects can be used like this:

```js
app.patch('/user/:id', (req, res) => {
    res.end(`The id is ${res.params.id}`);
});
```

In the example above, when a request is received with the path url as `/user/foo` the `req.params.id` variable will have the value `foo`. All values are guaranted to be strings.

Query string parameters, also known as GET parameters, are the parameters present after the `?` (question mark) on an url, such as `/?username=john`. They are parsed and are available at the `query` property of the request and for a request url like `/?id=foo` can be accessed by `req.query.id`, for example.

## Static folders

Sometimes you need to serve a folder as static resources, it is done like this:

```js
const mexpress = require('mexpress');
const app = mexpress();
app.use('*', mexpress.static(
    path.resolve(__dirname, 'public')
))
app.listen(8080, 'localhost');
```

Be aware that files such as `./public/.env` are served to requests to `/.env` (if they are present).

`use` requires the first argument to be a string because there are no variable function signatures in this library. This helps in keeping is complexity and volatility at a minimum. Either use `*` or `/` to match everything or specify a mount point, such as `/public`, for example:

You can serve files from virtual path prefix, serving file such as `./public/index.html` at the url `/static/index.html` like this:

```js
app.use('/static', mexpress.static('public'));
```

It should be noted that `/static/index.html` is also the default file for the directory, so it is also available by requesting `/static/`.

## Static files

To serve static files, you also use the `static` method, but with a file path as the function parameter:

```js
app.get('/', mexpress.static('./public/index.html'));
app.get('/static.html', mexpress.static('./public/static.html'));
```

Remember that if the files are not found then `.next()` will be called and the other routes might handle these static files.

## Internal primitives

You can access the primitives `IncomingRequest`, `ServerResponse` and `Server` at the following properties:

```js
request.primitive instanceof http.IncomingRequest;
response.primitive instanceof http.ServerResponse;
app.server instanceof http.Server;
```

Note that `app.server` is only available if you created the server by calling `app.listen()`, as opposed to `require('http').createServer(app)`, because the later situation leaves the library without access to the primitive server object.

# Interface

This library exports 2 things:

1. A top level method to create the Mexpress application
2. A `static` method to create static routes

The library also exports some extra classes for typing or mocking purposes, you probably won't need them, but for reference, here they are:

3. A server class that is returned by the top level method that has methods to add route handlers
4. A request class called MexpressRequest to wrap `IncomingRequest` predictably while adding some extra helper methods
5. A response class called MexpressResponse to wrap `ServerResponse` predictably while adding some extra helper methods

### require('mexpress')()

Creates a server instance to represent your app. This representation is a `MexpressServer` and has methods to add routes, to add middlewares, and to start listening to a port. It can also be used as a function that receives raw request/response objects and routes callback accordingly.

- **Syntax**

```text
mexpress(): MexpressApp
```

- **Usage example**: Creates an Mexpress application

```js
const mexpress = require('mexpress');
const app = mexpress();
```

### static()

Returns an asyncronous route callback that serves files on a path and its subpaths.

If the file is not found, then the route exits without finishing the request (it calls `next`) so that other handlers can deal with it.

Warning: When this handler detects the `/.` sequence in the pathname it will skip the router due to security concerns (dotfiles are usually where passwords are saved). If you want to serve these (such as a `.env` file) you will need to explicily handle them.

 - **Syntax**

```text
app.static(fileOrDirectoryPath: string): (req, res, next) => Promise<void>
```

 - Usage example to route all file requests from public folder (including dotfiles such as `./public/.env`)

```js
app.use('*', nexpress.static(
    path.resolve(__dirname, 'public')
));
```

The above example allows someone to request `/` and get `./public/index.html`, but it also allows someone to request `/.env` and get `./public/.env` and any sub folder such as requesting `/hello/index.html` to get `./public/hello/index.html`.

### app.get(path, callback)

Register a route of the GET method to a callback.

 - **Syntax**

```text
app.get(
    path: string,
    callback: (req: MexpressRequest, res: MexpressResponse, next: () => any) => any
)
```

 - **Usage example**: Add a route to the `/login` GET request:

```js
app.get('/login', (req, res) => {
    res.end('Hello world');
});
```

### app.post(path, callback)

Register a route of the POST method to a callback.

- **Syntax**

```text
app.post(
    path: string,
    callback: (req: MexpressRequest, res: MexpressResponse, next: () => any) => any
);
```

- **Usage example**: Add a route to the `/login` POST request and handle it:

```js
app.post('/login', async (req, res) => {
    const text = await req.getBodyAsText();
    if (!text) {
        return res.status(400).end('Got empty body');
    }
    res.end('POST Body: ' + text);
});
```

### Other HTTP methods

All HTTP methods have their corresponding function to add route:

```typescript
app.get(path, callback);
app.post(path, callback);
app.head(path, callback);
app.put(path, callback);
app.delete(path, callback);
app.connect(path, callback);
app.options(path, callback);
app.patch(path, callback);
app.trace(path, callback);
```

### app.use(path, callback)

Register a route that matches only the path pattern (does not check the method).

- **Syntax**

```text
app.use(
    path: string,
    callback: (req: MexpressRequest, res: MexpressResponse, next: () => any) => any
)
```

- **Usage example**

```js
const app = mexpress();

app.use('*', async (req, res, next) => {
    if (req.headers['authorization'] !== 'Bearer my-auth-token') {
        return res.status(401).end('Unauthorized');
    }
    next();
});

app.get('/', (req, res) => {
    res.end('Welcome, bearer of ' + req.headers['authorization'].substring(7));
});
```

## How to read headers from the Request

Headers are inside the request object `headers` property as key-value pairs, the keys are always lowercase.

```js
app.get('/', (req, res) => {
    const auth = req.headers['authorization'];
    res.end(auth);
});
```

## How to write headers to the Response

Headers are written by calling `setHeader` method on the response object:

```js
app.get('/', (req, res) => {
    res.setHeader('set-cookie', 'a=1');
    res.end(auth);
});
```

### Author

This framework was written entirely by me (Guilherme Rossato) over a few days. It is currently being maintained by me until all the bugs are solved and will eventually enter a state where it wont get updates unless absolutely necessary.
