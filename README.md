# Mexpress

(Under development, not for production use)

A fast and brutally minimalist web framework for Nodejs. This library allows you to create a http/https server to route callbacks from requests based on their pathname.

This library:

 - Is minimalist
 - Has no dependencies
 - Does not get new features over time (Only bugfixes)
 - Works for NodeJS 15 or up
 - Is entirely contained in a single javascript file 

It is an alternative to the [Expressjs](http://expressjs.com/) http framework.

## Usage

`npm install mexpress`

```js
const mexpress = require('mexpress');

const app = mexpress({
    host: 'localhost',
    port: 8080,
});

app.use(function(req, res, next) {
    console.log('Request passing through');
    next();
});

app.get('/', function(req, res) {
    console.log('Get handler');
    console.log(req, res);
});

app.listen().catch(console.error);
```

# Usage example

```js
app.get(`/user/:id`, function(req, res) {
    const id = req.params.id;
    if (id === 0) {
        res.status(404).end(`User ${id} not found`);
        return;
    }
    res.sendFile(`./user${id}.html`);
});
```

# Usage help

Scroll down or [click here](#interface) to see the methods and functions exported by this library.

# How does it works

It creates a server with `require('http').createServer` then on every request it tries to match the list of routes with the request pathname, executing the callback if it is matching.

If the callback does not call the `next` method then the route list loop ends and the response is considered handled. If no routes match, or the last route calls `next`, then a 404 (Not Found) response is sent.

# Why / Motivation

Express.js is a huge code base with a hierarchy of dependencies that are hard to validate for security purposes. At the time of writing, `npm i express` installs 56 dependencies, uses 1.88 MB of space and has 153 javascript files with a total of **28.482** lines of code. Even if you could review that much code, express guys work hard to push new major versions with different stuff every full moon.

This library is one source file with 900 lines (33kb) that doesn't update unless a bug or a security concern is found or added by a future NodeJS version.

And it does two things: It creates an http/https server and it also route callbacks from requests based on their pathname.

I also included few helper methods frequently used to handle http responses, such as `.sendFile(path)`, `.json(object)`, and `.redirect(url)`.

### Websockets

Upgrade requests are not handled by the library.

Although I don't think it is a good idea, you can do it manually by using the `primitive` property of the request that has an object of the IncomingMessage class. A good starting point is [this tutorial](https://medium.com/hackernoon/implementing-a-websocket-server-with-node-js-d9b78ec5ffa8).

Here's a minimal implementation:

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
        
        // Receive data (in websocket protocol)
        socket.on('data', data => {
            console.log('Raw buffer data received at server:', data);
        });
        
        socket.on('close', () => {
            console.log('Client disconnected');
        })
    })
})
```

I may create a example repository of how to get `socket.io` to work with this library.

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

## Path and parameters

You can use a single asterisk as a path to match with everything, aside from that, paths can be of the following formats (one per line):

```text
/
/foo
/user/
/user/:id
/user/:id/posts
/user/:id/posts/:postId
/public/index.html
/public/hello.txt/secret.txt
/.git/object
/~yes/
```

The parametric paths (such as `/user/:id`) specifies a param variable in its path and is available at the callback on the request object in the `param` property. Parametric objects can be used like this:

```js
app.get('/user/:id', (req, res) => {
    res.end(`The id is ${res.params.id}`);
});
```

In the example above, when the client sends a request with the path string as `/user/foo` then the `req.params.id` will have the value `foo`.

Query string parameters, also known as GET parameters, are the parameters present after the `?` (question mark) on an url. They are parsed and are available at the `query` property of the request and for a request url like `/?id=foo` can be accessed by `req.query.id`, for example.

## Internal primitives

This library handles 3 internal objects for you, they are acessible at:

```js
req.primitive instanceof http.IncomingRequest;
res.primitive instanceof http.ServerResponse;
app.server instanceof http.Server;
```

# Interface

### app = mexpress(config)

Creates an instance of the mexpress app. Serves as a representation of the server and has an interface to add routes and to start listening.

- **Syntax**

```text
function mexpress(config: {
    host?: string,
    port?: number,
    ssl?: {key: string, cert: string}
}): MexpressApp
```

- **Usage example** with the default values:

```js
const mexpress = require('mexpress');
const app = mexpress({
    host: 'localhost',
    port: 8080,
    ssl: null
});
app.listen();
```

### static()

Returns an asyncronous route callback that serves files on a path and its subpaths.

If the file is not found, then the route exits without finishing the request (it calls `next`) so that other handlers can deal with it.

Warning: When this handler detects the `/.` sequence in the pathname it will skip the router due to security concerns (dotfiles are usually where passwords are saved). If you want to serve these (such as a `.env` file) you will need to explicily handle them.

 - Syntax

```text
app.static(
    rootDirectory
): (req, res, next) => Promise<void>
```

 - Usage example for all files

```js
app.use('*', nexpress.static(
    path.resolve(__dirname, 'public')
));
```

### app.get(path, callback)

Register a route of the GET method to a callback.

 - **Syntax**

```text
app.get(
    path: string,
    callback: (req: MexpressRequest, res: MexpressResponse, next: () => any) => any
)
```

 - **Usage example**

```js
const app = mexpress();
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

- **Usage example**

```js
const app = mexpress();
app.post('/login', async (req, res) => {
    const text = await req.getBodyAsText();
    if (text[0] !== '{') {
        return res.status(400).end('Expected valid json object as body');
    }
    const json = await req.getBodyAsJson();
    await database.create('user', json);
    
    res.end('User added successfully');
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

Register a route that matches all methods (will not check) to a certain pathname.

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

const sessions = new Map();

sessions.set('foo', { data: 123 })

app.use('*', async (req, res, next) => {
    const session = sessions.get(req.headers['authorization']);
    if (!session) {
        res.status(401).end('Unauthorized');
        return;
    }
    next();
});

app.get('/', (req, res) => {
    res.end('You are logged in');
});
```

## How to read headers

Headers are inside the request object `headers` property as key-value pairs, the keys are always lowercase.

```js
app.get('/', (req, res) => {
    const auth = req.headers['authorization'];
    res.end(auth);
});
```

## How to write headers

Headers are written by calling `setHeader` method on the response object:

```js
app.get('/', (req, res) => {
    res.setHeader('set-cookie', 'a=1');
    res.end(auth);
});
```

### Author

This framework was written entirely by me (Guilherme Rossato) over a few days. It is currently being maintained by me until all the bugs are solved and will then enter a frozen state.
