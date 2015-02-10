/******************** Library Classes ********************/
class Rocky {
    _handlers = null;
    
    // Settings:
    _timeout = 10;
    _strictRouting = false;
    _allowUnsecure = false;
    _accessControl = true;
    
    constructor(settings = {}) {
        if ("timeout" in settings) _timeout = settings.timeout;
        if ("allowUnsecure" in settings) _allowUnsecure = settings.allowUnsecure;
        if ("strictRouting" in settings) _strictRouting = settings.strictRouting;
        if ("accessControl" in settings) _accessConrol = settings.accessControl;

        _handlers = { 
            authorize = _defaultAuthorizeHandler.bindenv(this),
            onUnauthorized = _defaultUnauthorizedHandler.bindenv(this),
            onTimeout = _defaultTimeoutHandler.bindenv(this), 
            onNotFound = _defaultNotFoundHandler.bindenv(this),
            onException = _defaultExceptionHandler.bindenv(this),
        };
        
        http.onrequest(_onrequest.bindenv(this));
    }
    
    /************************** [ PUBLIC FUNCTIONS ] **************************/
    function on(verb, signature, callback) {
        // Register this signature and verb against the callback
        verb = verb.toupper();
        signature = signature.tolower();
        if (!(signature in _handlers)) _handlers[signature] <- {};
        
        local routeHandler = Rocky.Route(callback);
        _handlers[signature][verb] <- routeHandler;

        return routeHandler;
    }
    
    function post(signature, callback) {
        return on("POST", signature, callback);
    }
    
    function get(signature, callback) {
        return on("GET", signature, callback);
    }
    
    function put(signature, callback) {
        return on("PUT", signature, callback);
    }
    
    function authorize(callback) {
        _handlers.authorize <- callback;
        return this;
    }
    
    function onUnauthorized(callback) {
        _handlers.onUnauthorized <- callback;
        return this;
    }
    
    function onTimeout(callback, timeout = 10) {
        _handlers.onTimeout <- callback;
        _timeout = timeout;
        return this;
    }
    
    function onNotFound(callback) {
        _handlers.onNotFound <- callback;
        return this;
    }
    
    function onException(callback) {
        _handlers.onException <- callback;
        return this;
    }

    // Adds access control headers
    function _addAccessControl(res) {
        res.header("Access-Control-Allow-Origin", "*")
        res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
        res.header("Access-Control-Allow-Methods", "POST, PUT, GET, OPTIONS");
    }
    
    /************************** [ PRIVATE FUNCTIONS ] *************************/
    function _onrequest(req, res) {
        
        // Add access control headers if required
        if (_accessControl) _addAccessControl(res);
        
        // Setup the context for the callbacks
        local context = Rocky.Context(req, res);
        
        // Check for unsecure reqeusts
        if (_allowUnsecure == false && "x-forwarded-proto" in req.headers && req.headers["x-forwarded-proto"] != "https") {
            context.send(405, "HTTP not allowed.");
            return;
        }
        
        // Parse the request body back into the body
        try {
            req.body = _parse_body(req);
        } catch (e) {
            server.log("Parse error '" + e + "' when parsing:\r\n" + req.body)
            context.send(400, e);
            return;
        }

        // Look for a handler for this path
        local route = _handler_match(req);
        if (route) {
            // if we have a handler
            context.path = route.path;
            context.matches = route.matches;
            
            // parse auth
            context.auth = _parse_authorization(context);
            
            // Create timeout
            local onTimeout = _handlers.onTimeout;
            local timeout = _timeout;
            
            if (route.handler.hasTimeout()) {
                onTimeout = route.handler.onTimeout; 
                timeout = route.handler.timeout;
            }
            
            context.setTimeout(_timeout, onTimeout);
            route.handler.execute(context, _handlers);
        } else {
            // if we don't have a handler
            _handlers.onNotFound(context);
        }
    }

    function _parse_body(req) {
        if ("content-type" in req.headers && req.headers["content-type"] == "application/json") {
            if (req.body == "" || req.body == null) return null;
            return http.jsondecode(req.body);
        }
        if ("content-type" in req.headers && req.headers["content-type"] == "application/x-www-form-urlencoded") {
            return http.urldecode(req.body);
        }
        if ("content-type" in req.headers && req.headers["content-type"].slice(0,20) == "multipart/form-data;") {
            local parts = [];
            local boundary = req.headers["content-type"].slice(30);
            local bindex = -1;
            do {
                bindex = req.body.find("--" + boundary + "\r\n", bindex+1);
                if (bindex != null) {
                    // Locate all the parts
                    local hstart = bindex + boundary.len() + 4;
                    local nstart = req.body.find("name=\"", hstart) + 6;
                    local nfinish = req.body.find("\"", nstart);
                    local fnstart = req.body.find("filename=\"", hstart) + 10;
                    local fnfinish = req.body.find("\"", fnstart);
                    local bstart = req.body.find("\r\n\r\n", hstart) + 4;
                    local fstart = req.body.find("\r\n--" + boundary, bstart);
                    
                    // Pull out the parts as strings
                    local headers = req.body.slice(hstart, bstart);
                    local name = null;
                    local filename = null;
                    local type = null;
                    foreach (header in split(headers, ";\n")) {
                        local kv = split(header, ":=");
                        if (kv.len() == 2) {
                            switch (strip(kv[0]).tolower()) {
                                case "name":
                                    name = strip(kv[1]).slice(1, -1);
                                    break;
                                case "filename":
                                    filename = strip(kv[1]).slice(1, -1);
                                    break;
                                case "content-type":
                                    type = strip(kv[1]);
                                    break;
                            }
                        }
                    }
                    local data = req.body.slice(bstart, fstart);
                    local part = { "name": name, "filename": filename, "data": data, "content-type": type };

                    parts.push(part);
                }
            } while (bindex != null);
            
            return parts;
        }
        
        // Nothing matched, send back the original body
        return req.body;
    }

    function _parse_authorization(context) {
        if ("authorization" in context.req.headers) {
            local auth = split(context.req.headers.authorization, " ");
            
            if (auth.len() == 2 && auth[0] == "Basic") {
                // Note the username and password can't have colons in them
                local creds = http.base64decode(auth[1]).tostring();
                creds = split(creds, ":"); 
                if (creds.len() == 2) {
                    return { authType = "Basic", user = creds[0], pass = creds[1] };
                }
            } else if (auth.len() == 2 && auth[0] == "Bearer") {
                // The bearer is just the password
                if (auth[1].len() > 0) {
                    return { authType = "Bearer", user = auth[1], pass = auth[1] };
                }
            }
        }
        
        return { authType = "None", user = "", pass = "" };
    }
    
    function _extract_parts(routeHandler, path, regexp = null) {
        local parts = { path = [], matches = [], handler = routeHandler };
        
        // Split the path into parts
        foreach (part in split(path, "/")) {
            parts.path.push(part);
        }
        
        // Capture regular expression matches
        if (regexp != null) {
            local caps = regexp.capture(path);
            local matches = [];
            foreach (cap in caps) {
                parts.matches.push(path.slice(cap.begin, cap.end));
            }
        }
        
        return parts;
    }
    
    function _handler_match(req) {
        local signature = req.path.tolower();
        local verb = req.method.toupper();

        // ignore trailing /s if _strictRouting == false
        if(!_strictRouting) {
            while (signature.len() > 1 && signature[signature.len()-1] == '/') {
                signature = signature.slice(0, signature.len()-1);
            }
        }

        if ((signature in _handlers) && (verb in _handlers[signature])) {
            // We have an exact signature match
            return _extract_parts(_handlers[signature][verb], signature);
        } else if ((signature in _handlers) && ("*" in _handlers[signature])) {
            // We have a partial signature match
            return _extract_parts(_handlers[signature]["*"], signature);
        } else {
            // Let's iterate through all handlers and search for a regular expression match
            foreach (_signature,_handler in _handlers) {
                if (typeof _handler == "table") {
                    foreach (_verb,_callback in _handler) {
                        if (_verb == verb || _verb == "*") {
                            try {
                                local ex = regexp(_signature);
                                if (ex.match(signature)) {
                                    // We have a regexp handler match
                                    return _extract_parts(_callback, signature, ex);
                                }
                            } catch (e) {
                                // Don't care about invalid regexp.
                            }
                        }
                    }
                }
            }
        }
        return null;
    }
    
    /*************************** [ DEFAULT HANDLERS ] *************************/
    function _defaultAuthorizeHandler(context) {
        return true;
    }
    
    function _defaultUnauthorizedHandler(context) {
        context.send(401, "Unauthorized");
    }
    
    function _defaultNotFoundHandler(context) {
        context.send(404, format("No handler for %s %s", context.req.method, context.req.path));
    }
    
    function _defaultTimeoutHandler(context) {
        context.send(500, format("Agent Request Timedout after %i seconds.", _timeout));
    }
    
    function _defaultExceptionHandler(context, ex) {
        context.send(500, "Agent Error: " + ex);
    }
}

class Rocky.Route {
    handlers = null;
    timeout = null;
    
    _callback = null;
    
    constructor(callback) {
        handlers = {};
        timeout = 10;
        
        _callback = callback;
    }
    
    /************************** [ PUBLIC FUNCTIONS ] **************************/
    function execute(context, defaultHandlers) {
        try {
            // setup handlers
            foreach (handlerName, handler in defaultHandlers) {
                if (!(handlerName in handlers)) handlers[handlerName] <- handler;
            }

            if(handlers.authorize(context)) {
                _callback(context);
            }
            else {
                handlers.onUnauthorized(context);
            }
        } catch(ex) {
            handlers.onException(context, ex);
        }
    }
    
    function authorize(callback) {
        handlers.authorize <- callback;
        return this;
    }
    
    function onException(callback) {
        handlers.onException <- callback;
        return this;
    }
    
    function onUnauthorized(callback) {
        handlers.onUnauthorized <- callback;
        return this;        
    }
    
    function onTimeout(callback, t = 10) {
        handlers.onTimeout <- callback;
        timeout = t;
        return this;
    }
    
    function hasTimeout() {
        return ("onTimeout" in handlers);
    }
}

class Rocky.Context {
    req = null;
    res = null;
    sent = false;
    id = null;
    time = null;
    auth = null;
    path = null;
    matches = null;
    timer = null;
    static _contexts = {};

    constructor(_req, _res) {
        req = _req;
        res = _res;
        sent = false;
        time = date();
        
        // Identify and store the context
        do {
            id = math.rand();
        } while (id in _contexts);
        _contexts[id] <- this;
    }
    
    /************************** [ PUBLIC FUNCTIONS ] **************************/
    function get(id) {
        if (id in _contexts) {
            return _contexts[id];
        } else {
            return null;
        }
    }
    
    function isbrowser() {
        return (("accept" in req.headers) && (req.headers.accept.find("text/html") != null));
    }
    
    function getHeader(key, def = null) {
        key = key.tolower();
        if (key in req.headers) return req.headers[key];
        else return def;
    }
    
    function setHeader(key, value) {
        return res.header(key, value);
    }
    
    function send(code, message = null) {
        // Cancel the timeout
        if (timer) {
            imp.cancelwakeup(timer);
            timer = null;
        }
        
        // Remove the context from the store
        if (id in _contexts) {
            delete Rocky.Context._contexts[id];
        }

        // Has this context been closed already?
        if (sent) {
            return false;
        } 
        
        if (message == null && typeof code == "integer") {
            // Empty result code
            res.send(code, "");
        } else if (message == null && typeof code == "string") {
            // No result code, assume 200
            res.send(200, code);
        } else if (message == null && (typeof code == "table" || typeof code == "array")) {
            // No result code, assume 200 ... and encode a json object
            res.header("Content-Type", "application/json; charset=utf-8");
            res.send(200, http.jsonencode(code));
        } else if (typeof code == "integer" && (typeof message == "table" || typeof message == "array")) {
            // Encode a json object
            res.header("Content-Type", "application/json; charset=utf-8");
            res.send(code, http.jsonencode(message));
        } else {
            // Normal result
            res.send(code, message);
        }
        sent = true;
    }
    
    function setTimeout(timeout, callback) {
        // Set the timeout timer
        if (timer) imp.cancelwakeup(timer);
        timer = imp.wakeup(timeout, function() {
            if (callback == null) {
                send(502, "Timeout");
            } else {
                callback(this);
            }
        }.bindenv(this))
    }
}

class SettingsManager {
    _rocky = null;
    
    _writeKey = null;
    _readKey = null;

    _data = null;
    
    constructor(rocky, writeKey = null, readKey = null) {
        _rocky = rocky;
        
        _writeKey = writeKey;
        _readKey = readKey;
        
        _data = server.load();
        
        _init();
    }
    
    function set(key, value) {
        if (!(key in _data)) _data[key] <- null;
        _data[key] = value;
        server.save(_data);
    }
    
    function get(key) {
        if (key in _data) return _data[key];
        return null;
    }
    
    function clear() {
        server.save({});
    }
    
    function _render() {
        return @"<!DOCTYPE html>
        <html lang='en'>
        <head>
            <title>Settings Manager</title>
            <link href='//cdn.jsdelivr.net/foundation/5.0.2/css/foundation.min.css' rel='stylesheet'>
            <link href='//cdnjs.cloudflare.com/ajax/libs/font-awesome/4.0.3/css/font-awesome.css' rel='stylesheet'>
            
            <script src='//ajax.googleapis.com/ajax/libs/jquery/1.9.1/jquery.min.js'></script>
            <script src='//rawgit.com/jdorn/json-editor/master/dist/jsoneditor.js'></script>
            
            <script src='//cdnjs.cloudflare.com/ajax/libs/foundation/5.5.0/css/foundation.min.css'></script>
            <script src='//cdnjs.cloudflare.com/ajax/libs/foundation/5.5.0/js/foundation/foundation.alert.min.js'></script>
            
            
            <script>
                // Set the default CSS theme and icon library globally
                JSONEditor.defaults.theme = 'foundation5';
                JSONEditor.defaults.iconlib = 'fontawesome4';
            </script>
        </head>
        <body>
            <div class='row' id='messages'></div>
            
            <div class='row'>
                <div class='medium-12 columns'>
                    <h1>Settings Manager</h1>
                </div>
            </div>
            <div class='row'>
                <div id='editor_holder' class='medium-12 columns'></div>
            </div>
            <div class='row'>
                <div class='medium-12 columns'>
                    <button id='submit' class='tiny'>Save</button>
                    <button id='revert' class='tiny'>Revert</button>
                    <span id='valid_indicator' class='label success'>valid</span>
                </div>    
            </div>
            

            <script type='text/javascript'>
            function logMessage(message, messageClass, autoclear) {
                autoclear = autoclear || true;
                var t = new Date().getTime();
                $('#messages').prepend('<div id=\'' + t + '\' data-alert class=\'alert-box ' + messageClass + ' radius\'>' + message + '<a href=\'#\' class=\'close\'>&times;</a></div>');
                if (autoclear) {
                    window.setTimeout(function() { $('#' + t).fadeOut(); }, 3000);
                }
                $('.alert-box > a.close').click(function() { $(this).closest('[data-alert]').fadeOut(); });
            }
            
            // agent.electricimp.com/{agentId}/settings
            var rootUrl = document.location.origin + document.location.pathname;
            
            var editor = new JSONEditor(document.getElementById('editor_holder'),{
                // Enable fetching schemas via ajax
                ajax: true,
                schema: { 
                    title: 'Settings'
                }
            }); // new JSONEditor   

            editor.on('change',function() {
                // Get an array of errors from the validator
                var errors = editor.validate();
                
                var indicator = document.getElementById('valid_indicator');
                
                // Not valid
                if(errors.length) {
                  indicator.style.color = 'red';
                  indicator.textContent = 'not valid';
                }
                // Valid
                else {
                  indicator.style.color = 'green';
                  indicator.textContent = 'valid';
                }
            });

            $.get(rootUrl + '.json', function(data) {
                editor.setValue(data);
                logMessage('Succesfully loaded settings', 'success' );
            });
            
            $('#submit').click(function() {
                $.ajax({
                   type: 'POST',
                   url: rootUrl + '.json', 
                   data: JSON.stringify(editor.getValue()),
                   dataType: 'json',
                   headers: { 'Content-Type': 'application/json' }
                })
                .done(function(data) {
                    editor.setValue(data);
                    logMessage('Sucessfully saved and reloaded settings.', 'success')
                })
                .fail(function() {
                    logMessage('Error saving settings', 'alert')  
                });
            });
            
            $('#revert').click(function() {
                $.ajax({
                    type: 'GET',
                    url: rootUrl + '.json',
                    dataType: 'json'
                })
                .done(function(data) {
                    editor.setValue(data);
                    logMessage('Sucessfully reloaded settings.', 'success')
                })
                .fail(function() {
                    logMessage('Error fetching settings', 'alert')  
                });;  
            });
            
            </script>
        </body>
        </html>";
    }
    
    
    function _init() {
        _rocky.get("/settings(/[^/]+)*\\.json", function(context) {
            // base case (/settings.json)
            if (context.path.len() == 1 && context.path[0] == "settings.json") {
                context.send(_data);
                return;
            }
            
            // clean up the path variables (remove first, and strip .json from last)            
            context.path.remove(0);
            context.path[context.path.len()-1] = split(context.path[context.path.len()-1], ".")[0];
            
            local data = _data;
            for(local idx = 0; idx < context.path.len(); idx++) {
                if (typeof(data) == "table" && context.path[idx] in data) {
                    data = data[context.path[idx]];
                } else {
                    context.send(404, "Element not found.");
                    return;
                }
            }

            context.send(200, http.jsonencode(data));
        }.bindenv(this));
        
        _rocky.put("/settings(/[^/]+)*\\.json", function(context) {
            // base case (/settings.json)
            if (context.path.len() == 1 && context.path[0] == "settings.json") {
                _data = context.req.body;
                server.save(_data)
                context.send(_data);
                return;
            }
            
            // clean up the path variables (remove first, and strip .json from last)            
            context.path.remove(0);
            context.path[context.path.len()-1] = split(context.path[context.path.len()-1], ".")[0];
            
            local data = _data.weakref();
            local idx = 0;
            for(idx; idx < context.path.len()-1; idx++) {
                if (typeof(data.ref()) == "table" && context.path[idx] in data) {
                    data = data.ref()[context.path[idx]].weakref();
                } else {
                    context.send(404, "Element not found.");
                    return;
                }
            }
            
            if(!(context.path[idx] in data.ref())) {
                context.send(404, "Element not found.");
                return;
            }
            data.ref()[context.path[idx]] = context.req.body;
            server.save(_data)
            context.send(_data);
        }.bindenv(this));
        
        _rocky.post("/settings(/[^/]+)*\\.json", function(context) {
            // base case (/settings.json)
            if (context.path.len() == 1 && context.path[0] == "settings.json") {
                _data = context.req.body;
                server.save(_data)
                context.send(_data);
                return;
            }

            // clean up the path variables (remove first, and strip .json from last)
            context.path.remove(0);
            context.path[context.path.len()-1] = split(context.path[context.path.len()-1], ".")[0];
            
            local data = _data.weakref();
            local idx = 0;
            for(idx; idx < context.path.len()-1; idx++) {
                if (typeof(data.ref()) == "table" && context.path[idx] in data.ref()) {
                    data = data.ref()[context.path[idx]].weakref();
                } else {
                    data.ref()[context.path[idx]] <- null;
                    data = data.ref()[context.path[idx]].weakref()
                }
            }
            
            if(!(context.path[context.path.len()-1] in data.ref())) {
                data.ref()[context.path[idx]] <- null;
            }
            data.ref()[context.path[idx]] = context.req.body;
            server.save(_data);
            context.send(_data);
        }.bindenv(this));
        
        _rocky.on("delete", "/settings(/[^/]+)*\\.json", function(context) {
            // base case (/settings.json)
            if (context.path.len() == 1 && context.path[0] == "settings.json") {
                _data = {};
                server.save(_data)
                context.send(_data);
                return;
            }

            // clean up the path variables (remove first, and strip .json from last)
            context.path.remove(0);
            context.path[context.path.len()-1] = split(context.path[context.path.len()-1], ".")[0];
            
            local data = _data.weakref();
            local idx = 0;
            for(idx; idx < context.path.len()-1; idx++) {
                server.log(context.path[idx])
                if (typeof(data.ref()) == "table" && context.path[idx] in data.ref()) {
                    server.log("found");
                    data = data.ref()[context.path[idx]].weakref();
                    server.log("really found");
                } else {
                    context.send(404, "Element not found.");
                    return;
                }
            }
            
            if(!(context.path[context.path.len()-1] in data.ref())) {
                context.send(404, "Element not found.");
                return;
            }
            
            delete data.ref()[context.path[idx]];
            server.save(_data);
            context.send(_data);
        }.bindenv(this));
        
        _rocky.get("/settings", function(context) {
            context.send(_render())
        }.bindenv(this));
    }
    
}

/******************** Application Code ********************/

app <- Rocky();
settings <- SettingsManager(app);

