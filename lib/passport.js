var Passport = require('passport').Passport;
var yaml = require('yaml-js');
var fs = require('fs');
var path = require('path');

exports.strategies = [];

exports.redirectOnSuccess = function redirectOnSuccess(req, res) {
    var redir = '/';
    if (req.session.redirect) {
        redir = req.session.redirect;
        delete req.session.redirect;
    }
    res.redirect(redir);
};

var stratDir = __dirname + '/strategies/';
fs.readdirSync(stratDir).forEach(function (file) {
    if (file.match(/[^\.].*?\.js$/)) {
        var name = file.replace(/\.js$/, '');
        exports.strategies[name] = require(stratDir + file);
        exports.strategies[name].redirectOnSuccess = exports.redirectOnSuccess;
    }
});

function requireIfExists(compound, file) {
    var confFile = path.join(compound.root, 'config', file);
    if (fs.existsSync(confFile)) {
        var conf = require(confFile);
        if (typeof(conf) == "function") {
            return conf(compound);
        } else {
            return conf;
        }
    }
    return null;
}


//  Helper regexp and function for reading apiKey/secret from process.env
var processEnvRegexp = /^process\.env\.(\w+)$/;
var evalProcessEnvIfNeeded = function(value) {
    if(!value) {
        return value;
    }

    var results = value.match(processEnvRegexp);
    if(!results
        || results.length != 2) {
        return value;
    }

    return process.env[results[1]];
}

exports.init = function (compound) {
    var app = compound.app;
    var passport = new Passport;

    (function injectRoutes() {

        var gotRouter, i, l = app.stack.length;
        app.stack.forEach(function (r, i) {
            if (r.handle === app.router) {
                gotRouter = i;
            }
        });
        for (i = l; i > gotRouter; i--) {
            app.stack[i + 1] = app.stack[i - 1];
        }
        if (gotRouter) {
            app.stack[gotRouter] = {route: '', handle: passport.initialize()};
            app.stack[gotRouter + 1] = {route: '', handle: passport.session()};
        } else {
            app.use(passport.initialize());
            app.use(passport.session());
            app.use(app.router);
        }
    })();

    var conf = requireIfExists(compound, 'passport.js') || requireIfExists(compound, 'passport.coffee');
    if (!conf) {
        conf = fs.readFileSync(app.root + '/config/passport.yml', 'utf8').toString();
        conf = yaml.load(conf);
    }
    if (!conf) {
        console.log("WARN: can not find passport configurations skipping passport configuration");
        return;
    }

    if (conf && conf instanceof Array) conf = conf[0];
    conf = conf[app.set('env')];
    Object.keys(exports.strategies).forEach(function (str) {
        if (conf[str]) {
            //  If the apiKey and/or secret are defined as process.env.<environment variable> then evaluate them as such.
            conf[str].apiKey = evalProcessEnvIfNeeded(conf[str].apiKey);
            conf[str].secret = evalProcessEnvIfNeeded(conf[str].secret);
            //  Github strategy uses clientID instead of apiKey so instead of introducing a breaking change
            //  we handle the special case.
            if(conf[str].clientID) {
                conf[str].clientID = evalProcessEnvIfNeeded(conf[str].clientID);
            }

            exports.strategies[str].init(conf, app);
        };
    });

    compound.on('models', function(models) {
        if (models.User) {
            exports.loadUser(models.User);
        }
    });

    compound.on('structure', function(s) {
        //  Use __compoundPassportAuth to avoid polluting controllers namespace.
        s.controllers.__compoundPassportAuth = function CompoundPassportAuthController() {
            this.__missingAction = function (c) {
                c.next();
            };
        };
    });

    //  For auth/* routes that aren't enabled leave the application to handle 404.

    // convert user to userId
    passport.serializeUser(function serializeUser(user, done) {
        done(null, user.id);
    });

    // convert userId to user
    passport.deserializeUser(function deserializeUser(userId, done) {
        exports.User.find(userId, function (err, user) {
            done(err, user);
        });
    });

};

exports.loadUser = function (u) {
    if (!u.findOrCreate) {
        u.findOrCreate = require('./user.js').findOrCreate;
    }
    Object.keys(exports.strategies).forEach(function (str) {
        exports.strategies[str].User = u;
    });
    exports.User = u;
};
