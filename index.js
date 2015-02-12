var util = require('util'),
    request = require('request'),
    OAuth2Strategy = require('passport-oauth').OAuth2Strategy,
    InternalOAuthError = require('passport-oauth').InternalOAuthError;

function Strategy(options, verify) {
    options = options || {};
    options.authorizationURL = options.authorizationURL || '';
    options.tokenURL = options.tokenURL || '';
    options.scopeSeparator = options.scopeSeparator || ',';
    options.customHeaders = options.customHeaders || {};

    if (!options.customHeaders['User-Agent']) {
        options.customHeaders['User-Agent'] = options.userAgent || 'passport-oneuser';
    }

    OAuth2Strategy.call(this, options, verify);
    this.name = 'oneuser';
    this._userProfileURL = options.userProfileURL || '';
    this._oauth2.useAuthorizationHeaderforGET(true);
}

util.inherits(Strategy, OAuth2Strategy);

Strategy.prototype.userProfile = function(accessToken, done) {
    this._oauth2.get(this._userProfileURL, accessToken, function (err, body, res) {

        var json;

        if (err) {
            return done(new InternalOAuthError('Failed to fetch user profile', err));
        }

        try {
            json = JSON.parse(body);
        } catch (ex) {
            return done(new Error('Failed to parse user profile'));
        }

        var profile = parse(json);

        profile.provider  = 'oneuser';
        profile._raw = body;
        profile._json = json;

        done(null, profile);
    });
};

function parse(json){
    if ('string' == typeof json) {
        json = JSON.parse(json);
    }
    var profile = {};
    profile.id = json._id;
    // profile.displayName = json.name;
    profile.username = json.username;
    // profile.profileUrl = json.html_url;
    if (json.email) {
        profile.emails = [{ value: json.email }];
    }

    return profile;
}


exports.Strategy = Strategy;
exports.auth = function(url){
    return function(req, res, next) {
        var token;
        if(req.query['access_token']) {
            token = req.query['access_token'];
        } else if((req.headers['authorization'] || '').indexOf('Bearer ') == 0) {
            token = req.headers['authorization'].replace('Bearer', '').trim();
        } else {
            return res.status(401).end();
        }
        request.post(url, {auth: {bearer: token}}, function(err, response, body){
            if(!err && response.statusCode === 200){
                req.user = JSON.parse(body);
                req.token = token;
                next();
            }else{
                return res.status(401).end();
            }
        });
    }
};