let express = require("express");
let url = require("url");
let bodyParser = require('body-parser');
let randomstring = require("randomstring");
let cons = require('consolidate');
let nosql = require('nosql').load('database.nosql');
let querystring = require('querystring');
let qs = require("qs");
let __ = require('underscore');
__.string = require('underscore.string');
let base64url = require('base64url');
let jose = require('jsrsasign');

let app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
let authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information
let clients = [
	{
		"client_id": "oauth-client-1",
		"client_secret": "oauth-client-secret-1",
		"redirect_uris": ["http://localhost:9000/callback"],
		"scope": "openid profile email phone address"
	}
];

let rsaKey = {
  "alg": "RS256",
  "d": "ZXFizvaQ0RzWRbMExStaS_-yVnjtSQ9YslYQF1kkuIoTwFuiEQ2OywBfuyXhTvVQxIiJqPNnUyZR6kXAhyj__wS_Px1EH8zv7BHVt1N5TjJGlubt1dhAFCZQmgz0D-PfmATdf6KLL4HIijGrE8iYOPYIPF_FL8ddaxx5rsziRRnkRMX_fIHxuSQVCe401hSS3QBZOgwVdWEb1JuODT7KUk7xPpMTw5RYCeUoCYTRQ_KO8_NQMURi3GLvbgQGQgk7fmDcug3MwutmWbpe58GoSCkmExUS0U-KEkHtFiC8L6fN2jXh1whPeRCa9eoIK8nsIY05gnLKxXTn5-aPQzSy6Q",
  "e": "AQAB",
  "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
  "kty": "RSA",
  "kid": "authserver"
};


let protectedResources = [
	{
		"resource_id": "protected-resource-1",
		"resource_secret": "protected-resource-secret-1"
	}
];

let userInfo = {

	"alice": {
		"sub": "9XE3-JI34-00132A",
		"preferred_username": "alice",
		"name": "Alice",
		"email": "alice.wonderland@example.com",
		"email_verified": true
	},
	
	"bob": {
		"sub": "1ZT5-OE63-57383B",
		"preferred_username": "bob",
		"name": "Bob",
		"email": "bob.loblob@example.net",
		"email_verified": false
	},

	"carol": {
		"sub": "F5Q1-L6LGG-959FS",
		"preferred_username": "carol",
		"name": "Carol",
		"email": "carol.lewis@example.net",
		"email_verified": true,
		"username" : "clewis",
		"password" : "user password!"
 	}	
};

let getUser = function(username) {
	return userInfo[username];
};

let codes = {};

let requests = {};

let getClient = function(clientId) {
	return __.find(clients, function(client) { return client.client_id == clientId; });
};

let getProtectedResource = function(resourceId) {
	return __.find(protectedResources, function(resource) { return resource.resource_id == resourceId; });
};

app.get('/', function(req, res) {
	res.render('index', {clients: clients, authServer: authServer});
});

app.get("/authorize", function(req, res){
	
	let client = getClient(req.query.client_id);
	
	if (!client) {
		console.log('Unknown client %s', req.query.client_id);
		res.render('error', {error: 'Unknown client'});
		return;
	} else if (!__.contains(client.redirect_uris, req.query.redirect_uri)) {
		console.log('Mismatched redirect URI, expected %s got %s', client.redirect_uris, req.query.redirect_uri);
		res.render('error', {error: 'Invalid redirect URI'});
		return;
	} else {
		
		let rscope = req.query.scope ? req.query.scope.split(' ') : undefined;
		let cscope = client.scope ? client.scope.split(' ') : undefined;
		if (__.difference(rscope, cscope).length > 0) {
			// client asked for a scope it couldn't have
			let urlParsed = buildUrl(req.query.redirect_uri, {
				error: 'invalid_scope'
			});
			res.redirect(urlParsed);
			return;
		}
		
		let reqid = randomstring.generate(8);
		
		requests[reqid] = req.query;
		
		res.render('approve', {client: client, reqid: reqid, scope: rscope});
		return;
	}

});

app.post('/approve', function(req, res) {

	let reqid = req.body.reqid;
	let query = requests[reqid];
	delete requests[reqid];

	if (!query) {
		// there was no matching saved request, this is an error
		res.render('error', {error: 'No matching authorization request'});
		return;
	}
	
	if (req.body.approve) {
		if (query.response_type == 'code') {
			// user approved access
			let code = randomstring.generate(8);
			
			let user = getUser(req.body.user);

			let scope = getScopesFromForm(req.body);

			let client = getClient(query.client_id);
			let cscope = client.scope ? client.scope.split(' ') : undefined;
			if (__.difference(scope, cscope).length > 0) {
				// client asked for a scope it couldn't have
				let urlParsed = buildUrl(query.redirect_uri, {
					error: 'invalid_scope'
				});
				res.redirect(urlParsed);
				return;
			}

			// save the code and request for later
			codes[code] = { request: query, scope: scope, user: user };
		
			let urlParsed = buildUrl(query.redirect_uri, {
				code: code,
				state: query.state
			});
			res.redirect(urlParsed);
			return;
		} else {
			// we got a response type we don't understand
			let urlParsed = buildUrl(query.redirect_uri, {
				error: 'unsupported_response_type'
			});
			res.redirect(urlParsed);
			return;
		}
	} else {
		// user denied access
		let urlParsed = buildUrl(query.redirect_uri, {
			error: 'access_denied'
		});
		res.redirect(urlParsed);
		return;
	}
	
});

app.post("/token", function(req, res){
	
	let auth = req.headers['authorization'];
	if (auth) {
		// check the auth header
		let clientCredentials = decodeClientCredentials(auth);
		let clientId = clientCredentials.id;
		let clientSecret = clientCredentials.secret;
	}
	
	// otherwise, check the post body
	if (req.body.client_id) {
		if (clientId) {
			// if we've already seen the client's credentials in the authorization header, this is an error
			console.log('Client attempted to authenticate with multiple methods');
			res.status(401).json({error: 'invalid_client'});
			return;
		}
		
		let clientId = req.body.client_id;
		let clientSecret = req.body.client_secret;
	}
	
	let client = getClient(clientId);
	if (!client) {
		console.log('Unknown client %s', clientId);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	if (client.client_secret != clientSecret) {
		console.log('Mismatched client secret, expected %s got %s', client.client_secret, clientSecret);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	if (req.body.grant_type == 'authorization_code') {
		
		let code = codes[req.body.code];
		
		if (code) {
			delete codes[req.body.code]; // burn our code, it's been used
			if (code.request.client_id == clientId) {

				let header = { 'typ': 'JWT', 'alg': rsaKey.alg, 'kid': rsaKey.kid};

				/*
				let payload = {
					iss: 'http://localhost:9001/',
					sub: code.user ? code.user.sub : null,
					aud: 'http://localhost:9002/',
					iat: Math.floor(Date.now() / 1000),
					exp: Math.floor(Date.now() / 1000) + (5 * 60),
					jti: randomstring.generate(8)
				};

				console.log(payload);

				let stringHeader = JSON.stringify(header);
				let stringPayload = JSON.stringify(payload);
				//let encodedHeader = base64url.encode(JSON.stringify(header));
				//let encodedPayload = base64url.encode(JSON.stringify(payload));

				//let access_token = encodedHeader + '.' + encodedPayload + '.';
				//let access_token = jose.jws.JWS.sign('HS256', stringHeader, stringPayload, Buffer.from(sharedTokenSecret).toString('hex'));

				let privateKey = jose.KEYUTIL.getKey(rsaKey);
				let access_token = jose.jws.JWS.sign(rsaKey.alg, stringHeader, stringPayload, privateKey);
				*/
				
				let access_token = randomstring.generate();
				nosql.insert({ access_token: access_token, client_id: clientId, scope: code.scope, user: code.user });

				console.log('Issuing access token %s', access_token);
				console.log('with scope %s', code.scope);

				let cscope = null;
				if (code.scope) {
					cscope = code.scope.join(' ');
				}

				let token_response = { access_token: access_token, token_type: 'Bearer',  scope: cscope };

				if (__.contains(code.scope, 'openid')) {
					let ipayload = {
						iss: 'http://localhost:9001/',
						sub: code.user.sub,
						aud: client.client_id,
						iat: Math.floor(Date.now() / 1000),
						exp: Math.floor(Date.now() / 1000) + (5 * 60)	
					};
					if (code.request.nonce) {
						ipayload.nonce = code.request.nonce;
					}

					let istringHeader = JSON.stringify(header);
					let istringPayload = JSON.stringify(ipayload);
					let privateKey = jose.KEYUTIL.getKey(rsaKey);
					let id_token = jose.jws.JWS.sign(rsaKey.alg, istringHeader, istringPayload, privateKey);

					console.log('Issuing ID token %s', id_token);

					token_response.id_token = id_token;

				}

				res.status(200).json(token_response);
				console.log('Issued tokens for code %s', req.body.code);
				
				return;
			} else {
				console.log('Client mismatch, expected %s got %s', code.request.client_id, clientId);
				res.status(400).json({error: 'invalid_grant'});
				return;
			}
		} else {
			console.log('Unknown code, %s', req.body.code);
			res.status(400).json({error: 'invalid_grant'});
			return;
		}
	} else {
		console.log('Unknown grant type %s', req.body.grant_type);
		res.status(400).json({error: 'unsupported_grant_type'});
	}
});



let buildUrl = function(base, options, hash) {
	let newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function(value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}
	
	return url.format(newUrl);
};

let getScopesFromForm = function(body) {
	return __.filter(__.keys(body), function(s) { return __.string.startsWith(s, 'scope_'); })
				.map(function(s) { return s.slice('scope_'.length); });
};

let decodeClientCredentials = function(auth) {
	let clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
	let clientId = querystring.unescape(clientCredentials[0]);
	let clientSecret = querystring.unescape(clientCredentials[1]);	
	return { id: clientId, secret: clientSecret };
};

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

let server = app.listen(9001, 'localhost', function () {
  let host = server.address().address;
  let port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
 


