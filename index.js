const passport = require("passport-strategy");
const {xpath, SignedXml} = require("xml-crypto");
const xmlbuilder = require("xmlbuilder");
const xml2js = require('xml2js');
const xmldom = require('xmldom');
const crypto = require("crypto");
const zlib = require("zlib");
const url = require("url");
const querystring = require("querystring");
const inMemoryCacheProvider = require('./inmemory-cache-provider.js');
const fileCacheProvider = require('./file-cache-provider.js');

class SpidStrategy extends passport.Strategy {

  constructor(options, verify) {

    super();

    if (typeof options === "function") {
      verify = options;
      options = {};
    }

    if (!verify) {
      throw new Error("SAML authentication strategy requires a verify function");
    }

    this.name = "spid";

    passport.Strategy.call(this);

    this.spidOptions = options;
    this._verify = verify;
    this._passReqToCallback = !!options.passReqToCallback;
    this._authnRequestBinding = options.authnRequestBinding || "HTTP-Redirect";
    this._acceptedClockSkewMs = options.acceptedClockSkewMs || 60 * 10000;
    this.cacheProvider = options.cacheProvider === 'FILE' ? new fileCacheProvider() : new inMemoryCacheProvider();

  }

  // Generate service provider metadata
  generateServiceProviderMetadata = function (decryptionCert) {

    const self = this;

    const spidOptions = this.spidOptions.sp;

    const ID = spidOptions.issuer.replace(/\W/g, "_");

    const metadata = {
      "md:EntityDescriptor": {
        "@xmlns:md": "urn:oasis:names:tc:SAML:2.0:metadata",
        "@xmlns:ds": "http://www.w3.org/2000/09/xmldsig#",
        "@xmlns:spid": "https://spid.gov.it/saml-extensions",
        "@xmlns:fpa": "https://spid.gov.it/invoicing-extensions",
        "@entityID": spidOptions.issuer,
        "@ID": ID,
        "md:SPSSODescriptor": {
          "@protocolSupportEnumeration": "urn:oasis:names:tc:SAML:2.0:protocol",
          "@AuthnRequestsSigned": true,
          "@WantAssertionsSigned": true,
        }
      }
    };

    if (spidOptions.decryptionPvk) {

      if (!decryptionCert) {
        throw new Error(
          "Missing decryptionCert while generating metadata for decrypting service provider"
        );
      }

      decryptionCert = decryptionCert.replace(/-+BEGIN CERTIFICATE-+\r?\n?/, "");
      decryptionCert = decryptionCert.replace(/-+END CERTIFICATE-+\r?\n?/, "");
      decryptionCert = decryptionCert.replace(/-+BEGIN CERTIFICATE REQUEST-+\r?\n?/, "");
      decryptionCert = decryptionCert.replace(/-+END CERTIFICATE REQUEST-+\r?\n?/, "");
      decryptionCert = decryptionCert.replace(/\r\n/g, "\n");

      metadata["md:EntityDescriptor"]["md:SPSSODescriptor"]["md:KeyDescriptor"] = [
        {
          "@use": "signing",
          "ds:KeyInfo": {
            "@xmlns:ds": "http://www.w3.org/2000/09/xmldsig#",
            "ds:X509Data": {
              "ds:X509Certificate": {
                "#text": decryptionCert
              }
            }
          }

        },
        {
          "@use": "encryption",
          "ds:KeyInfo": {
            "@xmlns:ds": "http://www.w3.org/2000/09/xmldsig#",
            "ds:X509Data": {
              "ds:X509Certificate": {
                "#text": decryptionCert
              }
            }
          }

        }
      ];

    }

    if (spidOptions.logoutCallbackUrl) {
      metadata["md:EntityDescriptor"]["md:SPSSODescriptor"]["md:SingleLogoutService"] = {
        "@Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        "@Location": spidOptions.logoutCallbackUrl
      };
    }

    metadata["md:EntityDescriptor"]["md:SPSSODescriptor"]["md:NameIDFormat"] = {
      "#text": spidOptions.identifierFormat
    }

    metadata["md:EntityDescriptor"]["md:SPSSODescriptor"]["md:AssertionConsumerService"] = {
      "@Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
      "@Location": self.getCallbackUrl(),
      "@index": spidOptions.attributeConsumingServiceIndex,
      "@isDefault": "true",
    };

    if (spidOptions.attributes) {

      metadata["md:EntityDescriptor"]["md:SPSSODescriptor"]["md:AttributeConsumingService"] = {
        "@index": spidOptions.attributeConsumingServiceIndex,
        "md:ServiceName": {
          "@xml:lang": "it",
          "#text": spidOptions.attributes.name
        },
        "md:ServiceDescription": {
          "@xml:lang": "it",
          "#text": spidOptions.attributes.description
        },
        "md:RequestedAttribute": spidOptions.attributes.attributes.map(item => {
          return {
            "@Name": item,
            "@NameFormat":
              "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
          };
        })
      };
    }

    if (!spidOptions.organization) {
      throw new Error("Missing organization data");
    }

    metadata["md:EntityDescriptor"]["md:Organization"] = {
      "md:OrganizationName": {
        "@xml:lang": "it",
        "#text": spidOptions.organization.name
      },
      "md:OrganizationDisplayName": {
        "@xml:lang": "it",
        "#text": spidOptions.organization.displayName
      },
      "md:OrganizationURL": {
        "@xml:lang": "it",
        "#text": spidOptions.organization.URL
      }
    };

    if (!spidOptions.organization.contact.technical) {
      throw new Error("Missing organization technical contact");
    }
    if (!spidOptions.organization.contact.billing) {
      throw new Error("Missing organization billing contact");
    }

    metadata["md:EntityDescriptor"]["md:ContactPerson"] = [

      // Technical contact details
      {
        "@contactType": "other",
        "md:Extensions": {
          "spid:VATNumber": {
            "@xmlns:spid": "https://spid.gov.it/saml-extensions",
            "#text": spidOptions.organization.contact.technical.vatNumber
          },
          "spid:Private": {
            "@xmlns:spid": "https://spid.gov.it/saml-extensions"
          }
        },
        "md:Company": {
          "#text": spidOptions.organization.contact.technical.company
        },
        "md:EmailAddress": {
          "#text": spidOptions.organization.contact.technical.emailAddress
        },
        "md:TelephoneNumber": {
          "#text": spidOptions.organization.contact.technical.telephoneNumber
        }
      },

      // Billing contact details
      {
        "@contactType": "billing",
        "md:Extensions": {
          "fpa:CessionarioCommittente": {
            "@xmlns:fpa": "https://spid.gov.it/invoicing-extensions",
            "fpa:DatiAnagrafici": {
              "fpa:IdFiscaleIVA": {
                "fpa:IdPaese": {
                  "#text": spidOptions.organization.contact.billing.country
                },
                "fpa:IdCodice": spidOptions.organization.contact.billing.vatNumber
              },
              "fpa:Anagrafica": {
                "fpa:Denominazione": {
                  "#text": spidOptions.organization.contact.billing.company
                }
              },
            },
            "fpa:Sede": {
              "fpa:Indirizzo": {
                "#text": spidOptions.organization.contact.billing.street
              },
              "fpa:NumeroCivico": {
                "#text": spidOptions.organization.contact.billing.streetNumber
              },
              "fpa:CAP": {
                "#text": spidOptions.organization.contact.billing.postalCode
              },
              "fpa:Comune": {
                "#text": spidOptions.organization.contact.billing.city
              },
              "fpa:Provincia": {
                "#text": spidOptions.organization.contact.billing.province
              },
              "fpa:Nazione": {
                "#text": spidOptions.organization.contact.billing.country
              }
            }
          }
        },
        "md:Company": {
          "#text": spidOptions.organization.contact.billing.company
        },
        "md:EmailAddress": {
          "#text": spidOptions.organization.contact.billing.emailAddress
        },
        "md:TelephoneNumber": {
          "#text": spidOptions.organization.contact.billing.telephoneNumber
        }

      }

    ];

    // generate XML data
    const xml = xmlbuilder.create(metadata).end({
      pretty: true,
      indent: "  ",
      newline: "\n"
    });

    function MyKeyInfo(file) {
      this.file = file;

      this.getKeyInfo = function (key, prefix) {

        prefix = prefix || ''
        prefix = prefix ? prefix + ':' : prefix
        return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" +
          decryptionCert +
          "</" + prefix + "X509Certificate></" + prefix + "X509Data>"

      };

      this.getKey = function (keyInfo) {
        return this.file;
      };
    }

    const sign = new SignedXml();
    sign.signingKey = spidOptions.privateCert;
    sign.keyInfoProvider = new MyKeyInfo(decryptionCert);
    sign.addReference(
      "//*[local-name(.)='EntityDescriptor']",
      [
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        "http://www.w3.org/2001/10/xml-exc-c14n#"
      ],
      "http://www.w3.org/2001/04/xmlenc#sha256"
    );
    sign.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    sign.computeSignature(xml, {
      prefix: 'ds',
      location: {
        'reference': "//*[local-name(.)='EntityDescriptor']",
        'action': 'prepend'
      }
    });

    return sign.getSignedXml();

  };

  // Generate unique id for the request
  generateUniqueID = function () {
    return crypto.randomBytes(10).toString('hex');
  };

  // Generate request time
  generateInstant = function () {
    return new Date().toISOString();
  };

  // Get additional params including RelayState
  getAdditionalParams = function (req, operation) {
    const self = this;
    const additionalParams = {};

    const RelayState = req.query && req.query.RelayState || req.body && req.body.RelayState;
    if (RelayState) {
      additionalParams.RelayState = RelayState;
    }

    const optionsAdditionalParams = self.spidOptions.additionalParams || {};
    Object.keys(optionsAdditionalParams).forEach(function (k) {
      additionalParams[k] = optionsAdditionalParams[k];
    });


    let optionsAdditionalParamsForThisOperation = {};
    if (operation === "authorize") {
      optionsAdditionalParamsForThisOperation = self.spidOptions.additionalAuthorizeParams || {};
    }
    if (operation === "logout") {
      optionsAdditionalParamsForThisOperation = self.spidOptions.additionalLogoutParams || {};
    }

    Object.keys(optionsAdditionalParamsForThisOperation).forEach(function (k) {
      additionalParams[k] = optionsAdditionalParamsForThisOperation[k];
    });

    return additionalParams;
  };

  // Get Callback url
  getCallbackUrl = function (req) {
    return this.spidOptions.sp.callbackUrl;
  };

  // Sign request
  signRequest = function (samlMessage) {

    const self = this;
    const spidOptions = self.spidOptions.sp;
    const samlMessageToSign = {};
    const signer = crypto.createSign('RSA-SHA256');

    samlMessage.SigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

    if (samlMessage.SAMLRequest) {
      samlMessageToSign.SAMLRequest = samlMessage.SAMLRequest;
    }
    if (samlMessage.SAMLResponse) {
      samlMessageToSign.SAMLResponse = samlMessage.SAMLResponse;
    }
    if (samlMessage.RelayState) {
      samlMessageToSign.RelayState = samlMessage.RelayState;
    }

    samlMessageToSign.SigAlg = samlMessage.SigAlg;
    signer.update(querystring.stringify(samlMessageToSign));
    samlMessage.Signature = signer.sign(spidOptions.privateCert, 'base64');
  };

  // Generate Request Url
  requestToUrl = function (request, response, operation, additionalParameters, callback) {

    const self = this;

    const spidOptions = self.spidOptions.sp;

    zlib.deflateRaw(request || response, (err, buffer) => {

      if (err) {
        return callback(err);
      }

      const base64 = buffer.toString('base64');

      if (operation !== 'authorize' && operation !== 'logout') {
        return callback(new Error("Unknown operation: " + operation));
      }

      const target = url.parse(
        operation === 'logout' ? spidOptions.logoutUrl : spidOptions.entryPoint,
        true
      );

      const samlMessage = request ? {SAMLRequest: base64} : {SAMLResponse: base64};

      Object.keys(additionalParameters).forEach(function (k) {
        samlMessage[k] = additionalParameters[k];
      });

      if (spidOptions.privateCert) {
        try {
          // sets .SigAlg and .Signature
          self.signRequest(samlMessage);
        } catch (ex) {
          return callback(ex);
        }
      }
      Object.keys(samlMessage).forEach(function (k) {
        target.query[k] = samlMessage[k];
      });

      // Delete 'search' to for pulling query string from 'query'
      // https://nodejs.org/api/url.html#url_url_format_urlobj
      delete target.search;

      callback(null, url.format(target));

    });
  };


  // Authenticate user
  authenticate = function (req, options) {
    const self = this;

    self.requestID = options.requestID || "_" + self.generateUniqueID();

    const spidOptions = this.spidOptions.sp;
    const entityID = req.query.entityID || options.entityID;

    // console.log('SPID: authenticate options: ' + JSON.stringify(options));
    // console.log('SPID: authenticate spidOptions: ' + JSON.stringify(this.spidOptions.sp));
    // console.log('SPID: authenticate req.query: ' + JSON.stringify(req.query));
    // console.log('SPID: authenticate entityID: ' + entityID);

    if (entityID !== undefined) {

      const idp = this.spidOptions.idp[entityID];

      if (!this.spidOptions.idp[entityID]) {
        throw Error('Invalid entityId provided: ' + entityID);
      }

      if (!spidOptions.logoutCallbackUrl) {
        throw Error('logoutCallbackUrl must be provided');
      }

      if (!spidOptions.callbackUrl) {
        throw Error('callbackUrl must be provided');
      }

      spidOptions.entryPoint = idp.entryPoint;
      spidOptions.logoutUrl = idp.logoutUrl;
      spidOptions.cert = idp.cert;

    } else {
      // Do a check against all IDP certs if we don't have an entityID
      const idps = this.spidOptions.idp;
      spidOptions.cert = Object.keys(idps).map(k => idps[k].cert);
    }

    options.samlFallback = options.samlFallback || "login-request";

    const authnRequestBinding = options.authnRequestBinding || self._authnRequestBinding;


    function validateCallback(err, profile, loggedOut) {
      if (err) {
        return self.error(err);
      }

      if (loggedOut) {
        req.logout();
        if (profile) {
          req.samlLogoutRequest = profile;
          return self.getLogoutResponseUrl(req, redirectIfSuccess);
        }
        return self.pass();
      }

      const verified = function (err, user, info) {
        if (err) {
          return self.error(err);
        }

        if (!user) {
          return self.fail(info);
        }

        self.success(user, info);
      };

      if (self._passReqToCallback) {
        self._verify(req, profile, verified);
      } else {
        self._verify(profile, verified);
      }
    }

    function redirectIfSuccess(err, url) {

      //console.log("SPID: redirectIfSuccess: " + err);
      //console.log("SPID: redirectIfSuccess: " + url);

      if (err) {
        self.error(err);
      } else {
        self.redirect(url);
      }
    }

    function getUrlIfSuccess(err, url) {

      // console.log("SPID: getUrlIfSuccess: " + err);
      // console.log("SPID: getUrlIfSuccess: " + url);

      if (err) {
        self.error(err);
      } else {
        self.success(null, {
          requestID: self.requestID,
          url: url
        });
      }
    }

    if (req.body && req.body.SAMLResponse) {
      self.validatePostResponse(req.body, validateCallback);
    } else if (req.body && req.body.SAMLRequest) {
      self.validatePostRequest(req.body, validateCallback);
    } else {

      //console.log("SPID: requestHandler");

      const requestHandler = {
        "login-request": function () {

          //console.log("SPID: login-request - authnRequestBinding:" + authnRequestBinding);

          if (authnRequestBinding === "HTTP-URL") {

            // Get Idp Authorize Url to handle externally
            self.getAuthorizeUrl(req, getUrlIfSuccess);

          } else {

            //console.log("SPID: _authnRequestBinding:HTTP-Redirect");

            // Defaults to HTTP-Redirect
            self.getAuthorizeUrl(req, redirectIfSuccess);

          }
        }.bind(self),
        "logout-request": function () {

          console.log("SPID: logout-request");

          self.getLogoutUrl(req, redirectIfSuccess);

        }.bind(self)
      }[options.samlFallback];

      if (typeof requestHandler !== "function") {

        console.log("SPID: requestHandler:FAIL");

        return self.fail();
      }

      requestHandler();
    }
  };

  // Get Authorize url from Identity Provider
  getAuthorizeUrl = function (req, callback) {
    const self = this;

    self.generateAuthorizeRequest(req, function (err, request) {
      if (err) {
        return callback(err);
      }

      const operation = 'authorize';

      self.requestToUrl(request, null, operation, self.getAdditionalParams(req, operation), callback);
    });
  };

  // Generate authorize request
  generateAuthorizeRequest = function (req, callback) {

    const self = this;
    const spidOptions = self.spidOptions.sp;
    const instant = self.generateInstant();

    self.cacheProvider.save(self.requestID, instant);

    const request = {
      'samlp:AuthnRequest': {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '@ID': self.requestID,
        '@Version': '2.0',
        '@IssueInstant': instant,
        '@Destination': spidOptions.entryPoint,
        '@AssertionConsumerServiceURL': self.getCallbackUrl(),
        '@ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        '@AttributeConsumingServiceIndex': spidOptions.attributeConsumingServiceIndex,
        'saml:Issuer': {
          '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
          '@NameQualifier': spidOptions.issuer,
          '@Format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
          '#text': spidOptions.issuer
        },
        'samlp:NameIDPolicy': {
          '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
          '@Format': spidOptions.identifierFormat,
        },
        'samlp:RequestedAuthnContext': {
          '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
          '@Comparison': 'exact',
          'saml:AuthnContextClassRef': {
            '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
            '#text': spidOptions.authnContext
          }
        }
      }
    };

    // console.log('🟣🟣🟣 SAML:request 🟣🟣🟣');
    // console.log(request);

    callback(null, xmlbuilder.create(request).end());

  };


  // Logout
  logout = function (req, callback) {
    const spidOptions = this.spidOptions.sp;

    const entityID = req.query.entityID;
    if (entityID !== undefined) {
      const idp = this.spidOptions.idp[entityID];
      spidOptions.entryPoint = idp.entryPoint;
      spidOptions.logoutUrl = idp.logoutUrl;
      spidOptions.cert = idp.cert;
    }

    self.getLogoutUrl(req, callback);
  };

  // Get Logout url
  getLogoutUrl = function (req, callback) {
    const self = this;
    const request = self.generateLogoutRequest(req);
    const operation = 'logout';
    self.requestToUrl(request, null, operation, self.getAdditionalParams(req, operation), callback);
  };

  // Generate logout request
  generateLogoutRequest = function (req) {
    const self = this;
    const id = "_" + self.generateUniqueID();
    const instant = self.generateInstant();
    const spidOptions = self.spidOptions.sp;

    const request = {
      'samlp:LogoutRequest': {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '@ID': id,
        '@Version': '2.0',
        '@IssueInstant': instant,
        '@Destination': spidOptions.logoutUrl,
        'saml:Issuer': {
          '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
          '#text': spidOptions.issuer
        },
        'saml:NameID': {
          '@Format': req.user.nameIDFormat,
          '#text': req.user.nameID
        }
      }
    };

    if (typeof (req.user.nameQualifier) !== 'undefined') {
      request['samlp:LogoutRequest']['saml:NameID']['@NameQualifier'] = req.user.nameQualifier;
    }

    if (typeof (req.user.spNameQualifier) !== 'undefined') {
      request['samlp:LogoutRequest']['saml:NameID']['@SPNameQualifier'] = req.user.spNameQualifier;
    }

    if (req.user.sessionIndex) {
      request['samlp:LogoutRequest']['saml2p:SessionIndex'] = {
        '@xmlns:saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '#text': req.user.sessionIndex
      };
    }

    return xmlbuilder.create(request).end();
  };

  // Generate logout response
  generateLogoutResponse = function (req, logoutRequest) {
    const self = this;
    const id = "_" + self.generateUniqueID();
    const instant = self.generateInstant();
    const spidOptions = self.spidOptions.sp;

    const request = {
      'samlp:LogoutResponse': {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '@ID': id,
        '@Version': '2.0',
        '@IssueInstant': instant,
        '@Destination': spidOptions.logoutUrl,
        '@InResponseTo': logoutRequest.ID,
        'saml:Issuer': {
          '#text': spidOptions.issuer
        },
        'samlp:Status': {
          'samlp:StatusCode': {
            '@Value': 'urn:oasis:names:tc:SAML:2.0:status:Success'
          }
        }
      }
    };

    return xmlbuilder.create(request).end();
  };

  // Get Logout response url
  getLogoutResponseUrl = function (req, callback) {
    const self = this;
    const response = self.generateLogoutResponse(req, req.samlLogoutRequest);
    const operation = 'logout';
    self.requestToUrl(null, response, operation, self.getAdditionalParams(req, operation), callback);
  };


  // Get certs use to check validation
  certsToCheck = function () {

    const self = this;
    const spidOptions = self.spidOptions.sp;

    if (!spidOptions.cert) {
      return false;
    }

    const certs = spidOptions.cert;

    return (!Array.isArray(certs)) ? [certs] : certs;

  };

  // Validate timestamp
  checkTimestampsValidityError = function (nowMs, notBefore, notOnOrAfter) {
    const self = this;

    if (self._acceptedClockSkewMs === -1)
      return null;

    if (notBefore) {
      const notBeforeMs = Date.parse(notBefore);
      if (nowMs + self._acceptedClockSkewMs < notBeforeMs) {
        return new SpidError(666, 'Assertion not yet valid');
      }
    }

    if (notOnOrAfter) {
      const notOnOrAfterMs = Date.parse(notOnOrAfter);
      if (nowMs - self._acceptedClockSkewMs >= notOnOrAfterMs) {
        return new SpidError(666, 'Issue Instant expired', null);
      }
    }

    return null;
  };


  /***
   * Check if date is valid iso format with or without milliseconds
   *
   * @param str
   * @returns {boolean}
   */
  isValidDate = function (str) {

    return /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z/.test(str) ||
      /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/.test(str);

  }

  /**
   * Check if date is on or after target date
   *
   * @param target timestamp or iso-string
   * @param onOrAfter timestamp or iso-string
   * @returns {boolean}
   */
  checkIsOnOrAfter = function (target, onOrAfter) {
    const self = this;

    const targetMs = Number.isInteger(target) ? target : Date.parse(target);

    if (onOrAfter) {
      const onOrAfterMs = Date.parse(onOrAfter);
      if (onOrAfterMs > targetMs + self._acceptedClockSkewMs) {
        return true;
      }
    }
    return false;
  }


  /**
   * Check if date is before target date
   *
   * @param target timestamp or iso-string
   * @param before timestamp or iso-string
   * @returns {boolean}
   */
  checkIsBefore = function (target, before) {
    const self = this;

    const targetMs = Number.isInteger(target) ? target : Date.parse(target);

    if (before) {
      const beforeMs = Date.parse(before);
      if (beforeMs <= targetMs - self._acceptedClockSkewMs) {
        return true;
      }
    }

    return false;

  };

  // Extract cert and convert it to pem string
  certToPEM = function (cert) {

    cert = cert[0].match(/.{1,64}/g).join('\n');

    if (cert.indexOf('-BEGIN CERTIFICATE-') === -1)
      cert = "-----BEGIN CERTIFICATE-----\n" + cert;
    if (cert.indexOf('-END CERTIFICATE-') === -1)
      cert = cert + "\n-----END CERTIFICATE-----\n";

    return cert;
  };

  // Checks if signature is signed with a given cert.
  validateSignatureForCert = function (signature, cert, fullXml, currentNode) {
    const self = this;
    const sig = new SignedXml();
    sig.keyInfoProvider = {
      getKeyInfo: function (key) {
        return "<X509Data></X509Data>";
      },
      getKey: function (keyInfo) {
        return self.certToPEM(cert);
      }
    };
    sig.loadSignature(signature);
    // We expect each signature to contain exactly one reference to the top level of the xml we
    // are validating, so if we see anything else, reject.
    if (sig.references.length !== 1) {
      return false;
    }

    const refUri = sig.references[0].uri;
    const refId = (refUri[0] === '#') ? refUri.substring(1) : refUri;
    // If we can't find the reference at the top level, reject
    if (currentNode.getAttribute('ID') !== refId) {
      return false;
    }

    // If we find any extra referenced nodes, reject. (xml-crypto can only verifies one digest)
    const totalReferencedNodes = xpath(currentNode.ownerDocument, "//*[@ID='" + refId + "']");
    if (totalReferencedNodes.length > 1) {
      return false;
    }

    return sig.checkSignature(fullXml);

  };

  // Validate Signature
  validateSignature = function (fullXml, currentNode, certs) {
    const self = this;

    const xpathSigQuery = "./*[local-name(.)='Signature' and " +
      "namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";

    const signatures = xpath(currentNode, xpathSigQuery);

    // This function is expecting to validate exactly one signature, so if we find more or fewer than that, reject.
    if (signatures.length !== 1) {
      return false;
    }

    const signature = signatures[0];

    return certs.some((certToCheck) => {
      return self.validateSignatureForCert(signature, certToCheck, fullXml, currentNode);
    });

  };

  // Process Post request after validation
  processValidlySignedPostRequest = function (self, doc, callback) {

    const request = doc.LogoutRequest;

    if (request) {
      const profile = {};
      if (request.$.ID) {
        profile.ID = request.$.ID;
      } else {
        return callback(new Error('Missing SAML LogoutRequest ID'));
      }
      const issuer = request.Issuer;
      if (issuer) {
        profile.issuer = issuer[0];
      } else {
        return callback(new Error('Missing SAML issuer'));
      }

      const nameID = request.NameID;
      if (nameID) {
        profile.nameID = (nameID[0]._ || nameID[0]).trim();

        if (nameID[0].$ && nameID[0].$.Format) {
          profile.nameIDFormat = nameID[0].$.Format;
        }
      } else {
        return callback(new Error('Missing SAML NameID'));
      }
      const sessionIndex = request.SessionIndex;
      if (sessionIndex) {
        profile.sessionIndex = sessionIndex[0];
      }

      callback(null, profile, true);
    } else {
      return callback(new Error('Unknown SAML request message'));
    }
  }

  // Process Assertion after validation
  processAssertion = function (xml, inResponseTo, callback) {

    const self = this;
    const profile = {};

    const parser = new xml2js.Parser({
      explicitRoot: true,
      tagNameProcessors: [xml2js.processors.stripPrefix],
    });

    parser.parseString(xml, function (err, res) {

      const assertion = res.Assertion;

      // extract assertion info
      profile.issuer = assertion.Issuer[0]._;
      profile.issuerFormat = assertion.Issuer[0].$.Format;
      profile.sessionIndex = assertion.AuthnStatement[0].$.SessionIndex;
      profile.nameID = assertion.Subject[0].NameID[0]._.trim();
      profile.nameIDFormat = assertion.Subject[0].NameID[0].$.Format;
      profile.inResponseTo = assertion.Subject[0].SubjectConfirmation[0].SubjectConfirmationData[0].$.InResponseTo;

      // extract valid attributes
      const attributes = [].concat.apply([], assertion.AttributeStatement.filter(function (attr) {
        return Array.isArray(attr.Attribute);
      }).map(function (attr) {
        return attr.Attribute;
      }));

      const attrValueMapper = function (value) {
        return typeof value === 'string' ? value : value._;
      };

      attributes.forEach(function (attribute) {
        // if attributes has no AttributeValue child, continue
        if (!attribute.hasOwnProperty('AttributeValue')) {
          return;
        }
        const value = attribute.AttributeValue;
        if (value.length === 1) {
          profile[attribute.$.Name] = attrValueMapper(value[0]);
        } else {
          profile[attribute.$.Name] = value.map(attrValueMapper);
        }
      });


      profile.getAssertionXml = (xml) => {
        return xml;
      };

      callback(null, profile, false);

    });

  };


  // Validate Post Request
  validatePostRequest = function (container, callback) {
    const self = this;
    const xml = Buffer.from(container.SAMLRequest, 'base64').toString('utf8');
    const dom = new xmldom.DOMParser().parseFromString(xml, 'application/xml');

    const parser = new xml2js.Parser({
      explicitRoot: true,
      tagNameProcessors: [xml2js.processors.stripPrefix]
    });

    parser.parseString(xml, function (err, doc) {
      if (err) {
        return callback(err);
      }

      const certs = self.certsToCheck();

      // Check if this document has a valid top-level signature
      if (certs && !self.validateSignature(xml, dom.documentElement, certs)) {
        return callback(new Error('Invalid signature'));
      }

      self.processValidlySignedPostRequest(self, doc, callback);

    });
  };

  // Validate Post Response
  validatePostResponse = function (container, callback) {

    const self = this;
    const spidOptions = self.spidOptions.sp;
    const nowMs = new Date().getTime();

    if (!container.SAMLResponse) {
      return self.error(new SpidError(-1, 'No response from server'));
    }

    const xml = Buffer.from(container.SAMLResponse, 'base64').toString('utf8');

    const doc = new xmldom.DOMParser().parseFromString(xml, 'application/xml');

    if (!doc.hasOwnProperty('documentElement')) {
      return self.error(new SpidError(0, 'Response is not valid base64-encoded XML'));
    }

    const responseNode = xpath(doc, "/*[local-name()='Response']")[0];

    if (!responseNode) {
      return self.error(new SpidError(0, 'Response is not valid'));
    }


    // Validate inResponseTo

    const inResponseToNode = xpath(responseNode, "@InResponseTo");

    if (!inResponseToNode.length) {
      return self.error(new SpidError(17, 'Missing inResponseTo'));
    }

    if (!inResponseToNode[0].nodeValue.length) {
      return self.error(new SpidError(16, 'Empty inResponseTo'));
    }

    const inResponseTo = inResponseToNode[0].nodeValue;

    // console.log(self.cacheProvider.debug());

    if (!self.cacheProvider.get(inResponseTo)) {
      return self.error(new SpidError(18, 'Invalid inResponseTo', inResponseTo));
    }


    // Validate ResponseID

    const responseIdAttr = xpath(responseNode, "@ID");

    if (!responseIdAttr.length) {
      return self.error(new SpidError(9, 'Missing response ID', inResponseTo));
    }

    if (!responseIdAttr[0].nodeValue.length) {
      return self.error(new SpidError(8, 'Empty response ID', inResponseTo));
    }


    // Validate Version

    const versionAttr = xpath(responseNode, "@Version");

    if (!versionAttr.length || versionAttr[0].nodeValue !== '2.0') {
      return self.error(new SpidError(10, 'Wrong version', inResponseTo));
    }


    // Validate IssueInstant

    const issueInstantAttr = xpath(responseNode, "@IssueInstant");

    if (!issueInstantAttr.length) {
      return self.error(new SpidError(12, 'Missing issueInstant', inResponseTo));
    }

    const issueInstant = issueInstantAttr[0].nodeValue;

    if (!issueInstant.length) {
      return self.error(new SpidError(11, 'Empty issueInstant', inResponseTo));
    }

    if (!self.isValidDate(issueInstant)) {
      return self.error(new SpidError(13, 'Invalid issueInstant format', inResponseTo));
    }

    if (self.checkIsBefore(nowMs, issueInstant)) {
      return self.error(new SpidError(14, 'IssueInstant is before request', inResponseTo));
    }

    if (self.checkIsOnOrAfter(nowMs, issueInstant)) {
      return self.error(new SpidError(15, 'IssueInstant is after request', inResponseTo));
    }


    // Validate Destination

    const destinationAttr = xpath(responseNode, "@Destination");

    if (!destinationAttr.length) {
      return self.error(new SpidError(20, 'Missing Destination', inResponseTo));
    }

    if (!destinationAttr[0].nodeValue.length) {
      return self.error(new SpidError(19, 'Empty Destination', inResponseTo));
    }

    if (destinationAttr[0].nodeValue !== self.getCallbackUrl()) {
      return self.error(new SpidError(21, 'Invalid Destination', inResponseTo));
    }


    // Validate status

    const statusNode = xpath(responseNode, "./*[local-name()='Status']");
    const statusCodeNode = xpath(responseNode, "./*[local-name()='Status']/*[local-name()='StatusCode']");
    const statusCodeValueAttr = xpath(responseNode, "./*[local-name()='Status']/*[local-name()='StatusCode']/@Value");

    if (!statusNode.length) {
      return self.error(new SpidError(23, 'Missing Status', inResponseTo));
    }

    if (!statusCodeNode.length) {
      return self.error(new SpidError(22, 'Empty Status', inResponseTo));
      //return self.error(new SpidError(25, 'Empty Status', inResponseTo));
    }

    if (!statusCodeValueAttr[0].nodeValue.length) {
      return self.error(new SpidError(24, 'Empty StatusCode', inResponseTo));
    }


    if (statusCodeValueAttr[0].nodeValue !== 'urn:oasis:names:tc:SAML:2.0:status:Success' && !statusCodeNode[0].childNodes.length) {
      return self.error(new SpidError(26, 'Invalid StatusCode', inResponseTo));
    }

    if (statusCodeValueAttr[0].nodeValue !== 'urn:oasis:names:tc:SAML:2.0:status:Success' && statusCodeNode[0].childNodes.length > 1) {

      const statusMessageNode = xpath(statusNode[0], "./*[local-name()='StatusMessage']");

      switch (statusMessageNode[0].childNodes[0].nodeValue) {
        case 'ErrorCode nr19':
          return self.error(new SpidError(104, 'Too many failed login attempts', inResponseTo));
        case 'ErrorCode nr20':
          return self.error(new SpidError(105, 'Credentials with invalid level', inResponseTo));
        case 'ErrorCode nr21':
          return self.error(new SpidError(106, 'Authentication Timeout', inResponseTo));
        case 'ErrorCode nr22':
          return self.error(new SpidError(107, 'User decline access to his data', inResponseTo));
        case 'ErrorCode nr23':
          return self.error(new SpidError(108, 'User with blocked or suspended account', inResponseTo));
        case 'ErrorCode nr25':
          return self.error(new SpidError(111, 'Authentication cancelled by user', inResponseTo));

      }


    }

    // Validate Assertion

    const assertionNode = xpath(responseNode, "./*[local-name()='Assertion']");

    if (assertionNode.length > 1) {
      return self.error(new SpidError(0, 'Multiple assertion not allowed', inResponseTo));
    }

    if (!assertionNode.length) {
      return self.error(new SpidError(32, 'Missing Assertion', inResponseTo));
    }


    // Validate Assertion ID

    const assertionIdAttr = xpath(assertionNode[0], "@ID");

    if (!assertionIdAttr.length) {
      return self.error(new SpidError(34, 'Missing Assertion ID', inResponseTo));
    }

    if (!assertionIdAttr[0].nodeValue.length) {
      return self.error(new SpidError(33, 'Empty Assertion ID', inResponseTo));
    }


    // Validate Assertion Version

    const assertionVersionAttr = xpath(assertionNode[0], "@Version");

    if (!assertionVersionAttr[0].nodeValue.length || assertionVersionAttr[0].nodeValue !== '2.0') {
      return self.error(new SpidError(35, 'Invalid Assertion Version', inResponseTo));
    }


    // Validate Assertion IssueInstant

    const assertionIssueInstantAttr = xpath(assertionNode[0], "@IssueInstant");

    if (!assertionIssueInstantAttr.length) {
      return self.error(new SpidError(37, 'Missing Assertion IssueInstant', inResponseTo));
    }

    const assertionIssueInstant = assertionIssueInstantAttr[0].nodeValue;

    if (!assertionIssueInstant.length) {
      return self.error(new SpidError(36, 'Empty Assertion IssueInstant', inResponseTo));
    }

    if (!self.isValidDate(assertionIssueInstant)) {
      return self.error(new SpidError(38, 'Invalid Assertion IssueInstant', inResponseTo));
    }

    if (self.checkIsBefore(issueInstant, assertionIssueInstant)) {
      return self.error(new SpidError(39, 'Assertion IssueInstant is before request', inResponseTo));
    }

    if (self.checkIsOnOrAfter(issueInstant, assertionIssueInstant)) {
      return self.error(new SpidError(40, 'Assertion IssueInstant is after request', inResponseTo));
    }


    // Validate Assertion Subject

    const assertionSubjectNode = xpath(assertionNode[0], "./*[local-name()='Subject']");

    if (!assertionSubjectNode.length) {
      return self.error(new SpidError(42, 'Missing Assertion Subject', inResponseTo));
    }

    if (assertionSubjectNode[0].childNodes.length === 1 && !assertionSubjectNode[0].nodeValue) {
      return self.error(new SpidError(41, 'Empty Assertion Subject', inResponseTo));
    }


    // Validate Assertion Subject NameId

    const assertionSubjectNameIdNode = xpath(assertionSubjectNode[0], "./*[local-name()='NameID']");
    const assertionSubjectNameIdText = xpath(assertionSubjectNode[0], "./*[local-name()='NameID']/text()");
    const assertionSubjectNameIdFormatAttr = xpath(assertionSubjectNode[0], "./*[local-name()='NameID']/@Format");
    const assertionSubjectNameIdNameQualifierAttr = xpath(assertionSubjectNode[0], "./*[local-name()='NameID']/@NameQualifier");

    if (!assertionSubjectNameIdNode.length) {
      return self.error(new SpidError(44, 'Missing Assertion Subject NameID', inResponseTo));
    }

    if (!assertionSubjectNameIdText.toString().trim()) {
      return self.error(new SpidError(43, 'Empty Assertion Subject NameID', inResponseTo));
    }

    if (!assertionSubjectNameIdFormatAttr[0]) {
      return self.error(new SpidError(46, 'Missing Assertion Subject NameID Format', inResponseTo));
    }

    if (!assertionSubjectNameIdFormatAttr[0].nodeValue.length) {
      return self.error(new SpidError(45, 'Empty Assertion Subject NameID Format', inResponseTo));
    }

    if (assertionSubjectNameIdFormatAttr[0].nodeValue !== 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient') {
      return self.error(new SpidError(47, 'Invalid Assertion Subject NameID Format', inResponseTo));
    }

    if (!assertionSubjectNameIdNameQualifierAttr[0]) {
      return self.error(new SpidError(49, 'Missing Assertion Subject NameID NameQualifier', inResponseTo));
    }

    if (!assertionSubjectNameIdNameQualifierAttr[0].nodeValue.length) {
      return self.error(new SpidError(48, 'Empty Assertion Subject NameID NameQualifier', inResponseTo));
    }


    // Validate Assertion Subject Confirmation

    const assertionSubjectSubjectConfirmationNode = xpath(assertionSubjectNode[0], "./*[local-name()='SubjectConfirmation']");
    const assertionSubjectSubjectConfirmationText = xpath(assertionSubjectNode[0], "./*[local-name()='SubjectConfirmation']/text()");
    const assertionSubjectSubjectConfirmationMethodAttr = xpath(assertionSubjectNode[0], "./*[local-name()='SubjectConfirmation']/@Method");

    if (!assertionSubjectSubjectConfirmationNode.length) {
      return self.error(new SpidError(52, 'Missing Assertion Subject Confirmation', inResponseTo));
    }

    if (!assertionSubjectSubjectConfirmationText.toString().trim()) {
      return self.error(new SpidError(51, 'Empty Assertion Subject Confirmation', inResponseTo));
      //  return self.error(new SpidError(56, 'Empty Assertion Subject Confirmation', inResponseTo));
    }

    if (!assertionSubjectSubjectConfirmationMethodAttr[0]) {
      return self.error(new SpidError(54, 'Missing Assertion Subject Confirmation Method', inResponseTo));
    }

    if (!assertionSubjectSubjectConfirmationMethodAttr[0].nodeValue.length) {
      return self.error(new SpidError(53, 'Empty Assertion Subject Confirmation Method', inResponseTo));
    }

    if (assertionSubjectSubjectConfirmationMethodAttr[0].nodeValue !== 'urn:oasis:names:tc:SAML:2.0:cm:bearer') {
      return self.error(new SpidError(55, 'Invalid Assertion Subject NameID Format', inResponseTo));
    }

    const assertionSubjectSubjectConfirmationDataNode = xpath(assertionSubjectSubjectConfirmationNode[0], "./*[local-name()='SubjectConfirmationData']");
    const assertionSubjectSubjectConfirmationDataRecipientAttr = xpath(assertionSubjectSubjectConfirmationDataNode[0], "@Recipient");
    const assertionSubjectSubjectConfirmationDataInResponseToAttr = xpath(assertionSubjectSubjectConfirmationDataNode[0], "@InResponseTo");
    const assertionSubjectSubjectConfirmationDataNotOnOrAfterToAttr = xpath(assertionSubjectSubjectConfirmationDataNode[0], "@NotOnOrAfter");

    if (!assertionSubjectSubjectConfirmationDataRecipientAttr[0]) {
      return self.error(new SpidError(58, 'Missing Assertion Subject Confirmation Data Recipient', inResponseTo));
    }

    if (!assertionSubjectSubjectConfirmationDataRecipientAttr[0].nodeValue.length) {
      return self.error(new SpidError(57, 'Empty Assertion Subject Confirmation Data Recipient', inResponseTo));
    }

    if (assertionSubjectSubjectConfirmationDataRecipientAttr[0].nodeValue !== self.getCallbackUrl()) {
      return self.error(new SpidError(59, 'Invalid Assertion Subject Confirmation Data Recipient', inResponseTo));
    }

    if (!assertionSubjectSubjectConfirmationDataInResponseToAttr[0]) {
      return self.error(new SpidError(61, 'Missing Assertion Subject Confirmation Data InResponseTo', inResponseTo));
    }

    if (!assertionSubjectSubjectConfirmationDataInResponseToAttr[0].nodeValue.length) {
      return self.error(new SpidError(60, 'Empty Assertion Subject Confirmation Data InResponseTo', inResponseTo));
    }

    if (assertionSubjectSubjectConfirmationDataInResponseToAttr[0].nodeValue !== inResponseTo) {
      return self.error(new SpidError(62, 'Invalid Assertion Subject Confirmation Data InResponseTo', inResponseTo));
    }

    if (!assertionSubjectSubjectConfirmationDataNotOnOrAfterToAttr[0]) {
      return self.error(new SpidError(64, 'Missing Assertion Subject Confirmation Data NotOnOrAfter', inResponseTo));
    }

    if (!assertionSubjectSubjectConfirmationDataNotOnOrAfterToAttr[0].nodeValue.length) {
      return self.error(new SpidError(63, 'Empty Assertion Subject Confirmation Data NotOnOrAfter', inResponseTo));
    }

    if (!self.isValidDate(assertionSubjectSubjectConfirmationDataNotOnOrAfterToAttr[0].nodeValue)) {
      return self.error(new SpidError(65, 'Invalid Assertion Subject Confirmation Data NotOnOrAfter', inResponseTo));
    }

    if (self.checkIsBefore(issueInstant, assertionSubjectSubjectConfirmationDataNotOnOrAfterToAttr[0].nodeValue)) {
      return self.error(new SpidError(66, 'Assertion Subject Confirmation Data NotOnOrAfter is before request', inResponseTo));
    }


    // Validate Issuer and Assertion Issuer

    const issuerNode = xpath(responseNode, "./*[local-name()='Issuer']");
    const issuerFormatAttr = xpath(issuerNode[0], "@Format");
    const assertionIssuerNode = xpath(responseNode, "./*[local-name()='Assertion']/*[local-name()='Issuer']");
    const assertionIssuerFormatAttr = xpath(assertionIssuerNode[0], "@Format");

    if (!issuerNode.length) {
      return self.error(new SpidError(28, 'Missing Issuer', inResponseTo));
    }

    if (!issuerNode[0].firstChild) {
      return self.error(new SpidError(27, 'Empty Issuer', inResponseTo));
    }

    if (!assertionIssuerNode.length) {
      return self.error(new SpidError(68, 'Missing Assertion Issuer', inResponseTo));
    }

    if (!assertionIssuerNode[0].firstChild) {
      return self.error(new SpidError(67, 'Empty Assertion Issuer', inResponseTo));
    }

    if (issuerNode[0].firstChild.nodeValue !== assertionIssuerNode[0].firstChild.nodeValue) {
      return self.error(new SpidError(29, 'Invalid Issuer', inResponseTo));
      // return self.error(new SpidError(29, 'Invalid Issuer', inResponseTo));
    }

    if (!issuerFormatAttr.length) {
      return self.error(new SpidError(31, 'Missing Format Issuer', inResponseTo));
    }

    if (issuerFormatAttr[0].nodeValue !== 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity') {
      return self.error(new SpidError(30, 'Invalid Format Issuer', inResponseTo));
    }

    if (!assertionIssuerFormatAttr.length) {
      return self.error(new SpidError(71, 'Missing Assertion Issuer Format ', inResponseTo));
    }

    if (!assertionIssuerFormatAttr[0].nodeValue) {
      return self.error(new SpidError(70, 'Empty Assertion Issuer Format', inResponseTo));
    }

    if (assertionIssuerFormatAttr[0].nodeValue !== 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity') {
      return self.error(new SpidError(72, 'Invalid Assertion Issuer Format', inResponseTo));
    }


    // Validate Assertion conditions

    const assertionConditionsNode = xpath(assertionNode[0], "./*[local-name()='Conditions']");

    if (!assertionConditionsNode.length) {
      return self.error(new SpidError(74, 'Missing Assertion Conditions', inResponseTo));
    }

    if (assertionConditionsNode[0].childNodes.length === 1 && !assertionConditionsNode[0].nodeValue) {
      return self.error(new SpidError(73, 'Empty Assertion Conditions', inResponseTo));
      //return self.error(new SpidError(84, 'Empty Assertion Conditions', inResponseTo));
    }

    const assertionConditionsNotBeforeAttr = xpath(assertionConditionsNode[0], "@NotBefore");
    const assertionConditionsNotOnOrAfterAttr = xpath(assertionConditionsNode[0], "@NotOnOrAfter");

    if (!assertionConditionsNotBeforeAttr.length) {
      return self.error(new SpidError(76, 'Missing Assertion Conditions NotBefore ', inResponseTo));
    }

    if (!assertionConditionsNotBeforeAttr[0].nodeValue) {
      return self.error(new SpidError(75, 'Empty Assertion Conditions NotBefore', inResponseTo));
    }

    if (!self.isValidDate(assertionConditionsNotBeforeAttr[0].nodeValue)) {
      return self.error(new SpidError(77, 'Invalid Assertion Conditions NotBefore ', inResponseTo));
    }

    if (self.checkIsOnOrAfter(issueInstant, assertionConditionsNotBeforeAttr[0].nodeValue)) {
      return self.error(new SpidError(78, 'Invalid Assertion Conditions NotBefore ', inResponseTo));
    }

    if (!assertionConditionsNotOnOrAfterAttr.length) {
      return self.error(new SpidError(80, 'Missing Assertion Conditions NotOnOrAfter ', inResponseTo));
    }

    if (!assertionConditionsNotOnOrAfterAttr[0].nodeValue) {
      return self.error(new SpidError(79, 'Empty Assertion Conditions NotOnOrAfter', inResponseTo));
    }

    if (!self.isValidDate(assertionConditionsNotOnOrAfterAttr[0].nodeValue)) {
      return self.error(new SpidError(81, 'Invalid Assertion Conditions NotOnOrAfter ', inResponseTo));
    }

    if (self.checkIsBefore(issueInstant, assertionConditionsNotOnOrAfterAttr[0].nodeValue)) {
      return self.error(new SpidError(82, 'Invalid Assertion Conditions NotOnOrAfter ', inResponseTo));
    }

    const assertionConditionsAudienceRestrictionNode = xpath(assertionConditionsNode[0], "./*[local-name()='AudienceRestriction']");

    if (assertionConditionsAudienceRestrictionNode[0].childNodes.length === 1 && !assertionConditionsAudienceRestrictionNode[0].nodeValue) {
      return self.error(new SpidError(83, 'Empty Assertion Conditions AudienceRestriction', inResponseTo));
      // return self.error(new SpidError(86, 'Empty Assertion Conditions AudienceRestriction', inResponseTo));
    }

    const assertionConditionsAudienceRestrictionAudienceNode = xpath(assertionConditionsAudienceRestrictionNode[0], "./*[local-name()='Audience']");

    if (assertionConditionsAudienceRestrictionAudienceNode.length === 1 && !assertionConditionsAudienceRestrictionAudienceNode[0].firstChild) {
      return self.error(new SpidError(85, 'Empty Assertion Conditions AudienceRestriction Audience', inResponseTo));
    }

    if (assertionConditionsAudienceRestrictionAudienceNode[0].firstChild.nodeValue !== self.spidOptions.sp.issuer) {
      return self.error(new SpidError(87, 'Invalid Assertion Conditions AudienceRestriction Audience', inResponseTo));
    }


    // Validate Assertion AuthnStatement

    const assertionAuthnStatementNode = xpath(assertionNode[0], "./*[local-name()='AuthnStatement']");

    if (!assertionAuthnStatementNode.length) {
      return self.error(new SpidError(89, 'Missing Assertion AuthnStatement', inResponseTo));
    }

    if (assertionAuthnStatementNode[0].childNodes.length === 1 && !assertionAuthnStatementNode[0].nodeValue) {
      return self.error(new SpidError(88, 'Empty Assertion AuthnStatement', inResponseTo));
      // return self.error(new SpidError(91, 'Empty Assertion Conditions AuthnStatement AuthnContext', inResponseTo));
    }

    const assertionAuthnStatementAuthnContextNode = xpath(assertionAuthnStatementNode[0], "./*[local-name()='AuthnContext']");

    if (assertionAuthnStatementAuthnContextNode[0].childNodes.length === 1 && !assertionAuthnStatementAuthnContextNode[0].nodeValue) {
      return self.error(new SpidError(90, 'Empty Assertion Conditions AuthnStatement AuthnContext', inResponseTo));
      // return self.error(new SpidError(93, 'Empty Assertion Conditions AuthnStatement AuthnContext AuthnContextClassRef', inResponseTo));
    }

    const assertionAuthnStatementAuthnContextAuthnContextClassRefNode = xpath(assertionAuthnStatementAuthnContextNode[0], "./*[local-name()='AuthnContextClassRef']");

    if (assertionAuthnStatementAuthnContextAuthnContextClassRefNode.length === 1 && !assertionAuthnStatementAuthnContextAuthnContextClassRefNode[0].firstChild) {
      return self.error(new SpidError(92, 'Empty Assertion Conditions AuthnStatement AuthnContext AuthnContextClassRef', inResponseTo));
    }

    if (self.spidOptions.sp.authnContext === 'https://www.spid.gov.it/SpidL1'
      && (
        assertionAuthnStatementAuthnContextAuthnContextClassRefNode[0].firstChild.nodeValue === 'https://www.spid.gov.it/SpidL2' ||
        assertionAuthnStatementAuthnContextAuthnContextClassRefNode[0].firstChild.nodeValue === 'https://www.spid.gov.it/SpidL3')
    ) {
      // no need to throw error to handle an higher spidLevel
    }

    if (self.spidOptions.sp.authnContext === 'https://www.spid.gov.it/SpidL2' &&
      assertionAuthnStatementAuthnContextAuthnContextClassRefNode[0].firstChild.nodeValue === 'https://www.spid.gov.it/SpidL1'
    ) {
      return self.error(new SpidError(95, 'AuthnContextClassRefn lower than required', inResponseTo));
    }

    if (self.spidOptions.sp.authnContext === 'https://www.spid.gov.it/SpidL3' && (
      assertionAuthnStatementAuthnContextAuthnContextClassRefNode[0].firstChild.nodeValue === 'https://www.spid.gov.it/SpidL1' ||
      assertionAuthnStatementAuthnContextAuthnContextClassRefNode[0].firstChild.nodeValue === 'https://www.spid.gov.it/SpidL2')
    ) {
      return self.error(new SpidError(96, 'AuthnContextClassRefn lower than required', inResponseTo));
    }

    if (assertionAuthnStatementAuthnContextAuthnContextClassRefNode[0].firstChild.nodeValue !== 'https://www.spid.gov.it/SpidL1' &&
      assertionAuthnStatementAuthnContextAuthnContextClassRefNode[0].firstChild.nodeValue !== 'https://www.spid.gov.it/SpidL2' &&
      assertionAuthnStatementAuthnContextAuthnContextClassRefNode[0].firstChild.nodeValue !== 'https://www.spid.gov.it/SpidL3'
    ) {
      return self.error(new SpidError(97, 'Invalid AuthnContextClassRefn', inResponseTo));
    }


    // Validate Assertion AttributeStatement

    const assertionAttributeStatementNode = xpath(assertionNode[0], "./*[local-name()='AttributeStatement']");

    if (assertionAttributeStatementNode[0].childNodes.length === 1 && !assertionAttributeStatementNode[0].nodeValue) {
      return self.error(new SpidError(98, 'Empty Assertion AttributeStatement', inResponseTo));
    }

    const assertionAttributeStatementAttributeNode = xpath(assertionAttributeStatementNode[0], "./*[local-name()='Attribute']");

    if (!assertionAttributeStatementAttributeNode[0].childNodes.length && !assertionAttributeStatementAttributeNode[0].nodeValue) {
      return self.error(new SpidError(99, 'Empty Assertion AttributeStatement Attribute', inResponseTo));
    }

    if (assertionAttributeStatementAttributeNode.length !== spidOptions.attributes.attributes.length) {
      return self.error(new SpidError(103, 'Required attributes not match', inResponseTo));
    }


    // Validate signatures

    const responseSignature = xpath(responseNode, "./*[local-name()='Signature']");
    const assertionSignature = xpath(assertionNode[0], "./*[local-name()='Signature']");

    if (!responseSignature.length) {
      return self.error(new SpidError(2, 'Response not signed', inResponseTo));
    }

    if (!assertionSignature.length) {
      return self.error(new SpidError(3, 'Invalid signature - Assertion not signed', inResponseTo));
    }

    const validAssertionSignature = self.validateSignature(xml, assertionNode[0], self.certsToCheck());
    const validResponseSignature = self.validateSignature(xml, responseNode, self.certsToCheck());

    if (!validResponseSignature || !validAssertionSignature) {
      return self.error(new SpidError(4, 'Response Invalid Signature', inResponseTo));
      // return self.error(new SpidError(100, 'Response Invalid Assertion Signature', inResponseTo));
    }

    // if no error throw process assertion
    return self.processAssertion(assertionNode.toString(), inResponseTo, callback);

  };


}

class SpidError extends Error {
  constructor(code, message, requestId = null) {
    super(message);
    this.name = "SpidError";
    this.code = code;
    this.requestId = requestId;
  }
}

module.exports = SpidStrategy;
