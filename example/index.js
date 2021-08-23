const fs = require('fs')
const express = require('express')
const app = express()
const bodyParser = require('body-parser')
const passport = require('passport')
const SpidStrategy = require('../index')


app.use(bodyParser.urlencoded({ extended: false }))

// parse application/json
app.use(bodyParser.json())

// init passport
app.use(passport.initialize())

let spidStrategy = new SpidStrategy({
  sp: {
    entryPoint: 'https://demo.spid.gov.it/samlsso',
    callbackUrl: "https://example.com/acs",
    logoutCallbackUrl: "https://example.com/logout",
    issuer: "https://www.example.com",
    privateCert: fs.readFileSync("./certs/spid-sp.pem", "utf-8"),
    decryptionPvk: fs.readFileSync("./certs/spid-sp.crt", "utf-8"),
    digestAlgorithm: "sha256",
    signatureAlgorithm: "sha256",
    attributeConsumingServiceIndex: 0,
    identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    authnContext: "https://www.spid.gov.it/SpidL1",
    attributes: {
      name: "Required attributes",
      description: "Required attributes to allow login inside app",
      attributes: [
        "spidCode",
        "name",
        "familyName",
        "email",
        "dateOfBirth",
        "gender",
        "fiscalNumber",
        "mobilePhone",
        "address"
      ]
    },
    organization: {
      name: "example",
      displayName: "example",
      URL: "https://www.example.com",

      contact : {
        technical: {
          company: "example",
          vatNumber: "0000000000",
          emailAddress: "info@example.com",
          telephoneNumber: "000000",
        },
        billing: {
          company: "example S.p.A.",
          vatNumber: "00000000",
          street: "via milano",
          streetNumber: "10",
          postalCode: "20100",
          city: "Milano",
          province: "MI",
          country: "IT",
          emailAddress: "info@example.com",
          telephoneNumber: "0000000",
        }
      },

    }
  },
  idp: {
    test: {
      entryPoint: "https://spid-testenv-identityserver:9443/samlsso",
      cert: "MIICNTCCAZ6gAwIBAgIES343gjANBgkqhkiG9w0BAQUFADBVMQswCQYD..."
    }
  }
}, function(profile, done){

  // Find or create your user
  console.log('all done!!!!!', profile)
  done(null, profile);
})

passport.use(spidStrategy)

app.get("/login", passport.authenticate('spid'))

app.post("/acs",
  passport.authenticate('spid', {session: false}),
  function(req, res){
    console.log(req.user)
    res.send(`Hello ${req.user.name_id}`)
  })

// Create xml metadata
app.get("/metadata", spidStrategy.generateServiceProviderMetadata(fs.readFileSync("./certs/spid-sp.crt", "utf-8")))


app.listen(3000);
