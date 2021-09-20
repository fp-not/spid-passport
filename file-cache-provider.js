/**
 * Simple file cache provider. To be used to store state of requests that needs
 * to be validated/checked when a response is received.
 *
 * This is the persistent implementation of a cache provider used by Passport-SAML.  For
 * multiple server instances/load balanced scenarios (I.e. the SAML request could have
 * been generated from a different server/process handling the SAML response) this
 * implementation will NOT be sufficient.
 *
 * @param options
 * @constructor
 */

const fs = require('fs');
const crypto = require("crypto");

class FileCacheProvider {

  constructor(options) {

    if (!options) {
      options = {};
    }

    if (!options.keyExpirationPeriodMs) {
      options.keyExpirationPeriodMs = 28800000;  // 8 hours
    }

    if (!options.cacheDir) {
      options.cacheDir = __dirname + '/cache'
    }

    this.options = options;


    // Expire old cache keys
    const expirationTimer = setInterval(() => {

      const nowMs = new Date().getTime();

      console.log(new Date())

      this.cacheKeys().forEach((key) => {
        const keyCreatedAt = this.createdAt(key);
        if (nowMs >= keyCreatedAt + this.options.keyExpirationPeriodMs) {
          fs.unlinkSync(`${this.options.cacheDir}/${key}`);
        }
      });
    }, this.options.keyExpirationPeriodMs);

    // we only want this to run if the process is still open; it shouldn't hold the process open
    if (expirationTimer.unref) {
      expirationTimer.unref();
    }

  }


  cacheFile = (key) => {

    const cacheKey = crypto.scryptSync(key, process.env.SPID_SECRET, 30).toString('hex');
    return this.options.cacheDir + '/' + cacheKey;

  }

  /**
   * Returns the value of the specified key in the cache
   * @param key
   */
  get = (key) => {
    const cacheFile = this.cacheFile(key);

    return new Promise(function(resolve, reject){
      fs.readFile(cacheFile, 'utf8', (err, data) => {
        err ? reject(err) : resolve(data);
      });
    });

  }

  set = (key, value) => {

    const cacheFile = this.cacheFile(key);

    return new Promise((resolve, reject) => {
      fs.writeFile(cacheFile, value, (err) => {
        err ? reject(err) : resolve(true);
      });
    });

  }


  /**
   * Removes an item from the cache if it exists
   * @param key
   */
  remove = (key) => {

    const cacheFile = this.cacheFile(key);
    return new Promise((resolve, reject) => {
      fs.unlink(cacheFile, (err) => {
        err ? reject(err) : resolve(true);
      });
    });
  }

  cacheKeys = () => {
    return fs.readdirSync(this.options.cacheDir);
  }

  createdAt = (key, ms=true) => {

    if(ms){
      const {birthtimeMs} = fs.statSync(`${this.options.cacheDir}/${key}`)
      return birthtimeMs
    }

    const {birthtime} = fs.statSync(`${this.options.cacheDir}/${key}`)
    return birthtime
  }

  debug = () => {
    this.cacheKeys().map((key) => {
      //return `${this.options.cacheDir}/${key}`;
      console.log(`${key} ${this.createdAt(key, false)}`);
    });
  }


}


module.exports = FileCacheProvider;
