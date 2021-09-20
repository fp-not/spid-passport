/**
 * Simple in memory cache provider.  To be used to store state of requests that needs
 * to be validated/checked when a response is received.
 *
 * This is the default implementation of a cache provider used by Passport-SAML.  For
 * multiple server instances/load balanced scenarios (I.e. the SAML request could have
 * been generated from a different server/process handling the SAML response) this
 * implementation will NOT be sufficient.
 *
 * @param options
 * @constructor
 */
class InmemoryCacheProvider {

  constructor(options) {

    this.cacheKeys = {};

    if (!options) {
      options = {};
    }

    if (!options.keyExpirationPeriodMs) {
      options.keyExpirationPeriodMs = 28800000;  // 8 hours
    }

    this.options = options;

    // Expire old cache keys
    const expirationTimer = setInterval(() => {

      const nowMs = new Date().getTime();
      const keys = Object.keys(this.cacheKeys);

      keys.forEach((key) => {
        if (nowMs >= new Date(this.cacheKeys[key].createdAt).getTime() + this.options.keyExpirationPeriodMs) {
          this.remove(key);
        }
      });
    }, this.options.keyExpirationPeriodMs);

    // we only want this to run if the process is still open; it shouldn't hold the process open
    if (expirationTimer.unref) {
      expirationTimer.unref();
    }

  }


  /**
   * Store an item in the cache, using the specified key and value.
   * Internally will keep track of the time the item was added to the cache
   * @param key
   * @param value
   * @returns {Promise}
   */
  set = function (key, value) {
    return new Promise((resolve, reject) => {
      if (!this.cacheKeys[key]) {
        this.cacheKeys[key] = {
          createdAt: new Date().getTime(),
          value: value
        };
        resolve(true);
      }
      reject();
    });

  }


  /**
   * Returns the value of the specified key in the cache
   * @param key
   * @returns {Promise}
   */
  get = function (key) {
    return new Promise((resolve, reject) => {
      return this.cacheKeys[key] ? resolve(this.cacheKeys[key].value) : reject();
    });
  }


  /**
   * Removes an item from the cache if it exists
   * @param key
   * @returns {Promise}
   */
  remove = function (key) {
    return new Promise((resolve, reject) => {
      if (this.cacheKeys[key]) {
        delete this.cacheKeys[key];
        return resolve(true);
      } else {
        return reject();
      }
    });
  }


  debug = function(){
    return this.cacheKeys;
  }

}


module.exports = InmemoryCacheProvider;
