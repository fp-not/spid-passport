/**
 * Simple redis cache provider. To be used to store state of requests that needs
 * to be validated/checked when a response is received.
 *
 * @param options
 * @constructor
 */

const Redis = require("ioredis");

class RedisCacheProvider {

  constructor(options) {

    if (!options) {
      options = {};
    }

    if (!options.keyExpirationPeriodMs) {
      options.keyExpirationPeriodMs = 28800000;  // 8 hours
    }

    options.host = options.host || "localhost";
    options.port = options.port || 6379;
    options.db = options.db || 0;

    this.redisClient = new Redis({
      host: options.host,
      port: options.port,
      db: options.db
    })

    this.options = options;

  }


  /**
   * Returns the value of the specified key in the cache
   * @param key
   */
  get = (key) => {
    return this.redisClient.get(key);
  }

  set = (key, value) => {
    return this.redisClient.set(key, value, 'ex', this.options.keyExpirationPeriodMs);
  }

  /**
   * Removes an item from the cache if it exists
   * @param key
   */
  remove = (key) => {
      return this.redisClient.del(key);
  }


  debug = () => {

    return this.redisClient.keys('*', (err, res) => {
      console.log(res);
    });
  }


}


module.exports = RedisCacheProvider;
