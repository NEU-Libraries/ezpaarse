'use strict';

var iconv = require('iconv-lite');

/**
 * Get requested charsets for input and ouput streams
 * @param  {Object}   req   the request stream
 * @param  {Object}   res   the response stream
 * @param  {Object}   job   the job being initialized
 * @param  {Function} next  continue to next middleware
 */
module.exports = function (req, res, job, next) {
  job.logger.verbose('Initializing charsets');

  var reqCharset = req.header('request-charset')  || 'utf-8';
  var resCharset = req.header('response-charset') || 'utf-8';
  var err;

  if (iconv.encodingExists(reqCharset)) {
    job.logger.info('Charset for request : ' + reqCharset);
    job.inputCharset = reqCharset;
  } else {
    job.logger.warn('(request) Charset is  not supported');
    err        = new Error();
    err.code   = 4015;
    err.status = 406;
    return next(err);
  }

  if (iconv.encodingExists(resCharset)) {
    job.logger.info('Charset for response : ' + resCharset);
    job.outputCharset = resCharset;
  } else {
    job.logger.warn('(response) Charset is  not supported');
    err        = new Error();
    err.code   = 4016;
    err.status = 406;
    return next(err);
  }

  next(null);
};