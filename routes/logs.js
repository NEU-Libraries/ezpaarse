/*jslint node: true, maxlen: 100, maxerr: 50, indent: 2 */
'use strict';

var fs     = require('fs');
var path   = require('path');
var moment = require('moment');

module.exports = function (app) {
  
  var jobidPattern = '^/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})';
  /**
   * GET route on /:rid/:logfile
   * Used to get a logfile
   */
  app.get(new RegExp(jobidPattern + '/([a-zA-Z\\-]+\\.log)$'), function (req, res) {
    var requestID = req.params[0];
    var logFile   = path.join(__dirname, '/../tmp/jobs/',
      requestID.charAt(0),
      requestID.charAt(1),
      requestID,
      req.params[1]);
    if (fs.existsSync(logFile)) {
      fs.stat(logFile, function (err, stats) {
        if (err) {
          res.status(500);
          res.end();
          return;
        }
        // download as an attachment if file size is >500ko
        // open it in directly in the browser if file size is <500ko
        if (stats.size > 500 * 1024) {
          res.download(logFile, requestID + '-' + req.params[1]);
        } else {
          res.sendfile(logFile);
        }
      });
    } else {
      res.status(404);
      res.end();
    }
  });

  /**
   * GET route on /:rid/job-report.{html|json}
   * Used to get a report file
   */
  app.get(new RegExp(jobidPattern + '/job-report\\.(html|json)$'), function (req, res) {
    var requestID  = req.params[0];
    var format     = req.params[1];
    var logPath    = path.join(__dirname, '/../tmp/jobs/',
    requestID.charAt(0),
    requestID.charAt(1),
    requestID);
    var reportFile = path.join(logPath, '/report.json');
    fs.exists(reportFile, function (exists) {
      if (!exists) {
        res.status(404);
        res.end();
        return;
      }

      switch (format) {
      case 'json':
        res.sendfile('report.json', {root: logPath}, function (err) {
          if (err) {
            res.status(500);
            res.end();
            return;
          }
        });
        break;
      case 'html':
        fs.readFile(reportFile, function (err, data) {
          if (err) {
            res.status(500);
            res.end();
            return;
          }
          var report = JSON.parse(data);
          var title = "Rapport d'exécution";
          if (report.general && report.general['Job-Date']) {
            title += " (" + moment(report.general['Job-Date']).format('DD-MM-YYYY hh[h]mm') + ')';
          }
          title += ' - ezPAARSE';
          // Rapport d’exécution (25-06-2013 11h25) - ezPAARSE
          res.render('report', { report: report, title: title, user: req.user });
        });
        break;
      default:
        res.status(406);
        res.end();
      }
    });
  });
};
