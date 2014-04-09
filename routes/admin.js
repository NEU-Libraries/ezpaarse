'use strict';

var path     = require('path');
var crypto   = require('crypto');
var express  = require('express');
var execFile = require('child_process').execFile;
var userlist = require('../lib/userlist.js');
var auth     = require('../lib/auth-middlewares.js');

module.exports = function (app) {

  /**
   * GET route on /users
   * To get the user list
   */
  app.get('/users', auth.ensureAuthenticated(true), function (req, res) {
      var users = userlist.getAll();
      res.set("Content-Type", "application/json; charset=utf-8");
      res.set("ezPAARSE-Logged-User", req.user.username);
      res.send(200, JSON.stringify(users));
    }
  );

  /**
   * POST route on /users
   * To add a user
   */
  app.post('/users/', express.bodyParser(), function (req, res) {
    var userid   = req.body.userid;
    var password = req.body.password;
    var confirm  = req.body.confirm;

    if (!userid || !password || !confirm) {
      res.writeHead(400, {
        'ezPAARSE-Status-Message': 'vous devez soumettre un login et un mot de passe'
      });
      res.end();
      return;
    }

    if (password != confirm) {
      res.writeHead(400, {
        'ezPAARSE-Status-Message': 'le mot de passe de confirmation ne correspond pas'
      });
      res.end();
      return;
    }

    if (userlist.get(userid)) {
      res.writeHead(409, {
        'ezPAARSE-Status-Message': 'cet utilisateur existe'
      });
      res.end();
      return;
    }

    var cryptedPassword = crypto.createHmac('sha1', 'ezgreatpwd0968')
    .update(userid + password)
    .digest('hex');

    var user = userlist.add({
      username: userid,
      password: cryptedPassword,
      group: userlist.length() === 0 ? 'admin' : 'user'
    });

    if (!user) {
      res.send(500);
      return;
    }

    var copyUser = {};
    for (var prop in user) {
      if (prop != 'password') { copyUser[prop] = user[prop]; }
    }

    if (req.user && req.user.group == 'admin') {
      //TODO: put that in a separate route
      res.set("Content-Type", "application/json; charset=utf-8");
      res.json(201, copyUser);
      return;
    }

    req.logIn(user, function (err) {
      if (err) {
        res.send(500);
        return;
      }
      res.set("Content-Type", "application/json; charset=utf-8");
      res.json(201, copyUser);
    });
  });

  /**
   * DELETE route on /users/{username}
   * To remove a user
   */
  app.delete(/^\/users\/([a-zA-Z0-9\-_]+)$/, auth.ensureAuthenticated(true),
    auth.authorizeMembersOf('admin'), function (req, res) {
      var username = req.params[0];
      if (username == req.user.username) {
        res.set('ezPAARSE-Status-Message', 'vous ne pouvez pas vous supprimer vous-même');
        res.send(403);
      } else {
        var user = userlist.remove(username);
        if (user) {
          res.send(204);
        } else {
          res.send(404);
        }
      }
    }
  );

  /**
   * GET route on /pkb/status
   * To know if there are incoming changes in the PKB folder
   */
  app.get('/pkb/status', auth.ensureAuthenticated(true), function (req, res) {
    var pkbFolder = path.join(__dirname, '../platforms-kb');
    var gitscript = path.join(__dirname, '../bin/check-git-uptodate');

    execFile(gitscript, {cwd: pkbFolder}, function (error, stdout) {
      if (error || !stdout) {
        res.send(500);
        return;
      }
      res.send(200, stdout);
    });
  });

  function updatePkb(req, res) {
    var bodyString = '';

    req.on('readable', function () {
      bodyString += req.read() || '';
    });

    req.on('error', function () {
      res.send(500);
    });

    req.on('end', function () {
      if (bodyString.trim() == 'uptodate') {
        var pkbFolder = path.join(__dirname, '../platforms-kb');
        var gitscript = path.join(__dirname, '../bin/git-update');

        execFile(gitscript, {cwd: pkbFolder}, function (error) {
          if (error) {
            res.send(500);
            return;
          }
          res.send(200);
        });
      } else {
        res.send(400);
      }
    });
  }

  /**
   * PUT route on /pkb/status
   * To update the PKB folder
   */
  app.put('/pkb/status', auth.ensureAuthenticated(true),
    auth.authorizeMembersOf('admin'), updatePkb);

  /**
   * GET route on /parsers/status
   * To know if there are incoming changes in the parsers folder
   */
  app.get('/parsers/status', auth.ensureAuthenticated(true),
    function (req, res) {
    var parsersFolder = path.join(__dirname, '../platforms-parsers');
    var gitscript = path.join(__dirname, '../bin/check-git-uptodate');

    execFile(gitscript, {cwd: parsersFolder}, function (error, stdout) {
      if (error || !stdout) {
        res.send(500);
        return;
      }
      res.send(200, stdout);
    });
  });

  function updateParsers(req, res) {
    var bodyString = '';

    req.on('readable', function () {
      bodyString += req.read() || '';
    });

    req.on('error', function () {
      res.send(500);
    });

    req.on('end', function () {
      if (bodyString.trim() == 'uptodate') {
        var parsersFolder = path.join(__dirname, '../platforms-parsers');
        var gitscript = path.join(__dirname, '../bin/git-update');

        execFile(gitscript, {cwd: parsersFolder}, function (error) {
          if (error) {
            res.send(500);
            return;
          }
          res.send(200);
        });
      } else {
        res.send(400);
      }
    });
  }

  /**
   * PUT route on /parsers/status
   * To update the parsers folder
   */
  app.put('/parsers/status', auth.ensureAuthenticated(true),
    auth.authorizeMembersOf('admin'), updateParsers);
};
