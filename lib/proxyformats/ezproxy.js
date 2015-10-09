/*jshint maxlen: 150*/
'use strict';

/*
* Takes a custom log format and translates it into
* a regex using EZproxy syntax.
* logFormat example: %h %l %u [%t] "%r" %s %b
* %h | %u | %t | "%r" | %b | "%{referer}<[a-zA-Z0-9:.?=/&_%+ -]+>" | "%{user-agent}<.*>" | "%{loginName}<[a-zA-Z0-9: -]+>"|"%{nuid}<[a-zA-Z0-9: -]+>"|"%{fullName}<[a-zA-Z0-9: -]+>"|"%{affiliation}<[a-zA-Z0-9: -]+>"|"%{college}<[a-zA-Z0-9: -]+>"|"%{collegeName}<[a-zA-Z0-9: -]+>"|"%{campus}<[a-zA-Z0-9: -]+>"|"%{school}<[a-zA-Z0-9: -]+>"|"%{schoolName}<[a-zA-Z0-9: -]+>"|"%{department}<[a-zA-Z0-9: -]+>"|"%{departmentName}<[a-zA-Z0-9: -]+>"|"%{classLevel}<[a-zA-Z0-9: -]+>"|"%{ezproxy-groups}<[a-zA-Z0-9:+ -]+>"|"%{coop}<[a-zA-Z0-9: -]+>"|"%{emeritus}<[a-zA-Z0-9: -]+>"
*/

function regexpEscape(str) {
  if (!str) { return ''; }
  return str.replace(/[\-\[\]\/\{\}\(\)\*\+\?\.\\\^\$\|]/g, "\\$&");
}

module.exports = function (logFormat, laxist) {
  var usedProperties = [];
  var parameters = {
    '%h': {property: 'host',     regexp: '([a-zA-Z0-9\\.\\-]+(?:, ?[a-zA-Z0-9\\.\\-]+)*)'},
    '%u': {property: 'login',    regexp: '([a-zA-Z0-9@\\.\\-_%,=]+)'},
    '%l': {property: 'identd',   regexp: '([a-zA-Z0-9\\-]+)'},
    '%b': {property: 'size',     regexp: '([0-9]+)'},
    '%U': {property: 'url',      regexp: '([^ ]+)'},
    '%m': {property: 'method',   regexp: '([A-Z]+)'},
    '%r': {property: 'url',      regexp: '[A-Z]+ ([^ ]+) [^ ]+'                        },
    '%t': {property: 'datetime', regexp: '\\[([^\\]]+)\\]'},
    '%s': {property: 'status',   regexp: '([0-9]+)'},
    '%referer': {property: 'referer', regexp: '([a-zA-Z0-9:.?=/&_%+ -]+)'},
    '%user-agent': {property: 'user-agent', regexp: '(.*)'},
    '%loginName': {property: 'loginName', regexp: '([a-zA-Z0-9: -]+)'},
    '%nuid': {property: 'nuid', regexp:'([a-zA-Z0-9: -]+)'},
    '%fullName': {property:'fullName', regexp:'([a-zA-Z0-9: -]+)'},
    '%affiliation': {property:'affiliation', regexp:'([a-zA-Z0-9: -]+)'},
    '%college': {property:'college', regexp:'([a-zA-Z0-9: -]+)'},
    '%collegeName': {property:'collegeName', regexp:'([a-zA-Z0-9: -]+)'},
    '%campus': {property:'campus', regexp:'([a-zA-Z0-9: -]+)'},
    '%school': {property:'school', regexp:'([a-zA-Z0-9: -]+)'},
    '%schoolName': {property:'schoolName', regexp:'([a-zA-Z0-9: -]+)'},
    '%department': {property:'department', regexp:'([a-zA-Z0-9: -]+)'},
    '%departmentName': {property:'departmentName', regexp:'([a-zA-Z0-9: -]+)'},
    '%classLevel': {property:'classLevel', regexp:'([a-zA-Z0-9:+ -]+)'},
    '%ezproxy-groups': {property:'ezproxy-groups', regexp:'([a-zA-Z0-9:+ -]+)'},
    '%coop': {property:'coop', regexp:'([a-zA-Z0-9: -]+)'},
    '%emeritus': {property:'emeritus', regexp:'([a-zA-Z0-9: -]+)'},
  };


  // Initialize the format with a 'raw' regex (parameters yet to be translated)
  var format = {
    regexp: '^' + regexpEscape(logFormat) + (laxist ? '' : '$'),
    properties: []
  };

  // This regexp is used to catch any expression matching one of those patterns :
  //   %x
  //   %{property}<regexp>
  //   %<regexp>
  var paramRegex = new RegExp('(%[a-zA-Z]|%{[a-zA-Z0-9\\-_]+}i?<[^<>]+>|%<[^<>]+>|%{[a-zA-Z0-9\\-_]+}i?)', 'g');
  var match;

  while ((match = paramRegex.exec(logFormat)) !== null) {
    var paramToTranslate  = match[1];
    var customRegexp      = false;
    var customProperty    = false;
    var customMatch;

    // When a property or a regexp is provided, we must grab the expression inside {...} or <...>
    if ((customMatch = new RegExp('^%{([a-zA-Z0-9\\-_]+)}i?$').exec(paramToTranslate)) !== null) {
      customProperty = customMatch[1];
    } else if ((customMatch = new RegExp('^%{([a-zA-Z0-9\\-_]+)}i?<([^<>]+)>$').exec(paramToTranslate)) !== null) {
      customProperty = customMatch[1];
      customRegexp = customMatch[2];
    } else if ((customMatch = new RegExp('^%<([^<>]+)>$').exec(paramToTranslate)) !== null) {
      customRegexp = customMatch[1];
    }

    if (customProperty) {
      // Properties can't be used twice
      if (usedProperties.indexOf(customProperty) != -1) { return null; }

      customRegexp = customRegexp || '[a-zA-Z0-9\\-]+';
      if (/\((?!\?:)/.test(customRegexp)) {
        return null;
      }
      customRegexp = '(' + customRegexp + ')';

      parameters[customProperty] = {
        regexp: customRegexp,
        property: customProperty
      };
      usedProperties.push(customProperty);
    } else if (customRegexp) {
      // If a regex has no matching label, it'll be taken into account
      // but won't be caught when parsing log lines
      if (/\((?!\?:)/.test(customRegexp)) {
        return null;
      }
      format.regexp = format.regexp.replace(regexpEscape(paramToTranslate), customRegexp);
      continue;
    }

    var param = parameters[customProperty || paramToTranslate];
    if (param) {
      format.properties.push(param.property);
      format.regexp = format.regexp.replace(regexpEscape(paramToTranslate), param.regexp);
    }
  }

  try {
    format.regexp = new RegExp(format.regexp);
  } catch (e) {
    return null;
  }

  return format;
};
