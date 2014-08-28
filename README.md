Malicious
=========

A simple, lightweight framework to detect potential suspicious/malicious PHP Code and few other commons sources of problems. Fully extensible with plugins (Check & Report) support...

@copyright [Ackwa.fr](http://www.ackwa.fr) - 2014

Usage
---
### via HTTP

```
http://mydomain.com/Malicious/index.php?s=mysecretkey
```

### via CLI

```
php index.php -s=mysecretkey
```

Plugins
---

Active plugins are defined in config.php` via `MCS_PLUGINS` (Check) and `MCS_REPORTS` (Report) constants:

```
define('MCS_PLUGINS'  , 'readable,big');
define('MCS_REPORTS'  , 'echo');
```

### Check Plugins

Name     | Description
-------- | -----------------------------------
readable | Check if files are readable
writable | Check if files are writable
updated  | Check if files has been updated since last check
eval     | Track PHP files with suspect "eval()"
empty    | Track empty files
big      | Track big files and files larger "than post_max_size"
hidden   | Track hidden files and directories (.xxx)
image    | In progress
syntax   | In progress
metrics  | In progress

### Report Plugins

Name        | Description
----------- | -----------------------------------
echo        | Display result to browser / screen
log         | Log result in malicious.log
Mail        | In progress
Analytics   | In progress
In Progress | In progress

Resources
---

### inspiration

- [Malicious Code Scanner](https://github.com/mikestowe/Malicious-Code-Scanner)
- [Obfuscalp](https://github.com/Orbixx/Obfuscalp)
- [Tripwire](https://github.com/lucanos/Tripwire)

### Security informations

- [Code injection – a simple PHP virus carried in a JPEG image](http://php.webtutor.pl/en/2011/05/13/php-code-injection-a-simple-virus-written-in-php-and-carried-in-a-jpeg-image)

TODO
---
- More plugins
- Documentation
