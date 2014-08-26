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
empty    | Track empty files
readable | Check if files are readable
writable | Check if files are writable
updated  | Check if files has been updated since last check
big      | Track big files and files larger "than post_max_size"
eval     | Track PHP files with suspect "eval()"

### Report Plugins

Name     | Description
-------- | -----------------------------------
echo     | Display result to browser / screen
log      | Log result in malicious.log

Resources
---

### inspiration

- [Malicious Code Scanner](https://github.com/mikestowe/Malicious-Code-Scanner)
- [Obfuscalp](https://github.com/Orbixx/Obfuscalp)
- [Tripwire](https://github.com/lucanos/Tripwire)

TODO
---
- More plugins
- Documentation
