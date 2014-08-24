Malicious
=========

A simple, lightweight code to detect potential malicious PHP Code and few other commons sources of problems. Fully extensible with plugins (Check & Report) support...

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
empty    | Check for empty files
readable | Check if files are readable
writable | Check if files are writable
updated  | Check if files has been updated since last check
updated  | Check for big files and files larger "than post_max_size"

### Report Plugins

Name     | Description
-------- | -----------------------------------
echo     | Display result to browser / screen
log      | Log result in malicious.log

TODO
---
- More plugins
- Documentation
