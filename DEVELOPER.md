logstash-CEF
============

Logstash Codec to handle CEF encoded data

Build
=====

Run 'make tarball' to build the project. A tarball will end up in ./build. Extract the file over top of your logstash directory. 
(Hint: or, just copy the ./lib and ./vendor directories to your logstash folder)


Config
======

This is an example input config. 

```
input {
    generator {
	message => "TODO"
	count => 1
	codec => cef
    }
}

output {
    stdout { 
	codec => "rubydebug"
    }
}
```

This is an example output config. 

```
input {
    generator {
	message => "TODO"
	count => 1
    }
}

output {
    stdout { 
	codec => cef
    }
}
```
