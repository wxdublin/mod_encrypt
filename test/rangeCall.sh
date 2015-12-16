#!/bin/bash

curl -v -XPUT -H "Expect:" -H "x-scal-usermd: bXl1c2VybWQ=" http://127.0.0.1/myFCGI/1234 --data-binary @testfile
sleep 1
curl -v -H "Content-Range: bytes=100-900,1000-1500" http://127.0.0.1/myFCGI/1234
echo "done"

