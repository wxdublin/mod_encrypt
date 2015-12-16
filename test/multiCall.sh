#!/bin/bash

for i in {1..10}
do
{
	curl -v -XPUT -H "Expect:" -H "x-scal-usermd: bXl1c2VybWQ=" http://127.0.0.1/myFCGI/1234 --data-binary @testfile
	sleep 1
	curl -v http://127.0.0.1/myFCGI/1234
	echo "done $i"
}&
done
sleep 1
echo "Completed"
