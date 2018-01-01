#!/bin/sh

output=`perl Makefile.PL 2>&1`;
if [ $? != 0 ]; then
	echo "Command: [perl Makefile.PL]"
	echo "$output";
	exit 1
fi;

output=`make 2>&1`;
if [ $? != 0 ]; then
	echo "Command: [make]"
	echo "$output";
	exit 1
fi;

output=`make test 2>&1`;
if [ $? != 0 ]; then
	echo "Command: [make test]";
	echo "$output";
	exit 1
fi;

output=`make install 2>&1`;
if [ $? != 0 ]; then
	echo "Command: [make install]"
	echo "$output";
	exit 1
fi;

make clean 2>&1 1>/dev/null && rm -rf Makefile.old
