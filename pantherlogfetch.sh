#!/bin/bash

set -e

rm -f pypanther/pantherlog
curl -sS https://panther-community-us-east-1.s3.amazonaws.com/latest/tools/darwin-arm64-pantherlog.zip -o pantherlog.zip
unzip pantherlog.zip
rm pantherlog.zip
mv pantherlog pypanther/pantherlog
