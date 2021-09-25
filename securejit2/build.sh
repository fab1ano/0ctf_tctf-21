#!/bin/bash
wget https://github.com/benhoyt/pyast64/raw/master/pyast64.py
patch -p1 < patch.diff
