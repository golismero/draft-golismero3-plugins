Description
===========

This Docker image contains the last version of [wfuzz](https://github.com/xmendez/wfuzz) and a copy of [fuzzdbwordlist database](https://github.com/fuzzdb-project/fuzzdb)

The copy of wordlist database is located at: `/wordlists`

Usage examples
--------------

    docker run --rm  wfuzz --filter "code=200 and lines!=0" -w /wordlists/discovery/predictable-filepaths/webservers-appservers/Apache.txt http://domain.com/FUZZ

Tip
---

- You can find an special wordlist that contains all the predictable files at: `/wordlists/discovery/predictable-filepaths/webservers-appservers/BigPredictable.txt`