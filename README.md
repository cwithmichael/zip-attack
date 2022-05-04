# Zip Attack

## Motivation

This program was created for a very specfic problem I had. I had a large encrypted zip file that I lost/forgot the password for. Using traditional bruteforce methods resulted in a lot of false positives.

This program hopes to minimize false positives. It works by actually checking to see if a given file type exists in the 'plaintext' after attempting a guess password.

## Usage

Let's say we had an encrypted zip file named `cats.zip` with a jpg file in it.
In this example the password is `fun` and our wordlist contains `fun`.

Build the uber jar:

```bash
$ clj -T:build uber
```

Run the program:

```bash
$ java -jar ./target/zip-attack-0.0.1-standalone.jar ./test/com/cwithmichael/cats.zip kitten.jpg < wordlist
Found it! -> fun
```

We can also use a password generator like JohnTheRipper to provide passwords.

```bash
$ ./JohnTheRipper/run/john --mask=fu?a -stdout | java -jar ./target/zip-attack-0.0.1-standalone.jar ./test/com/cwithmichael/cats.zip kitten.jpg
Press 'q' or Ctrl-C to abort, almost any other key for status
95p 0:00:00:00 100.00% (2020-04-13 17:35) 1520p/s fu|
Found it! -> fun
```

## Important Notes

Supports PKZip/ZipCrypto Encryption _only_

Only a limited number of file types are supported at the moment: zip, wmv/asf/wma, jpg, png, xml

But it's pretty easy to extend support for various file types.
