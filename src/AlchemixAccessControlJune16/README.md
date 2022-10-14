Alchemix Access Control Bug
==

Tldr
--

The ```setWhitelist()``` function does not have access control. Any attacker could have called ```setWhitelist()``` to give an attacker the ability to call the harvest function.

- [Source](https://medium.com/immunefi/alchemix-access-control-bug-fix-debrief-a13d39b9f2e0)

Run test
--
```
$ brownie test -s
```
