# PyDaemon

This project is an implementation of a UNIX daemon in pure Python3. 

On its own, this daemon does not do anything, it is meant to be used in 
projects. The typical use case is to import `pydaemon` and then implement 
a subclass of the `Daemon` class in your own project. 

For an example of how to do that, check out the 
[PiServerStatus Daemon](https://github.com/mkrzysztofowicz/piserverstatusd) project.
