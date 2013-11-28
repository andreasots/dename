How to install/use:

* Install an up-to-date version of PostgreSQL
* Install an up-to-date version of golang (>= 1.1.2)
* Set up your $GOPATH, if you don't have it already:
	* Create a directory to hold go source code for your user, e.g. `$HOME/go`
	* Edit `~/.profile` to contain the following lines (change $HOME/go if you like): 
	```
	export $GOPATH=$HOME/go
	export PATH=$GOPATH/bin:$PATH
	```
	* You might have to log out and log in for this to take effect (or just set them manually).
* Run `go install github.com/andres-erbsen/dename`
* Make sure you have a `dename.cfg` file in the current directory
* Run `dename`
