How to to run a dename server:

* Install an up-to-date version of PostgreSQL
* Install an up-to-date version of golang (>= 1.1.2)
* Set up your $GOPATH, if you don't have it already:
    * Create a directory to hold go source code for your user, e.g. `$HOME/go`
    * Edit `~/.profile` to contain the following lines (change $HOME/go if you like): 

            export $GOPATH=$HOME/go
            export PATH=$GOPATH/bin:$PATH

    * You'll have to log out and log in for this to take effect (or just set the variables manually).
* Run `go install github.com/andres-erbsen/dename`
* Create a DB user and a new database in PostgreSQL
*    Configure your `dename.cfg` 
* Run `dename` in the directory of `dename.cfg`

Script for testing multiple instances on the same machine:
 * `./setup-instances.sh <directory> <number of instances>`
