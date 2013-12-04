How to install/use:

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
* Run `dename`

How to test multiple instances on the same machine:
 * Run `./setup-instances.sh <directory> <number of instances>`
 * Run `./run-instances.sh <directory> <number of instances>` (or run them manually in different terminal windows, if you like)

